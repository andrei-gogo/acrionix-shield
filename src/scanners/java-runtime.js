const fs = require('node:fs');
const path = require('node:path');
const { findDockerfiles } = require('./docker-scanner');
const { parseRelease, compareReleases } = require('../version-range');

const ADVISORY = 'CVE-2026-114938 (Java4Shell)';
const ORACLE_FIXES = { 17: '17.0.21.1', 21: '21.0.13.1', 25: '25.0.5.1', 27: '27.0.1.1' };
const DESCRIPTION = 'Java Base64 decoder may permit remote code execution when attacker-controlled Base64 is decoded on x86-64 hardware with AVX-512 VBMI';

function read(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch { return null; }
}

function imageInfo(ref) {
  const withoutDigest = ref.split('@')[0];
  const slash = withoutDigest.lastIndexOf('/');
  const colon = withoutDigest.indexOf(':', slash + 1);
  const repo = (colon < 0 ? withoutDigest : withoutDigest.slice(0, colon)).toLowerCase()
    .replace(/^(?:docker\.io|index\.docker\.io)\//, '').replace(/^library\//, '');
  const tag = colon < 0 ? 'latest' : withoutDigest.slice(colon + 1);
  const repoParts = repo.split('/');
  const imageName = repoParts[repoParts.length - 1];
  const trusted = ['openjdk', 'eclipse-temurin', 'amazoncorretto', 'azul/zulu-openjdk', 'container-registry.oracle.com/java/jdk'].includes(repo);
  let vendor = null;
  if (imageName === 'openjdk') vendor = 'openjdk';
  else if (imageName === 'eclipse-temurin') vendor = 'temurin';
  else if (imageName === 'amazoncorretto') vendor = 'corretto';
  else if (imageName === 'zulu-openjdk') vendor = 'zulu';
  else if (repo === 'container-registry.oracle.com/java/jdk') vendor = 'oracle';
  return { repo, tag, vendor, trusted, digest: ref.includes('@sha256:') };
}

function parseJavaVersion(tag) {
  const normalized = String(tag).replace(/^[a-z][a-z0-9]*-+(?=\d)/i, '');
  const match = normalized.match(/^(\d+(?:\.\d+){0,4})(?=$|[-+_])/);
  if (!match || /[-+_](?:ea|rc|beta|snapshot)(?:\d|\b)/i.test(tag)) return null;
  const parts = parseRelease(match[1]);
  return { parts, raw: match[1], full: parts.length >= 3 };
}

function classify(version, vendor) {
  if (!version) return 'unverified';
  const major = version.parts[0];
  // The OpenJDK issue starts at 17.0.6. Older OpenJDK 8/11 releases are outside its scope.
  if (major < 17) return 'outside';
  if (!version.full) return 'unverified';
  if (major === 17 && compareReleases(version.parts, [17, 0, 6]) < 0) return 'outside';
  const fix = ORACLE_FIXES[major];
  if (!fix) return major <= 27 ? 'potentially-affected' : 'unverified';
  const fixedParts = parseRelease(fix);
  const comparison = compareReleases(version.parts, fixedParts);
  if (comparison < 0) {
    // Three-component tags at the November update boundary may refer to rebuilt vendor images.
    if (version.parts.length === 3 && compareReleases(version.parts, fixedParts.slice(0, 3)) === 0 && vendor !== 'oracle') return 'unverified';
    return 'potentially-affected';
  }
  // Oracle's fourth component and Azul's published Zulu builds have confirmed fixes.
  if (vendor === 'oracle') return 'patched';
  if (vendor === 'zulu' && version.parts.length >= 4) return 'patched';
  if (version.parts[2] > fixedParts[2] && ['openjdk', 'temurin', 'corretto', 'zulu'].includes(vendor)) return 'patched';
  return 'unverified';
}

function dockerRuntimes(dir) {
  const found = [];
  for (const { path: file, name, isCompose } of findDockerfiles(dir)) {
    const content = read(file);
    if (!content) continue;
    const lines = content.split(/\r?\n/);
    if (isCompose) {
      lines.forEach((line, index) => {
        const match = line.match(/^\s*image:\s*["']?([^\s"'#]+)/i);
        if (match) found.push({ ref: match[1], file: name, line: index + 1 });
      });
      continue;
    }
    const stages = [];
    const args = new Map();
    lines.forEach((line, index) => {
      const arg = line.match(/^\s*ARG\s+([A-Za-z_][A-Za-z_0-9]*)=([^\s#]+)/i);
      if (arg) args.set(arg[1], arg[2]);
      const match = line.match(/^\s*FROM\s+((?:--\S+\s+)*)((?:\$\{[^}]+\}|[^\s#]+))(?:\s+AS\s+([^\s#]+))?/i);
      if (match) {
        const ref = match[2].replace(/\$\{([A-Za-z_][A-Za-z_0-9]*)\}/g, (_, key) => args.get(key) || '${' + key + '}');
        stages.push({ ref, alias: match[3], platform: match[1].match(/--platform=([^\s]+)/i)?.[1], file: name, line: index + 1, index });
      }
    });
    const final = stages[stages.length - 1];
    if (!final) continue;
    let ref = final.ref;
    const seen = new Set();
    while (!seen.has(ref.toLowerCase())) {
      seen.add(ref.toLowerCase());
      const base = stages.slice(0, -1).find(stage => stage.alias && stage.alias.toLowerCase() === ref.toLowerCase());
      if (!base) break;
      ref = base.ref;
    }
    found.push({ ...final, ref });
    for (const line of lines.slice(final.index + 1)) {
      const copy = line.match(/^\s*COPY\s+(.+)$/i);
      if (!copy) continue;
      const from = copy[1].match(/(?:^|\s)--from=([^\s]+)/i);
      if (!from || !/(?:java|jdk|jre|runtime)/i.test(copy[1].slice(copy[1].indexOf(from[0]) + from[0].length))) continue;
      let source = from[1];
      const visited = new Set();
      while (!visited.has(source.toLowerCase())) {
        visited.add(source.toLowerCase());
        const stage = stages.slice(0, -1).find(item => item.alias && item.alias.toLowerCase() === source.toLowerCase());
        if (!stage) break;
        source = stage.ref;
      }
      if (source !== ref && imageInfo(source).vendor) found.push({ ...final, ref: source, derived: true });
    }
  }
  return found;
}

function runJavaRuntimeCheck(dir) {
  const findings = [];
  const candidates = dockerRuntimes(dir).map(runtime => ({ ...runtime, kind: 'image', ...imageInfo(runtime.ref) }));
  for (const [file, pattern] of [['.java-version', /^(\S+)/], ['.tool-versions', /^java\s+(\S+)/m], ['.sdkmanrc', /^java\s*=\s*(\S+)/m]]) {
    const content = read(path.join(dir, file));
    const match = content && content.match(pattern);
    if (match) candidates.push({ kind: 'dev', file, tag: match[1], vendor: 'unknown' });
  }

  for (const candidate of candidates) {
    if (candidate.kind === 'image' && !candidate.vendor) continue;
    if (candidate.platform && /(?:^|\/)arm64|aarch64/i.test(candidate.platform)) continue;
    const version = parseJavaVersion(candidate.tag);
    const status = candidate.derived ? 'unverified' : classify(version, candidate.trusted ? candidate.vendor : 'unknown');
    if (status === 'outside' || status === 'patched') continue;
    // Development version files provide a lead, but cannot establish the deployed version.
    if (candidate.kind === 'dev' && status !== 'potentially-affected') continue;
    const potential = status === 'potentially-affected';
    const high = potential && candidate.kind === 'image';
    const unsupported = version && !ORACLE_FIXES[version.parts[0]];
    findings.push({
      type: potential ? 'java-runtime-potentially-affected' : 'java-runtime-unverified',
      severity: high ? 'high' : 'medium',
      file: candidate.file,
      line: candidate.line,
      package: 'java-runtime',
      version: candidate.tag,
      advisory: ADVISORY,
      ecosystem: 'java',
      description: `${DESCRIPTION}. ${candidate.kind === 'dev' ? 'Development version hint' : candidate.derived ? 'Java runtime copied from a build stage' : 'Container image'} ${candidate.tag} is ${potential ? unsupported ? 'on an unsupported Java line without a listed fix; deployed CPU and application path need verification' : 'below the published Oracle fix level; vendor patch status and deployed CPU need verification' : 'not enough to verify its patch status'}`,
      recommendation: `Check java -version and your vendor advisory on the deployed host; ${unsupported ? 'migrate to a supported, patched Java line' : `use a patched vendor build (Oracle baseline: ${Object.entries(ORACLE_FIXES).map(([major, fix]) => `${major}: ${fix}`).join(', ')})`} or disable Base64 intrinsics with -XX:-UseBASE64Intrinsics`,
    });
  }
  return findings;
}

module.exports = { runJavaRuntimeCheck, parseJavaVersion, classify };
