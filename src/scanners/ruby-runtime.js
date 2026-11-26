const fs = require('node:fs');
const path = require('node:path');
const { findDockerfiles } = require('./docker-scanner');

const ADVISORY = 'GHSA-3p8q-wmhx-vm2w';
const FIXES = { '3.3': 14, '3.4': 13, '4.0': 10 };

function read(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch { return null; }
}

function parseVersion(tag) {
  const [release, ...variants] = String(tag).replace(/^ruby-/, '').split('-');
  if (variants.some(part => !/^(?:alpine(?:\d+(?:\.\d+)?)?|slim|bookworm|bullseye|trixie|buster)$/i.test(part))) return null;
  const match = release.match(/^(\d+)\.(\d+)(?:\.(\d+))?$/);
  if (!match) return null;
  return { branch: `${match[1]}.${match[2]}`, patch: match[3] === undefined ? null : Number(match[3]), major: Number(match[1]), minor: Number(match[2]) };
}

function imageTag(ref) {
  const noDigest = ref.split('@')[0];
  const colon = noDigest.indexOf(':', noDigest.lastIndexOf('/') + 1);
  const repo = (colon < 0 ? noDigest : noDigest.slice(0, colon)).toLowerCase()
    .replace(/^(?:docker\.io|index\.docker\.io)\//, '').replace(/^library\//, '');
  if (repo !== 'ruby') return null;
  return colon < 0 ? (ref.includes('@sha256:') ? 'digest-only' : 'latest') : noDigest.slice(colon + 1);
}

function candidates(dir) {
  const found = [];
  for (const { path: file, name, isCompose } of findDockerfiles(dir)) {
    const content = read(file);
    if (!content) continue;
    if (isCompose) {
      content.split(/\r?\n/).forEach((line, i) => {
        const match = line.match(/^\s*image:\s*["']?([^\s"'#]+)/i);
        if (match) {
          const ref = match[1].replace(/\$\{[A-Za-z_][A-Za-z_0-9]*:-([^}]+)\}/g, (_, fallback) => fallback);
          found.push({ tag: imageTag(ref), file: name, line: i + 1, kind: 'image' });
        }
      });
    } else {
      const stages = [];
      const args = new Map();
      content.split(/\r?\n/).forEach((line, i) => {
        const arg = line.match(/^\s*ARG\s+([A-Za-z_][A-Za-z_0-9]*)=([^\s#]+)/i);
        if (arg) args.set(arg[1], arg[2]);
        const match = line.match(/^\s*FROM\s+(?:--\S+\s+)*([^\s#]+)(?:\s+AS\s+([^\s#]+))?/i);
        if (match) stages.push({ ref: match[1].replace(/\$(?:\{([A-Za-z_][A-Za-z_0-9]*)(?::-([^}]+))?\}|([A-Za-z_][A-Za-z_0-9]*))/g,
          (whole, braced, fallback, bare) => args.get(braced || bare) || fallback || whole), alias: match[2], line: i + 1 });
      });
      let final = stages[stages.length - 1];
      if (!final) continue;
      let ref = final.ref;
      const seen = new Set();
      while (!seen.has(ref.toLowerCase())) {
        seen.add(ref.toLowerCase());
        const stage = stages.slice(0, -1).find(item => item.alias && item.alias.toLowerCase() === ref.toLowerCase());
        if (!stage) break;
        ref = stage.ref;
      }
      found.push({ tag: imageTag(ref), file: name, line: final.line, kind: 'image' });
    }
  }
  for (const [file, pattern] of [['.ruby-version', /^\s*(\S+)/], ['.tool-versions', /^ruby\s+(\S+)/m]]) {
    const content = read(path.join(dir, file));
    const match = content && content.match(pattern);
    if (match) found.push({ tag: match[1], file, kind: 'development' });
  }
  return found.filter(item => item.tag);
}

function runRubyRuntimeCheck(dir) {
  const findings = [];
  for (const candidate of candidates(dir)) {
    const version = parseVersion(candidate.tag);
    if (version && (version.major > 4 || (version.major === 4 && version.minor > 0))) continue;
    if (version && FIXES[version.branch] !== undefined && version.patch !== null && version.patch >= FIXES[version.branch]) continue;
    const exactVulnerable = version && version.patch !== null && (FIXES[version.branch] !== undefined || version.major < 3 || (version.major === 3 && version.minor < 3));
    const fixed = version && FIXES[version.branch] !== undefined ? `${version.branch}.${FIXES[version.branch]}` : 'a supported patched Ruby release';
    findings.push({
      type: exactVulnerable ? 'ruby-runtime-vulnerable' : 'ruby-runtime-unverified',
      severity: exactVulnerable && candidate.kind === 'image' ? 'critical' : 'medium',
      file: candidate.file, line: candidate.line, version: candidate.tag, advisory: ADVISORY,
      ecosystem: 'ruby',
      description: exactVulnerable
        ? `Ruby ${candidate.tag} is affected by a regex compiler heap buffer overflow; remote code execution is possible if the app compiles attacker-controlled patterns${candidate.kind === 'development' ? ' (development version hint; deployed runtime unverified)' : ''}`
        : `Ruby ${candidate.tag} does not establish a patched deployed runtime for the regex compiler advisory`,
      recommendation: `Upgrade the deployed Ruby runtime to ${fixed} or newer and confirm with ruby -v`,
    });
  }
  return findings;
}

module.exports = { runRubyRuntimeCheck };
