const fs = require('node:fs');
const path = require('node:path');
const { findDockerfiles } = require('./docker-scanner');
const { parseRelease, compareReleases } = require('../version-range');

// Node.js runtime advisories. Lines missing from `fixed` and older than the newest
// fixed line are end-of-life; newer lines are not covered and are not reported.
const NODE_RUNTIME_ADVISORIES = [
  {
    advisory: 'CVE-2026-111497 (Node.js security release, 2026-10-21)',
    description: 'Node2Shell: bundled Brotli decoder flaw, reachable through node:zlib when decompressing attacker-controlled Brotli',
    fixed: { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' },
    severity: 'high',
  },
];

const OFFICIAL_VARIANT = /^(?:alpine(?:\d+\.\d+)?|slim|bookworm|bullseye|buster|trixie)(?:-slim)?$/i;

function parseNodeVersion(str) {
  const match = String(str).trim().match(/^v?(\d+(?:\.\d+){0,2})(?:-(.+))?$/i);
  if (!match) return null;
  if (match[2] && !OFFICIAL_VARIANT.test(match[2])) return null;
  const parts = match[1].split('.');
  return { raw: match[1], major: Number(parts[0]), full: parts.length === 3 };
}

function parseImageRef(ref) {
  const withoutDigest = ref.split('@')[0];
  const lastSlash = withoutDigest.lastIndexOf('/');
  const colon = withoutDigest.indexOf(':', lastSlash + 1);
  const repo = colon === -1 ? withoutDigest : withoutDigest.slice(0, colon);
  const tag = colon === -1 ? 'latest' : withoutDigest.slice(colon + 1);
  const normalized = repo.toLowerCase().replace(/^(?:docker\.io|index\.docker\.io)\//, '').replace(/^library\//, '');
  return { repo: normalized, tag };
}

function readIfExists(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

function findNodeRuntimes(dir) {
  const found = [];

  for (const { path: filePath, name, isCompose } of findDockerfiles(dir)) {
    const content = readIfExists(filePath);
    if (!content) continue;
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let ref = null;
      if (isCompose) {
        const match = line.match(/^\s*image:\s*["']?([^\s"'#]+)/i);
        if (match) ref = match[1];
      } else {
        const match = line.match(/^\s*FROM\s+(.+)$/i);
        if (match) ref = match[1].trim().split(/\s+/).find(token => !token.startsWith('--'));
      }
      if (!ref) continue;
      const { repo, tag } = parseImageRef(ref);
      if (repo !== 'node') continue;
      found.push({ kind: 'deploy', file: name, line: i + 1, tag, version: parseNodeVersion(tag) });
    }
  }

  // Version manager pins — development/CI hints, not proof of the deployed runtime
  for (const file of ['.nvmrc', '.node-version']) {
    const content = readIfExists(path.join(dir, file));
    const tag = content && content.trim().split(/\s+/)[0];
    if (tag) found.push({ kind: 'dev', file, tag, version: parseNodeVersion(tag) });
  }
  const toolVersions = readIfExists(path.join(dir, '.tool-versions'));
  const toolMatch = toolVersions && toolVersions.match(/^nodejs\s+(\S+)/m);
  if (toolMatch) found.push({ kind: 'dev', file: '.tool-versions', tag: toolMatch[1], version: parseNodeVersion(toolMatch[1]) });

  return found;
}

function checkNodeRuntime(version, advisory) {
  const lines = Object.keys(advisory.fixed).map(Number);
  const fixedIn = advisory.fixed[version.major];
  if (!fixedIn) {
    return version.major < Math.max(...lines) ? { status: 'eol' } : { status: 'not-covered' };
  }
  if (!version.full) return { status: 'floating', fixedIn };
  const vulnerable = compareReleases(parseRelease(version.raw), parseRelease(fixedIn)) < 0;
  return { status: vulnerable ? 'vulnerable' : 'ok', fixedIn };
}

function runNodeRuntimeCheck(dir) {
  const findings = [];

  for (const runtime of findNodeRuntimes(dir)) {
    for (const advisory of NODE_RUNTIME_ADVISORIES) {
      const base = {
        file: runtime.file,
        line: runtime.line,
        package: 'node',
        version: runtime.tag,
        advisory: advisory.advisory,
        ecosystem: 'node',
      };
      const allFixes = Object.values(advisory.fixed).join(', ');
      const devNote = runtime.kind === 'dev' ? ' (development pin)' : '';

      if (!runtime.version) {
        // lts/*, node:current, codenames — dev pins prove nothing; images are unverifiable
        if (runtime.kind === 'dev') continue;
        findings.push({
          ...base,
          type: 'node-runtime-unverified',
          severity: 'medium',
          description: `${advisory.description}. Image tag "node:${runtime.tag}" does not name a release, cannot verify patch level`,
          recommendation: `Pin a patched Node.js release (${allFixes}) and confirm with node -v`,
        });
        continue;
      }

      const result = checkNodeRuntime(runtime.version, advisory);
      if (result.status === 'eol') {
        findings.push({
          ...base,
          type: 'node-runtime-vulnerable',
          severity: advisory.severity,
          description: `${advisory.description}. Node.js ${runtime.version.major}${devNote} is end-of-life and receives no fix`,
          recommendation: `Migrate to a supported Node.js line (patched: ${allFixes})`,
        });
      } else if (result.status === 'vulnerable') {
        findings.push({
          ...base,
          type: 'node-runtime-vulnerable',
          severity: advisory.severity,
          description: `${advisory.description}. Node.js ${runtime.version.raw}${devNote} is unpatched`,
          recommendation: `Upgrade to Node.js ${result.fixedIn} or later`,
        });
      } else if (result.status === 'floating' && runtime.kind === 'deploy') {
        findings.push({
          ...base,
          type: 'node-runtime-unverified',
          severity: 'medium',
          description: `${advisory.description}. Tag "node:${runtime.tag}" floats within Node.js ${runtime.version.major}, patch level depends on when the image was pulled`,
          recommendation: `Pin node:${result.fixedIn} or later, or rebuild with --pull and confirm node -v`,
        });
      }
    }
  }

  return findings;
}

module.exports = { runNodeRuntimeCheck, parseNodeVersion, checkNodeRuntime, NODE_RUNTIME_ADVISORIES };
