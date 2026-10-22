const fs = require('node:fs');
const path = require('node:path');
const { findDockerfiles } = require('./docker-scanner');

// Vulnerabilities in the PHP runtime itself (not Composer packages).
// `fixed` maps each supported branch to the first patched release.
// Branches older than `minSupported` get no upstream fix and are always flagged.
const PHP_RUNTIME_ADVISORIES = [
  {
    name: 'PHP2Shell',
    advisory: 'CVE-2026-109618, CVE-2026-109619',
    description: 'PHP2Shell — unauthenticated remote code execution via crafted HTTP traffic (CVSS 9.2)',
    severity: 'critical',
    minSupported: '8.2',
    fixed: { '8.2': '8.2.35', '8.3': '8.3.36', '8.4': '8.4.27', '8.5': '8.5.12' },
  },
];

// Known compromised Composer packages — extend via .shieldrc.json knownCompromised.php
const COMPROMISED_COMPOSER = {};

// Variant suffixes used by the official php image (php:8.3.30-fpm-alpine3.20, php:8.4-zts-bookworm)
const OFFICIAL_VARIANT = /^(?:cli|fpm|apache|zts|alpine(?:\d+\.\d+)?|bookworm|bullseye|buster|trixie)$/i;

// Accepts the whole token only: 8.3, 8.3.30, 8.3.30-fpm, 8.3-fpm-alpine3.20.
// Anything else (8.6.0RC3, 8.3.36-rc1, 8.3.36garbage, latest, ${PHP_VERSION}) is unparseable
// → unverified, so a non-final build at a fixed patch number is never treated as patched.
function parseVersion(str) {
  const match = String(str).trim().match(/^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-([a-z0-9][a-z0-9._-]*))?$/i);
  if (!match) return null;
  if (match[4] && !match[4].split('-').every(part => OFFICIAL_VARIANT.test(part))) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: match[3] === undefined ? null : Number(match[3]),
    branch: `${match[1]}.${match[2]}`,
    raw: match[3] === undefined ? `${match[1]}.${match[2]}` : `${match[1]}.${match[2]}.${match[3]}`,
  };
}

// Splits an image reference into repository and tag; only the official `php` image counts.
// php:8.3-fpm, docker.io/library/php:8.3, php:8.3@sha256:… → { repo: 'php', tag }
function parseImageRef(ref) {
  const withoutDigest = ref.split('@')[0];
  const lastSlash = withoutDigest.lastIndexOf('/');
  const colon = withoutDigest.indexOf(':', lastSlash + 1);
  const repo = colon === -1 ? withoutDigest : withoutDigest.slice(0, colon);
  const tag = colon === -1 ? 'latest' : withoutDigest.slice(colon + 1);
  const normalized = repo.toLowerCase().replace(/^(?:docker\.io|index\.docker\.io)\//, '').replace(/^library\//, '');
  return { repo: normalized, tag };
}

function compareBranch(a, b) {
  const [aMaj, aMin] = a.split('.').map(Number);
  const [bMaj, bMin] = b.split('.').map(Number);
  return aMaj - bMaj || aMin - bMin;
}

function parseComposerVersion(str) {
  const match = String(str).trim().match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.\d+)?$/i);
  if (!match) return null;
  return [Number(match[1]), Number(match[2] || 0), Number(match[3] || 0)];
}

function compareTriple(a, b) {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

// Translates a single Composer constraint into { exact } or { min, max } (max exclusive).
// Returns null for anything not handled (|| unions, comma ranges, dev-*, stability flags)
// so callers report it as not evaluated instead of guessing.
function constraintRange(constraint) {
  const c = String(constraint).trim();
  if (c === '*') return { min: [0, 0, 0], max: null };

  const exact = c.match(/^=?=?\s*(v?\d+(?:\.\d+){0,3})$/);
  if (exact) {
    const parts = exact[1].replace(/^v/, '').split('.');
    // "1.4" in Composer means 1.4.0 exactly only when fully specified; treat partial as a range
    if (parts.length >= 3) return { exact: parseComposerVersion(exact[1]) };
  }

  const caret = c.match(/^\^\s*(v?\d+(?:\.\d+){0,2})$/);
  if (caret) {
    const min = parseComposerVersion(caret[1]);
    const depth = caret[1].split('.').length;
    let max;
    if (min[0] > 0 || depth === 1) max = [min[0] + 1, 0, 0];
    else if (min[1] > 0 || depth === 2) max = [0, min[1] + 1, 0];
    else max = [0, 0, min[2] + 1];
    return { min, max };
  }

  const tilde = c.match(/^~\s*(v?\d+(?:\.\d+){0,2})$/);
  if (tilde) {
    const min = parseComposerVersion(tilde[1]);
    const depth = tilde[1].split('.').length;
    const max = depth === 3 ? [min[0], min[1] + 1, 0] : [min[0] + 1, 0, 0];
    return { min, max };
  }

  const wildcard = c.match(/^v?(\d+)(?:\.(\d+))?(?:\.(?:\*|x))$/i);
  if (wildcard) {
    const major = Number(wildcard[1]);
    if (wildcard[2] === undefined) return { min: [major, 0, 0], max: [major + 1, 0, 0] };
    const minor = Number(wildcard[2]);
    return { min: [major, minor, 0], max: [major, minor + 1, 0] };
  }

  // Partial exact like "1.4" behaves as 1.4.0 in Composer
  if (exact) return { exact: parseComposerVersion(exact[1]) };

  return null;
}

// true / false when decidable, null when the constraint cannot be evaluated
function constraintAllows(constraint, version) {
  const range = constraintRange(constraint);
  const target = parseComposerVersion(version);
  if (!range || !target) return null;
  if (range.exact) return compareTriple(range.exact, target) === 0;
  if (compareTriple(target, range.min) < 0) return false;
  return !range.max || compareTriple(target, range.max) < 0;
}

// Returns { status: 'vulnerable' | 'eol' | 'floating' | 'unknown' | 'ok', fixedIn }
function checkRuntime(version, advisory) {
  if (compareBranch(version.branch, advisory.minSupported) < 0) return { status: 'eol' };
  const fixedIn = advisory.fixed[version.branch];
  if (!fixedIn) return { status: 'unknown' };
  if (version.patch === null) return { status: 'floating', fixedIn };
  const fixedPatch = parseVersion(fixedIn).patch;
  return version.patch < fixedPatch ? { status: 'vulnerable', fixedIn } : { status: 'ok', fixedIn };
}

function readIfExists(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

function readJson(filePath) {
  const content = readIfExists(filePath);
  if (!content) return null;
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

// Collect runtime evidence: places that name the PHP interpreter actually used.
// composer.json config.platform.php is deliberately excluded — Composer fakes the
// platform for dependency resolution, it says nothing about the deployed interpreter.
function findRuntimeVersions(dir) {
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
      if (repo !== 'php') continue;
      found.push({ kind: 'deploy', file: name, line: i + 1, tag, version: parseVersion(tag) });
    }
  }

  // Version manager files — development/CI hints, not proof of the deployed interpreter
  const phpVersion = readIfExists(path.join(dir, '.php-version'));
  if (phpVersion && phpVersion.trim()) {
    found.push({ kind: 'dev', file: '.php-version', tag: phpVersion.trim(), version: parseVersion(phpVersion.trim()) });
  }
  const toolVersions = readIfExists(path.join(dir, '.tool-versions'));
  if (toolVersions) {
    const match = toolVersions.match(/^php\s+(\S+)/m);
    if (match) found.push({ kind: 'dev', file: '.tool-versions', tag: match[1], version: parseVersion(match[1]) });
  }

  return found;
}

function parseComposerLock(dir) {
  const deps = {};
  const lock = readJson(path.join(dir, 'composer.lock'));
  if (!lock) return deps;
  for (const pkg of [...(lock.packages || []), ...(lock['packages-dev'] || [])]) {
    if (pkg && pkg.name) deps[pkg.name] = { version: String(pkg.version || '*').replace(/^v/, ''), source: 'composer.lock' };
  }
  return deps;
}

function parseComposerJson(composer) {
  const deps = {};
  if (!composer) return deps;
  for (const section of ['require', 'require-dev']) {
    for (const [name, version] of Object.entries(composer[section] || {})) {
      if (name === 'php' || name.startsWith('ext-')) continue;
      deps[name] = { version: String(version), source: 'composer.json' };
    }
  }
  return deps;
}

async function runPhpScan(dir, config = {}) {
  const findings = [];
  const composer = readJson(path.join(dir, 'composer.json'));
  const hasComposerLock = fs.existsSync(path.join(dir, 'composer.lock'));
  const runtimes = findRuntimeVersions(dir);

  // Runtime advisories (PHP2Shell etc.)
  for (const runtime of runtimes) {
    for (const advisory of PHP_RUNTIME_ADVISORIES) {
      const base = {
        file: runtime.file,
        line: runtime.line,
        package: 'php',
        version: runtime.tag,
        advisory: advisory.advisory,
        ecosystem: 'php',
      };
      const allFixes = Object.values(advisory.fixed).join(', ');

      const devNote = runtime.kind === 'dev' ? ' (development pin)' : '';

      if (!runtime.version) {
        // Dev pins that can't be parsed prove nothing either way; the undeclared-runtime check covers them
        if (runtime.kind === 'dev') continue;
        // php:latest, php:fpm, 8.6.0RC3, ${PHP_VERSION} — cannot map to a known release
        findings.push({
          ...base,
          type: 'php-runtime-unverified',
          severity: 'high',
          description: `${advisory.description} — PHP version "${runtime.tag}" is not a recognised release, cannot verify patch level`,
          recommendation: `Pin to a patched release (${allFixes}) and confirm with php -v`,
        });
        continue;
      }

      const result = checkRuntime(runtime.version, advisory);
      if (result.status === 'eol') {
        findings.push({
          ...base,
          type: 'php-runtime-vulnerable',
          severity: advisory.severity,
          description: `${advisory.description} — PHP ${runtime.version.branch}${devNote} is end-of-life and receives no fix`,
          recommendation: `Upgrade to PHP ${advisory.minSupported}+ (patched: ${allFixes}) unless your vendor ships a backport`,
        });
      } else if (result.status === 'vulnerable') {
        findings.push({
          ...base,
          type: 'php-runtime-vulnerable',
          severity: advisory.severity,
          description: `${advisory.description} — PHP ${runtime.version.raw}${devNote} is unpatched`,
          recommendation: `URGENT: Upgrade to PHP ${result.fixedIn} or later`,
        });
      } else if (runtime.kind === 'dev') {
        continue;
      } else if (result.status === 'floating') {
        findings.push({
          ...base,
          type: 'php-runtime-unverified',
          severity: 'high',
          description: `${advisory.description} — tag "${runtime.tag}" floats within ${runtime.version.branch}, cannot verify patch level`,
          recommendation: `Pin to PHP ${result.fixedIn} or later, or rebuild with --pull and confirm php -v`,
        });
      } else if (result.status === 'unknown') {
        findings.push({
          ...base,
          type: 'php-runtime-unverified',
          severity: 'high',
          description: `${advisory.description} — PHP ${runtime.version.branch} is not covered by this advisory, cannot verify`,
          recommendation: `Check the PHP security notice for ${runtime.version.branch} and confirm with php -v`,
        });
      }
    }
  }

  // A deployable PHP app with no deployment evidence must not look clean for runtime advisories.
  // Libraries (Composer's default type) have no runtime of their own and are skipped.
  // Dev pins and config.platform.php never count as deployment evidence.
  const isPhpProject = Boolean(composer) || hasComposerLock;
  const isDeployable = (composer && composer.type === 'project') || findDockerfiles(dir).length > 0;
  if (isPhpProject && isDeployable && !runtimes.some(r => r.kind === 'deploy')) {
    const platformPhp = composer && composer.config && composer.config.platform && composer.config.platform.php;
    const hints = runtimes.filter(r => r.kind === 'dev').map(r => `${r.file} "${r.tag}"`);
    if (platformPhp) hints.push(`config.platform.php "${platformPhp}"`);
    for (const advisory of PHP_RUNTIME_ADVISORIES) {
      findings.push({
        type: 'php-runtime-unverified',
        severity: 'medium',
        file: composer ? 'composer.json' : 'composer.lock',
        package: 'php',
        advisory: advisory.advisory,
        ecosystem: 'php',
        description: `${advisory.description} — deployed PHP runtime version not identified in repo` +
          (hints.length ? ` (${hints.join(', ')} are development/resolution hints, not the deployed interpreter)` : ''),
        recommendation: `Run php -v on every deployed environment; patched releases: ${Object.values(advisory.fixed).join(', ')}`,
      });
    }
  }

  // Composer dependencies
  const allDeps = { ...parseComposerJson(composer), ...parseComposerLock(dir) };
  const extraCompromised = (config.knownCompromised && config.knownCompromised.php) || {};
  const compromisedList = { ...COMPROMISED_COMPOSER, ...extraCompromised };

  for (const [name, info] of Object.entries(allDeps)) {
    for (const entry of compromisedList[name] || []) {
      const fromConstraint = info.source === 'composer.json';
      let verdict;
      if (entry.versions.includes('*')) {
        verdict = 'match';
      } else if (!fromConstraint) {
        verdict = entry.versions.includes(info.version) ? 'match' : 'clear';
      } else {
        const range = constraintRange(info.version);
        const allowed = entry.versions.map(v => constraintAllows(info.version, v));
        if (allowed.includes(null)) verdict = 'unevaluated';
        else if (!allowed.includes(true)) verdict = 'clear';
        else verdict = range && range.exact ? 'match' : 'possible';
      }

      if (verdict === 'match') {
        findings.push({
          type: 'compromised-composer',
          severity: entry.severity,
          file: info.source,
          package: name,
          version: info.version,
          description: entry.description,
          advisory: entry.advisory,
          ecosystem: 'php',
          recommendation: `URGENT: Remove or update ${name} immediately`,
        });
      } else if (verdict === 'possible') {
        // A range like ^1.0 can resolve to a compromised release; only a lockfile can tell
        const reachable = entry.versions.filter(v => constraintAllows(info.version, v));
        findings.push({
          type: 'compromised-composer-unverified',
          severity: 'high',
          file: info.source,
          package: name,
          version: info.version,
          description: `Constraint "${info.version}" can resolve to compromised ${reachable.join(', ')} — ${entry.description}`,
          advisory: entry.advisory,
          ecosystem: 'php',
          recommendation: `Commit composer.lock so the installed version of ${name} can be verified`,
        });
      } else if (verdict === 'unevaluated') {
        findings.push({
          type: 'compromised-composer-unverified',
          severity: 'medium',
          file: info.source,
          package: name,
          version: info.version,
          description: `Constraint "${info.version}" was not evaluated against blocklisted ${name} versions — ${entry.description}`,
          advisory: entry.advisory,
          ecosystem: 'php',
          recommendation: `Commit composer.lock so the installed version of ${name} can be verified`,
        });
      }
    }
  }

  // Insecure Composer configuration
  if (composer) {
    const composerConfig = composer.config || {};
    if (composerConfig['secure-http'] === false) {
      findings.push({
        type: 'insecure-source',
        severity: 'critical',
        file: 'composer.json',
        description: 'Composer secure-http disabled — packages can be fetched over HTTP',
        ecosystem: 'php',
        recommendation: 'Remove "secure-http": false from composer.json config',
      });
    }
    if (composerConfig['disable-tls'] === true) {
      findings.push({
        type: 'insecure-source',
        severity: 'critical',
        file: 'composer.json',
        description: 'Composer disable-tls enabled — TLS and secure-http are turned off',
        ecosystem: 'php',
        recommendation: 'Remove "disable-tls": true from composer.json config',
      });
    }
    const repos = Array.isArray(composer.repositories) ? composer.repositories : Object.values(composer.repositories || {});
    if (repos.some(r => r && typeof r.url === 'string' && r.url.startsWith('http://'))) {
      findings.push({
        type: 'insecure-source',
        severity: 'critical',
        file: 'composer.json',
        description: 'Composer repository uses HTTP instead of HTTPS',
        ecosystem: 'php',
        recommendation: 'Use HTTPS URLs for all Composer repositories',
      });
    }
  }

  return findings;
}

module.exports = { runPhpScan, checkRuntime, parseVersion, parseImageRef, constraintAllows };
