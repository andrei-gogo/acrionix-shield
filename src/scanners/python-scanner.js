const fs = require('node:fs');
const path = require('node:path');
const { entryMatches } = require('../version-range');

// Known compromised PyPI packages
const COMPROMISED_PYPI = {
  // Typosquats of popular packages (the legitimate python-dateutil itself is not listed)
  'python3-dateutil': [{ versions: ['*'], advisory: 'PyPI advisory', description: 'Typosquat of python-dateutil — credential stealer', severity: 'critical' }],
  // Keys are lowercase: requirement names are lowercased before lookup
  'jeilyfish': [{ versions: ['*'], advisory: 'PyPI advisory 2019', description: 'Typosquat of jellyfish (capital I instead of l) — credential stealer', severity: 'critical' }],
  'colourfool': [{ versions: ['0.1.5'], advisory: 'Fortinet 2023', description: 'Info stealer disguised as color utility', severity: 'critical' }],
  'culturestreak': [{ versions: ['1.0', '1.1'], advisory: 'MAL-2024-5012', description: 'Cryptominer targeting GitLab CI', severity: 'critical' }],
  // The original 0.1.2 was legitimate; the attacker uploaded 0.1.2-1 and later
  'ctx': [{ versions: ['0.1.2-1', '0.1.2-2', '0.1.4', '0.2', '0.2.1', '0.2.2', '0.2.2.1', '0.2.3', '0.2.4', '0.2.5', '0.2.6'], advisory: 'PYSEC-2022-199', description: 'Hijacked — exfiltrates AWS keys and environment variables', severity: 'critical' }],
  'colorslib': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Info stealer — exfiltrates Discord tokens and browser data', severity: 'critical' }],
  'httpslib': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Info stealer — exfiltrates Discord tokens and browser data', severity: 'critical' }],
  'libhttps': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Info stealer — exfiltrates Discord tokens and browser data', severity: 'critical' }],
  'free-net-vpn': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Credential stealer disguised as VPN tool', severity: 'critical' }],
  'free-net-vpn2': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Credential stealer disguised as VPN tool', severity: 'critical' }],
  'requessts': [{ versions: ['*'], advisory: 'MAL-2022-7438', description: 'Malicious typosquat of requests', severity: 'critical' }],
  // Hijacked release pipeline; earlier 1.82.x releases were also malicious
  'litellm': [{ versions: ['1.82.7', '1.82.8', '1.107.0'], advisory: 'GHSA-92x9-889m-jgmw', description: 'Compromised release — credential stealer and backdoor run at interpreter startup', severity: 'critical' }],
};

// Known-vulnerable version ranges (inclusive atLeast, exclusive below).
// Only checked against exact pins (==, ===) and lockfile versions.
const VULNERABLE_PYPI = {
  'brotli': [{ atLeast: '1.0.3', below: '1.2.1', advisory: 'CVE-2026-111497 / GHSA-9v8h-qqgm-4m35', description: 'Node2Shell: Brotli decoder memory corruption when decompressing attacker-controlled data', severity: 'high', fixed: '1.2.1' }],
  'brotlicffi': [{ atLeast: '1.0.3', below: '1.2.1.0', advisory: 'CVE-2026-111497 / GHSA-9v8h-qqgm-4m35', description: 'Node2Shell: Brotli decoder memory corruption when decompressing attacker-controlled data', severity: 'high', fixed: '1.2.1.0' }],
  'pillow': [
    { atLeast: '2.6.0', below: '13.0.0', advisory: 'CVE-2026-112900 / GHSA-w889-685w-c8fh', description: 'Remote code execution through the EPS/Ghostscript path when an attacker controls the filename (conditional exposure)', severity: 'critical', fixed: '13.0.0' },
    { atLeast: '2.0.0', below: '13.0.0', advisory: 'CVE-2026-112393 / GHSA-332p-7hrc-92wf', description: 'Heap overflow when writing TIFF images to a non-file target (conditional exposure)', severity: 'high', fixed: '13.0.0' },
    { below: '13.0.0', advisory: 'CVE-2026-112403 / GHSA-8g5g-8vmr-9782', description: 'Heap overflow when opening lossless JPEG with draft() on libjpeg-turbo >= 3.0 (conditional exposure)', severity: 'medium', fixed: '13.0.0' },
  ],
};

// PEP 503 name normalisation: Pillow, python_dateutil and python.dateutil all match
function normalizeName(name) {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

// Python typosquat targets
const PYTHON_TYPOSQUATS = {
  'requests': ['requessts', 'requets', 'request', 'requsts', 'reequests'],
  // 'beautifulsoup' is the original BeautifulSoup 3 package, not a typosquat
  'beautifulsoup4': ['beautifulsoup3', 'beutifulsoup4'],
  'numpy': ['numppy', 'numpi', 'numpyy'],
  'pandas': ['pandass', 'pnadas', 'pandsa'],
  'flask': ['flaask', 'flaskk'],
  'django': ['djano', 'djnago', 'djangoo'],
  'tensorflow': ['tenserflow', 'tensorflw', 'tensroflow'],
  'pytorch': ['pytorh', 'pytoch', 'py-torch'],
  // 'sklearn' is the official deprecated shim, not a typosquat
  'scikit-learn': ['scikitlearn', 'scikit_learn'],
  // Pillow-SIMD is a legitimate fork, not a typosquat
  'pillow': ['piilow', 'pilllow'],
  'cryptography': ['crytography', 'cryptograpy', 'cyptography'],
  'boto3': ['botto3', 'bot3', 'btoo3'],
  'celery': ['cellery', 'celerey'],
  'sqlalchemy': ['sqalchemy', 'sqlalchmy'],
};

function parseRequirements(dir) {
  const deps = {};
  const files = [
    'requirements.txt',
    'requirements-dev.txt',
    'requirements_dev.txt',
    'requirements/base.txt',
    'requirements/prod.txt',
    'requirements/dev.txt',
  ];

  for (const file of files) {
    const filePath = path.join(dir, file);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;

      // Parse: package==version, package>=version, package~=version, package
      const match = trimmed.match(/^([a-zA-Z0-9._-]+)(?:\[[^\]]*\])?\s*(?:([=!<>~]+)\s*([a-zA-Z0-9.*_+-]+))?/);
      if (match) {
        deps[match[1].toLowerCase()] = {
          version: match[3] || '*',
          pinned: (match[2] === '==' || match[2] === '===') && !match[3].includes('*'),
          source: file,
        };
      }
    }
  }

  return deps;
}

function parsePipfileLock(dir) {
  const deps = {};
  const lockPath = path.join(dir, 'Pipfile.lock');

  if (!fs.existsSync(lockPath)) return deps;

  try {
    const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    for (const section of ['default', 'develop']) {
      if (!lock[section]) continue;
      for (const [name, info] of Object.entries(lock[section])) {
        deps[name.toLowerCase()] = {
          version: (info.version || '').replace(/^==/, ''),
          pinned: /^==/.test(info.version || ''),
          source: 'Pipfile.lock',
          hashes: info.hashes,
        };
      }
    }
  } catch {}

  return deps;
}

function parsePoetryLock(dir) {
  const deps = {};
  const lockPath = path.join(dir, 'poetry.lock');

  if (!fs.existsSync(lockPath)) return deps;

  try {
    const content = fs.readFileSync(lockPath, 'utf8');
    const packageBlocks = content.split(/\[\[package\]\]/);

    for (const block of packageBlocks) {
      const nameMatch = block.match(/name\s*=\s*"([^"]+)"/);
      const versionMatch = block.match(/version\s*=\s*"([^"]+)"/);
      if (nameMatch) {
        deps[nameMatch[1].toLowerCase()] = {
          version: versionMatch ? versionMatch[1] : '*',
          pinned: Boolean(versionMatch),
          source: 'poetry.lock',
        };
      }
    }
  } catch {}

  return deps;
}

async function runPythonScan(dir, config = {}) {
  const findings = [];

  // Collect all Python deps from various sources
  const reqDeps = parseRequirements(dir);
  const pipDeps = parsePipfileLock(dir);
  const poetryDeps = parsePoetryLock(dir);
  const allDeps = { ...reqDeps, ...pipDeps, ...poetryDeps };

  // pip config is checked below even when there are no dependency files
  // Check against compromised packages
  for (const [name, info] of Object.entries(allDeps)) {
    const compromised = COMPROMISED_PYPI[name] || COMPROMISED_PYPI[normalizeName(name)];
    if (compromised) {
      for (const entry of compromised) {
        if (entry.versions.includes('*') || entry.versions.includes(info.version)) {
          findings.push({
            type: 'compromised-pypi',
            severity: entry.severity,
            file: info.source,
            package: name,
            version: info.version,
            description: entry.description,
            advisory: entry.advisory,
            ecosystem: 'python',
            recommendation: `URGENT: Remove or replace ${name} immediately`,
          });
        }
      }
    }

    // Known-vulnerable ranges: only a resolved version can be judged
    const vulnerable = VULNERABLE_PYPI[normalizeName(name)] || [];
    const unverified = [];
    for (const entry of vulnerable) {
      const affected = info.pinned ? entryMatches(info.version, entry) : null;
      if (affected === true) {
        findings.push({
          type: 'vulnerable-pypi',
          severity: entry.severity,
          file: info.source,
          package: name,
          version: info.version,
          description: entry.description,
          advisory: entry.advisory,
          ecosystem: 'python',
          recommendation: `Upgrade ${name} to ${entry.fixed} or later`,
        });
      } else if (affected === null) {
        unverified.push(entry);
      }
    }
    if (unverified.length > 0) {
      findings.push({
        type: 'version-not-verified',
        severity: 'low',
        file: info.source,
        package: name,
        version: info.version,
        description: `${name} has known vulnerable versions (${unverified.map(e => e.advisory.split(' / ')[0]).join(', ')}), but "${info.version}" is not an exact release, so it was not checked`,
        advisory: unverified.map(e => e.advisory).join('; '),
        ecosystem: 'python',
        recommendation: `Pin ${name} with == or use a lockfile, and make sure the installed version is ${unverified[0].fixed} or later`,
      });
    }

    // Check typosquats
    for (const [legitimate, typos] of Object.entries(PYTHON_TYPOSQUATS)) {
      if (typos.includes(name)) {
        findings.push({
          type: 'typosquat',
          severity: 'high',
          file: info.source,
          package: name,
          version: info.version,
          description: `Possible typosquat of "${legitimate}" (name-similarity heuristic, not a confirmed advisory)`,
          ecosystem: 'python',
          recommendation: `Verify "${name}" is intended, not a typosquat of "${legitimate}"`,
        });
      }
    }
  }

  // Check for insecure pip configurations
  const pipConf = path.join(dir, 'pip.conf');
  const pipIni = path.join(dir, 'pip.ini');
  for (const conf of [pipConf, pipIni]) {
    if (fs.existsSync(conf)) {
      const content = fs.readFileSync(conf, 'utf8');
      if (content.includes('trusted-host')) {
        findings.push({
          type: 'insecure-config',
          severity: 'high',
          file: path.basename(conf),
          description: 'pip config uses trusted-host (bypasses SSL verification)',
          ecosystem: 'python',
          recommendation: 'Remove trusted-host entries — they disable SSL certificate verification',
        });
      }
      if (content.match(/index-url\s*=\s*http:/i)) {
        findings.push({
          type: 'insecure-config',
          severity: 'critical',
          file: path.basename(conf),
          description: 'pip config uses HTTP (not HTTPS) for package index',
          ecosystem: 'python',
          recommendation: 'Use HTTPS for all package index URLs',
        });
      }
    }
  }

  // Check for pinned vs unpinned dependencies
  const unpinned = Object.entries(reqDeps).filter(([, info]) => info.version === '*');
  if (unpinned.length > 5) {
    findings.push({
      type: 'unpinned-deps',
      severity: 'medium',
      file: 'requirements.txt',
      description: `${unpinned.length} dependencies without pinned versions`,
      ecosystem: 'python',
      packages: unpinned.slice(0, 10).map(([n]) => n),
      recommendation: 'Pin dependency versions to prevent unexpected upgrades',
    });
  }

  return findings;
}

module.exports = { runPythonScan };
