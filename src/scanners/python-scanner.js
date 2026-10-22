const fs = require('node:fs');
const path = require('node:path');

// Known compromised PyPI packages
const COMPROMISED_PYPI = {
  // Typosquats of popular packages
  'python-dateutil': [{ versions: ['*'], advisory: 'PyPI advisory', description: 'Typosquat of python-dateutil — credential stealer', severity: 'critical' }],
  'python3-dateutil': [{ versions: ['*'], advisory: 'PyPI advisory', description: 'Typosquat of python-dateutil — credential stealer', severity: 'critical' }],
  'jeIlyfish': [{ versions: ['*'], advisory: 'PyPI advisory', description: 'Typosquat of jellyfish (capital I instead of l) — credential stealer', severity: 'critical' }],
  'python-binance': [{ versions: ['*'], advisory: 'PyPI advisory', description: 'Typosquat targeting Binance API users — credential stealer', severity: 'critical' }],
  'colourfool': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Info stealer disguised as color utility', severity: 'critical' }],
  'daborapackage': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'RAT — remote access trojan', severity: 'critical' }],
  'daboralib': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'RAT — remote access trojan', severity: 'critical' }],
  'culturestreak': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Cryptominer targeting GitLab CI', severity: 'critical' }],
  'ctx': [{ versions: ['0.1.2', '0.2.6'], advisory: 'PyPI advisory 2022', description: 'Hijacked — exfiltrates AWS keys and environment variables', severity: 'critical' }],
  'phpass': [{ versions: ['*'], advisory: 'PyPI advisory 2022', description: 'Hijacked — exfiltrates AWS keys', severity: 'critical' }],
  'colorslib': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Info stealer — exfiltrates Discord tokens and browser data', severity: 'critical' }],
  'httpslib': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Info stealer — exfiltrates Discord tokens and browser data', severity: 'critical' }],
  'libhttps': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Info stealer — exfiltrates Discord tokens and browser data', severity: 'critical' }],
  'pypistats': [{ versions: ['*'], advisory: 'PyPI advisory', description: 'Typosquat of pypistats — data exfiltration', severity: 'critical' }],
  'free-net-vpn': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Credential stealer disguised as VPN tool', severity: 'critical' }],
  'free-net-vpn2': [{ versions: ['*'], advisory: 'PyPI advisory 2023', description: 'Credential stealer disguised as VPN tool', severity: 'critical' }],
  'beautifulsoup': [{ versions: ['*'], advisory: 'PyPI advisory', description: 'Typosquat of beautifulsoup4 — malicious payload', severity: 'critical' }],
  'requessts': [{ versions: ['*'], advisory: 'PyPI advisory', description: 'Typosquat of requests — credential stealer', severity: 'critical' }],
  'requets': [{ versions: ['*'], advisory: 'PyPI advisory', description: 'Typosquat of requests — credential stealer', severity: 'critical' }],
};

// Python typosquat targets
const PYTHON_TYPOSQUATS = {
  'requests': ['requessts', 'requets', 'request', 'requsts', 'reequests'],
  'beautifulsoup4': ['beautifulsoup', 'beautifulsoup3', 'beutifulsoup4'],
  'numpy': ['numppy', 'numpi', 'numpyy'],
  'pandas': ['pandass', 'pnadas', 'pandsa'],
  'flask': ['flaask', 'flaskk'],
  'django': ['djano', 'djnago', 'djangoo'],
  'tensorflow': ['tenserflow', 'tensorflw', 'tensroflow'],
  'pytorch': ['pytorh', 'pytoch', 'py-torch'],
  'scikit-learn': ['sklearn', 'scikitlearn', 'scikit_learn'],
  'pillow': ['piilow', 'pilllow', 'Pillow-SIMD'],
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
      const match = trimmed.match(/^([a-zA-Z0-9._-]+)\s*(?:[=!<>~]+\s*([a-zA-Z0-9.*_-]+))?/);
      if (match) {
        deps[match[1].toLowerCase()] = {
          version: match[2] || '*',
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
    const compromised = COMPROMISED_PYPI[name];
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

    // Check typosquats
    for (const [legitimate, typos] of Object.entries(PYTHON_TYPOSQUATS)) {
      if (typos.includes(name)) {
        findings.push({
          type: 'typosquat',
          severity: 'critical',
          file: info.source,
          package: name,
          version: info.version,
          description: `Possible typosquat of "${legitimate}"`,
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
