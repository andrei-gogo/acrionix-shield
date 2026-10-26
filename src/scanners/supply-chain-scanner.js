const fs = require('node:fs');
const path = require('node:path');
const { redactUrl } = require('../redact');
const { entryMatches } = require('../version-range');
const { runNodeRuntimeCheck } = require('./node-runtime');

// Known compromised packages — maintained list
// Format: { "package-name": [{ version, advisory, description, severity }] }
const KNOWN_COMPROMISED = {
  // The axios supply chain attack (March 2026)
  'axios': [
    {
      versions: ['1.14.1', '0.30.4'],
      advisory: 'Compromised versions published March 31 2026 (12:21-3:29 AM UTC)',
      description: 'Malicious versions injected plain-crypto-js dependency for credential harvesting',
      severity: 'critical',
    },
  ],
  // Malicious dependency from axios attack
  'plain-crypto-js': [
    {
      versions: ['*'],
      advisory: 'Malicious package from axios supply chain attack',
      description: 'Credential harvesting package injected via compromised axios versions',
      severity: 'critical',
    },
  ],
  // eslint-scope hijack (July 2018)
  'eslint-scope': [
    {
      versions: ['3.7.2'],
      advisory: 'GHSA-mh6f-8j2x-4483',
      description: 'Hijacked to steal npm tokens from .npmrc files',
      severity: 'critical',
    },
  ],
  // getcookies backdoor (May 2018)
  'getcookies': [
    {
      versions: ['1.0.0'],
      advisory: 'npm advisory',
      description: 'Backdoor via HTTP headers, injected into mailparser/nodemailer chain',
      severity: 'critical',
    },
  ],
  // crossenv typosquat (Aug 2017)
  'crossenv': [
    {
      versions: ['*'],
      advisory: 'npm advisory',
      description: 'Typosquat of cross-env; exfiltrated environment variables to external server',
      severity: 'critical',
    },
  ],
  // Ledger connect-kit compromise (Dec 2023)
  '@ledgerhq/connect-kit': [
    {
      versions: ['1.1.5', '1.1.6', '1.1.7'],
      advisory: 'Compromised via phishing attack on maintainer',
      description: 'Drainer malware targeting crypto wallets via Ledger CDN',
      severity: 'critical',
    },
  ],
  // rand-user-agent RAT (2025)
  'rand-user-agent': [
    {
      versions: ['1.0.110', '2.0.83', '2.0.84'],
      advisory: 'npm advisory',
      description: 'Remote access trojan (RAT) injected via compromised maintainer',
      severity: 'critical',
    },
  ],
  // es5-ext protestware (Mar 2024)
  'es5-ext': [
    {
      versions: ['0.10.63'],
      advisory: 'npm advisory',
      description: 'Protestware: anti-war message to Russian users (low destructive impact)',
      severity: 'medium',
    },
  ],
  // Historical compromised packages
  'event-stream': [
    {
      versions: ['3.3.6'],
      advisory: 'GHSA-4w2v-q235-vp99',
      description: 'Malicious dependency flatmap-stream injected to steal cryptocurrency wallets',
      severity: 'critical',
    },
  ],
  'flatmap-stream': [
    {
      versions: ['*'],
      advisory: 'GHSA-4w2v-q235-vp99',
      description: 'Malicious package targeting copay bitcoin wallet',
      severity: 'critical',
    },
  ],
  'ua-parser-js': [
    {
      versions: ['0.7.29', '0.8.0', '1.0.0'],
      advisory: 'GHSA-pjwm-rvh2-c87w',
      description: 'Hijacked versions contained cryptominer and credential stealer',
      severity: 'critical',
    },
  ],
  'coa': [
    {
      versions: ['2.0.3', '2.0.4', '2.1.1', '2.1.3', '3.0.1', '3.1.3'],
      advisory: 'GHSA-73qr-pfmq-6rp8',
      description: 'Compromised versions contained malicious code',
      severity: 'critical',
    },
  ],
  'rc': [
    {
      versions: ['1.2.9', '1.3.9', '2.3.9'],
      advisory: 'GHSA-g2q5-5433-rhrf',
      description: 'Compromised versions exfiltrated environment variables',
      severity: 'critical',
    },
  ],
  'colors': [
    {
      versions: ['1.4.1', '1.4.2'],
      advisory: 'Protest-ware: infinite loop crashing applications',
      description: 'Maintainer deliberately corrupted package in protest',
      severity: 'high',
    },
  ],
  'faker': [
    {
      versions: ['6.6.6'],
      advisory: 'Protest-ware: all functionality removed',
      description: 'Maintainer deliberately corrupted package in protest',
      severity: 'high',
    },
  ],
  // 10.1.3 is the patched release; 11.x is clean
  'node-ipc': [
    {
      versions: ['10.1.1', '10.1.2'],
      advisory: 'GHSA-97m3-w2cp-4xx6',
      description: 'Protest-ware: overwrites files on systems with Russian/Belarusian IPs',
      severity: 'critical',
    },
    {
      versions: ['9.1.6', '9.2.3', '12.0.1'],
      advisory: 'node-ipc 2026 compromise (StepSecurity)',
      description: 'Malicious releases published in the 2026 node-ipc supply chain attack',
      severity: 'critical',
    },
  ],
  'peacenotwar': [
    {
      versions: ['*'],
      advisory: 'Protest-ware dependency of node-ipc',
      description: 'Creates files on desktop as political protest',
      severity: 'high',
    },
  ],
  // Tensorlake (Oct 8 2026) — malicious 0.5.144 published with valid provenance; 0.5.143 and earlier unaffected
  'tensorlake': [
    {
      versions: ['0.5.144'],
      advisory: 'GHSA-8g63-53c9-65j2',
      description: 'Compromised release with credential-stealing worm (spreads via stolen npm tokens)',
      severity: 'critical',
    },
  ],
  'tensorlake-native-darwin-arm64': [
    {
      versions: ['0.5.144'],
      advisory: 'GHSA-8g63-53c9-65j2',
      description: 'Compromised release with credential-stealing worm (spreads via stolen npm tokens)',
      severity: 'critical',
    },
  ],
  'tensorlake-native-linux-arm64-gnu': [
    {
      versions: ['0.5.144'],
      advisory: 'GHSA-8g63-53c9-65j2',
      description: 'Compromised release with credential-stealing worm (spreads via stolen npm tokens)',
      severity: 'critical',
    },
  ],
  'tensorlake-native-linux-arm64-musl': [
    {
      versions: ['0.5.144'],
      advisory: 'GHSA-8g63-53c9-65j2',
      description: 'Compromised release with credential-stealing worm (spreads via stolen npm tokens)',
      severity: 'critical',
    },
  ],
  'tensorlake-native-linux-x64-gnu': [
    {
      versions: ['0.5.144'],
      advisory: 'GHSA-8g63-53c9-65j2',
      description: 'Compromised release with credential-stealing worm (spreads via stolen npm tokens)',
      severity: 'critical',
    },
  ],
  'tensorlake-native-linux-x64-musl': [
    {
      versions: ['0.5.144'],
      advisory: 'GHSA-8g63-53c9-65j2',
      description: 'Compromised release with credential-stealing worm (spreads via stolen npm tokens)',
      severity: 'critical',
    },
  ],
  'tensorlake-native-win32-x64': [
    {
      versions: ['0.5.144'],
      advisory: 'GHSA-8g63-53c9-65j2',
      description: 'Compromised release with credential-stealing worm (spreads via stolen npm tokens)',
      severity: 'critical',
    },
  ],
  // SubQuery (Oct 5 2026) — 5.8.2 and the 5.8.3 prerelease are clean
  '@subql/common': [
    {
      versions: ['5.8.3'],
      advisory: 'MAL-2026-17571 (StepSecurity)',
      description: 'Compromised release published through a modified publish workflow',
      severity: 'critical',
    },
  ],
  // MALFEX campaign (Checkmarx, Oct 2026) — three payload paths; exact malicious releases only
  'function-flag': [
    {
      versions: ['1.7.3', '4.0.0', '3.0.0', '2.3.5', '2.3.6', '2.3.7', '2.3.8', '2.3.9'],
      advisory: 'MALFEX (Checkmarx)',
      description: 'Malware: postinstall downloads and runs a Windows node.exe payload',
      severity: 'critical',
    },
  ],
  'function-color': [
    {
      versions: ['1.7.3', '1.0.0'],
      advisory: 'MALFEX (Checkmarx)',
      description: 'Malware: wraps function-flag, which downloads and runs a Windows payload',
      severity: 'critical',
    },
  ],
  'cdn-img-fetch': [
    {
      versions: ['1.0.0', '1.0.1', '1.0.2', '1.0.3'],
      advisory: 'MALFEX (Checkmarx)',
      description: 'Malware: part of the movinlike information-stealer chain',
      severity: 'critical',
    },
  ],
  'img-to-native': [
    {
      versions: ['1.0.0', '1.0.1', '1.0.2', '1.0.3'],
      advisory: 'MALFEX (Checkmarx)',
      description: 'Malware: part of the movinlike information-stealer chain',
      severity: 'critical',
    },
  ],
  'native-runner': [
    {
      versions: ['1.0.0', '1.0.1', '1.0.2', '1.0.3'],
      advisory: 'MALFEX (Checkmarx)',
      description: 'Malware: part of the movinlike information-stealer chain',
      severity: 'critical',
    },
  ],
  'tlxbnhd': [
    {
      versions: ['0.0.1'],
      advisory: 'MALFEX (Checkmarx)',
      description: 'Malware: Overlord RAT loader',
      severity: 'critical',
    },
  ],
  'tldriver': [
    {
      versions: ['0.0.1'],
      advisory: 'MALFEX (Checkmarx)',
      description: 'Malware: Overlord RAT loader',
      severity: 'critical',
    },
  ],
  'mxdriver': [
    {
      versions: ['0.0.1', '0.0.2'],
      advisory: 'MALFEX (Checkmarx)',
      description: 'Malware: Overlord RAT loader',
      severity: 'critical',
    },
  ],
};

// Typosquatting patterns — common legitimate packages and their known typosquats
const TYPOSQUAT_TARGETS = {
  'lodash': ['1odash', 'lodash-js', 'lodahs', 'lodashs'],
  'express': ['expres', 'expresss', 'exppress'],
  'react': ['raect', 'recat', 'reactjs-core'],
  'chalk': ['chalkk', 'cha1k'],
  'commander': ['comander', 'comanderjs'],
  'request': ['reqiest', 'requets'],
  'webpack': ['webpak', 'web-pack'],
  'babel': ['bable', 'babell'],
  'eslint': ['es1int', 'eslitn'],
  'typescript': ['typscript', 'tyepscript'],
  'mongoose': ['mongose', 'mongooose'],
  'moment': ['momnet', 'momet'],
  'axios': ['axois', 'axioss', 'axxios'],
  'cross-env': ['crossenv', 'cross-env.js'],
  'babel-cli': ['babelcli'],
  'gulp': ['glup', 'gulpp'],
  'mongoose': ['mongose', 'mongooose', 'mongoos'],
  'jquery': ['jquery.js', 'jquerry'],
  'grunt-cli': ['gruntcli'],
  'http-proxy': ['http-proxy.js'],
  'mysql': ['mysqljs', 'mysqI'],
  'mariadb': ['maria-db', 'mariaddb'],
  'd3': ['d3.js', 'dd3'],
};

// deps is keyed by install location (or name@version), never by bare name, so a nested
// copy of a package cannot hide another copy at a different version. Each entry carries `name`.
function parseLockfile(dir) {
  const deps = {};

  // Try package-lock.json
  const npmLockPath = path.join(dir, 'package-lock.json');
  if (fs.existsSync(npmLockPath)) {
    try {
      const lock = JSON.parse(fs.readFileSync(npmLockPath, 'utf8'));

      // npm v2+ lockfile format
      if (lock.packages) {
        for (const [pkgPath, info] of Object.entries(lock.packages)) {
          if (!pkgPath) continue; // root package
          const name = pkgPath.replace(/^.*node_modules\//, '');
          deps[pkgPath] = { name, version: info.version, resolved: info.resolved, integrity: info.integrity };
        }
      }

      // npm v1 lockfile format (v2 lockfiles carry both; packages is authoritative)
      if (lock.dependencies && !lock.packages) {
        function walkDeps(depMap, prefix) {
          for (const [name, info] of Object.entries(depMap)) {
            const pkgPath = `${prefix}node_modules/${name}`;
            deps[pkgPath] = { name, version: info.version, resolved: info.resolved, integrity: info.integrity };
            if (info.dependencies) walkDeps(info.dependencies, `${pkgPath}/`);
          }
        }
        walkDeps(lock.dependencies, '');
      }

      return { type: 'package-lock.json', deps };
    } catch (err) {
      return { type: 'package-lock.json', deps: {}, error: err.message };
    }
  }

  // Try yarn.lock (basic parsing)
  const yarnLockPath = path.join(dir, 'yarn.lock');
  if (fs.existsSync(yarnLockPath)) {
    try {
      const content = fs.readFileSync(yarnLockPath, 'utf8');
      const lines = content.split('\n');
      let currentPkg = null;
      let current = null;

      for (const line of lines) {
        const pkgMatch = line.match(/^"?(@?[^@\s"]+)@/);
        if (pkgMatch && !line.startsWith(' ')) {
          currentPkg = pkgMatch[1];
          current = null;
        }
        if (currentPkg && line.match(/^\s+version\s+"?([^"\s]+)/)) {
          const version = line.match(/^\s+version\s+"?([^"\s]+)/)[1];
          current = { name: currentPkg, version };
          deps[`${currentPkg}@${version}`] = current;
        }
        if (current && line.match(/^\s+resolved\s+"?([^"\s]+)/)) {
          current.resolved = line.match(/^\s+resolved\s+"?([^"\s]+)/)[1];
        }
      }

      return { type: 'yarn.lock', deps };
    } catch (err) {
      return { type: 'yarn.lock', deps: {}, error: err.message };
    }
  }

  // Try pnpm-lock.yaml (basic parsing)
  const pnpmLockPath = path.join(dir, 'pnpm-lock.yaml');
  if (fs.existsSync(pnpmLockPath)) {
    try {
      const content = fs.readFileSync(pnpmLockPath, 'utf8');
      const pkgRegex = /\/(@?[^@\s:]+)@([^:\s(]+)/g;
      let match;
      while ((match = pkgRegex.exec(content))) {
        deps[`${match[1]}@${match[2]}`] = { name: match[1], version: match[2] };
      }
      return { type: 'pnpm-lock.yaml', deps };
    } catch (err) {
      return { type: 'pnpm-lock.yaml', deps: {}, error: err.message };
    }
  }

  return { type: null, deps: {} };
}


async function runSupplyChainScan(dir, config = {}) {
  const findings = [];
  // knownCompromised holds npm entries (arrays) plus per-ecosystem maps like knownCompromised.php
  const npmOverrides = Object.fromEntries(
    Object.entries(config.knownCompromised || {}).filter(([, entries]) => Array.isArray(entries))
  );
  const allCompromised = { ...KNOWN_COMPROMISED, ...npmOverrides };

  findings.push(...runNodeRuntimeCheck(dir));

  // Parse lockfile
  const lockfile = parseLockfile(dir);

  if (!lockfile.type) {
    // Only npm projects are expected to have an npm lockfile
    if (!fs.existsSync(path.join(dir, 'package.json'))) return findings;
    findings.push({
      type: 'missing-lockfile',
      severity: 'medium',
      file: 'N/A',
      description: 'No lockfile found (package-lock.json, yarn.lock, or pnpm-lock.yaml)',
      recommendation: 'Use a lockfile to pin dependency versions and prevent supply chain attacks',
    });
    return findings;
  }

  if (lockfile.error) {
    findings.push({
      type: 'parse-error',
      severity: 'low',
      file: lockfile.type,
      description: `Error parsing ${lockfile.type}: ${lockfile.error}`,
      recommendation: 'Ensure your lockfile is valid',
    });
  }

  const depCount = Object.keys(lockfile.deps).length;

  // One finding per name@version, however many install locations share it
  const installs = [];
  const seenInstalls = new Set();
  for (const info of Object.values(lockfile.deps)) {
    const id = `${info.name}@${info.version}`;
    if (seenInstalls.has(id)) continue;
    seenInstalls.add(id);
    installs.push(info);
  }

  // Check against known compromised packages
  for (const info of installs) {
    const name = info.name;
    const compromisedEntries = allCompromised[name];
    if (compromisedEntries) {
      for (const entry of compromisedEntries) {
        if (entryMatches(info.version, entry)) {
          findings.push({
            type: 'compromised-package',
            severity: entry.severity,
            file: lockfile.type,
            package: name,
            version: info.version,
            description: entry.description,
            advisory: entry.advisory,
            recommendation: `URGENT: Remove or update ${name}@${info.version} immediately. ${entry.advisory}`,
          });
        }
      }
    }
  }

  // Check for typosquatting
  for (const { name, version } of installs) {
    for (const [legitimate, typosquats] of Object.entries(TYPOSQUAT_TARGETS)) {
      if (typosquats.includes(name)) {
        findings.push({
          type: 'typosquat',
          severity: 'critical',
          file: lockfile.type,
          package: name,
          version,
          description: `Possible typosquat of "${legitimate}"`,
          recommendation: `Verify that "${name}" is the intended package, not a typosquat of "${legitimate}"`,
        });
      }
    }
  }

  // Check for suspicious registry URLs
  for (const info of installs) {
    const name = info.name;
    if (info.resolved && !info.resolved.startsWith('https://registry.npmjs.org/') &&
        !info.resolved.startsWith('https://registry.yarnpkg.com/') &&
        !info.resolved.startsWith('https://registry.npmmirror.com/') &&
        !info.resolved.match(/^https?:\/\/[^/]*\.github\.com/)) {
      const resolved = redactUrl(info.resolved);
      findings.push({
        type: 'suspicious-registry',
        severity: 'high',
        file: lockfile.type,
        package: name,
        version: info.version,
        resolved,
        description: `Package resolved from non-standard registry: ${resolved}`,
        recommendation: `Verify the registry URL for ${name} is trusted`,
      });
    }
  }

  // Check for missing integrity hashes
  if (lockfile.type === 'package-lock.json') {
    const missingIntegrity = installs
      .filter(info => !info.integrity && info.resolved)
      .map(info => info.name);

    if (missingIntegrity.length > 0) {
      findings.push({
        type: 'missing-integrity',
        severity: 'medium',
        file: lockfile.type,
        description: `${missingIntegrity.length} package(s) missing integrity hashes`,
        packages: missingIntegrity.slice(0, 10),
        recommendation: 'Run npm install to regenerate the lockfile with integrity hashes',
      });
    }
  }

  return findings;
}

module.exports = { runSupplyChainScan };
