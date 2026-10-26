const fs = require('node:fs');
const path = require('node:path');
const { entryMatches } = require('../version-range');

// Known compromised or vulnerable Go modules
const COMPROMISED_GO = {
  'github.com/dgrijalva/jwt-go': [
    { versions: ['*'], advisory: 'CVE-2020-26160', description: 'Deprecated — audience claim not verified. Use github.com/golang-jwt/jwt/v5', severity: 'high' },
  ],
  'github.com/miekg/dns': [
    { below: '1.1.25', advisory: 'CVE-2019-19794', description: 'Predictable DNS transaction IDs in older releases', severity: 'high' },
  ],
  'github.com/gogo/protobuf': [
    { below: '1.3.2', advisory: 'CVE-2021-3121', description: 'Unmarshaling panic on crafted input — denial of service', severity: 'high' },
  ],
  'github.com/buger/jsonparser': [
    { versions: ['0.0.0-20180318095312-2cac668e8456'], advisory: 'GHSA advisory', description: 'Infinite loop on malformed JSON', severity: 'medium' },
  ],
  'golang.org/x/text': [
    { below: '0.3.8', advisory: 'CVE-2022-32149', description: 'Denial of service via crafted Accept-Language header', severity: 'high' },
  ],
  'golang.org/x/net': [
    { versions: ['0.0.0-20220722155237-a158d28d115b'], below: '0.17.0', advisory: 'CVE-2023-44487 (HTTP/2 Rapid Reset)', description: 'HTTP/2 rapid reset attack — denial of service', severity: 'high' },
  ],
};

function parseGoSum(dir) {
  const deps = {};
  const goSumPath = path.join(dir, 'go.sum');
  if (!fs.existsSync(goSumPath)) return deps;

  const content = fs.readFileSync(goSumPath, 'utf8');
  for (const line of content.split('\n')) {
    const match = line.match(/^(\S+)\s+(v?\S+?)(?:\/go\.mod)?\s+h1:/);
    if (match) {
      const mod = match[1];
      const version = match[2].replace(/^v/, '');
      if (!deps[mod]) {
        deps[mod] = { version, source: 'go.sum' };
      }
    }
  }

  return deps;
}

function parseGoMod(dir) {
  const deps = {};
  const goModPath = path.join(dir, 'go.mod');
  if (!fs.existsSync(goModPath)) return deps;

  const content = fs.readFileSync(goModPath, 'utf8');

  // Parse require blocks
  const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/g);
  if (requireBlock) {
    for (const block of requireBlock) {
      const lines = block.split('\n');
      for (const line of lines) {
        const match = line.match(/^\s+(\S+)\s+(v\S+)/);
        if (match) {
          deps[match[1]] = { version: match[2].replace(/^v/, ''), source: 'go.mod' };
        }
      }
    }
  }

  // Parse single require lines
  const singleReq = /^require\s+(\S+)\s+(v\S+)/gm;
  let match;
  while ((match = singleReq.exec(content))) {
    deps[match[1]] = { version: match[2].replace(/^v/, ''), source: 'go.mod' };
  }

  return deps;
}

async function runGoScan(dir, config = {}) {
  const findings = [];

  // go.mod holds the selected versions; go.sum keeps checksums for historical versions too,
  // so it is only used when there is no go.mod to read
  const goModDeps = parseGoMod(dir);
  const allDeps = fs.existsSync(path.join(dir, 'go.mod')) ? goModDeps : parseGoSum(dir);

  if (Object.keys(allDeps).length === 0) return findings;

  for (const [mod, info] of Object.entries(allDeps)) {
    const compromised = COMPROMISED_GO[mod];
    if (compromised) {
      for (const entry of compromised) {
        if (entryMatches(info.version.replace(/\+incompatible$/, ''), entry) === true) {
          findings.push({
            type: 'compromised-go',
            severity: entry.severity,
            file: info.source,
            package: mod,
            version: info.version,
            description: entry.description,
            advisory: entry.advisory,
            ecosystem: 'go',
            recommendation: `Update ${mod} to the latest version`,
          });
        }
      }
    }
  }

  // Check for replace directives pointing to local paths (potential supply chain risk)
  const goModPath = path.join(dir, 'go.mod');
  if (fs.existsSync(goModPath)) {
    const content = fs.readFileSync(goModPath, 'utf8');
    const replaceRegex = /replace\s+\S+\s+=>\s+(?:\.\.?\/\S+)/gm;
    let match;
    while ((match = replaceRegex.exec(content))) {
      findings.push({
        type: 'local-replace',
        severity: 'medium',
        file: 'go.mod',
        description: `Local replace directive: ${match[0].substring(0, 80)}`,
        ecosystem: 'go',
        recommendation: 'Local replace directives should not be committed — they break reproducible builds',
      });
    }
  }

  return findings;
}

module.exports = { runGoScan };
