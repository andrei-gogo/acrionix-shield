const fs = require('node:fs');
const path = require('node:path');

// Known compromised RubyGems
const COMPROMISED_GEMS = {
  'rest-client': [
    { versions: ['1.6.13'], advisory: 'CVE-2019-15224', description: 'Hijacked — backdoor that exfiltrated credentials via pastebin', severity: 'critical' },
  ],
  'strong_password': [
    { versions: ['0.0.7'], advisory: 'RubyGems advisory 2019', description: 'Hijacked — backdoor that downloaded malicious code', severity: 'critical' },
  ],
  'bootstrap-sass': [
    { versions: ['3.2.0.3'], advisory: 'RubyGems advisory 2019', description: 'Hijacked — backdoor injected into gem', severity: 'critical' },
  ],
  'rsa-key-converter': [
    { versions: ['*'], advisory: 'RubyGems advisory', description: 'Typosquat — credential stealer', severity: 'critical' },
  ],
  'atlas-client': [
    { versions: ['*'], advisory: 'RubyGems advisory 2023', description: 'Malicious gem — data exfiltration', severity: 'critical' },
  ],
  'actionmailer-text': [
    { versions: ['*'], advisory: 'RubyGems advisory', description: 'Typosquat of actionmailer — malicious payload', severity: 'critical' },
  ],
  'activesupport-text': [
    { versions: ['*'], advisory: 'RubyGems advisory', description: 'Typosquat of activesupport — malicious payload', severity: 'critical' },
  ],
};

const RUBY_TYPOSQUATS = {
  'rails': ['raills', 'raiils', 'rail'],
  'devise': ['devize', 'deviise'],
  'sidekiq': ['sidekik', 'sidekiqq'],
  'puma': ['pumaa', 'pumma'],
  'nokogiri': ['nokogri', 'nokogiii'],
  'activerecord': ['active-record', 'activerecrd'],
  'actionmailer': ['actionmailer-text', 'action-mailer'],
  'activesupport': ['activesupport-text', 'active-support'],
  'bundler': ['bunlder', 'bundlr'],
  'rspec': ['rsspec', 'r-spec'],
};

function parseGemfileLock(dir) {
  const deps = {};
  const lockPath = path.join(dir, 'Gemfile.lock');
  if (!fs.existsSync(lockPath)) return deps;

  const content = fs.readFileSync(lockPath, 'utf8');
  const lines = content.split('\n');
  let inSpecs = false;

  for (const line of lines) {
    if (line.trim() === 'specs:') {
      inSpecs = true;
      continue;
    }
    if (inSpecs && line.match(/^\S/)) {
      inSpecs = false;
      continue;
    }
    if (inSpecs) {
      const match = line.match(/^\s{4}(\S+)\s+\(([^)]+)\)/);
      if (match) {
        deps[match[1]] = { version: match[2], source: 'Gemfile.lock' };
      }
    }
  }

  return deps;
}

function parseGemfile(dir) {
  const deps = {};
  const gemfilePath = path.join(dir, 'Gemfile');
  if (!fs.existsSync(gemfilePath)) return deps;

  const content = fs.readFileSync(gemfilePath, 'utf8');
  const gemRegex = /gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/g;
  let match;
  while ((match = gemRegex.exec(content))) {
    deps[match[1]] = { version: match[2] || '*', source: 'Gemfile' };
  }

  return deps;
}

async function runRubyScan(dir, config = {}) {
  const findings = [];

  const lockDeps = parseGemfileLock(dir);
  const gemfileDeps = parseGemfile(dir);
  const allDeps = { ...gemfileDeps, ...lockDeps };

  if (Object.keys(allDeps).length === 0) return findings;

  for (const [name, info] of Object.entries(allDeps)) {
    const compromised = COMPROMISED_GEMS[name];
    if (compromised) {
      for (const entry of compromised) {
        if (entry.versions.includes('*') || entry.versions.includes(info.version)) {
          findings.push({
            type: 'compromised-gem',
            severity: entry.severity,
            file: info.source,
            package: name,
            version: info.version,
            description: entry.description,
            advisory: entry.advisory,
            ecosystem: 'ruby',
            recommendation: `URGENT: Remove or update ${name} immediately`,
          });
        }
      }
    }

    for (const [legitimate, typos] of Object.entries(RUBY_TYPOSQUATS)) {
      if (typos.includes(name)) {
        findings.push({
          type: 'typosquat',
          severity: 'critical',
          file: info.source,
          package: name,
          version: info.version,
          description: `Possible typosquat of "${legitimate}"`,
          ecosystem: 'ruby',
          recommendation: `Verify "${name}" is intended, not a typosquat of "${legitimate}"`,
        });
      }
    }
  }

  // Check for HTTP gem sources
  const gemfilePath = path.join(dir, 'Gemfile');
  if (fs.existsSync(gemfilePath)) {
    const content = fs.readFileSync(gemfilePath, 'utf8');
    if (content.match(/source\s+['"]http:\/\//)) {
      findings.push({
        type: 'insecure-source',
        severity: 'critical',
        file: 'Gemfile',
        description: 'Gem source uses HTTP instead of HTTPS',
        ecosystem: 'ruby',
        recommendation: 'Use source "https://rubygems.org" instead of HTTP',
      });
    }
  }

  return findings;
}

module.exports = { runRubyScan };
