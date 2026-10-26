const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');
const { redactSecret } = require('../redact');
const { PROVIDER_SECRET_PATTERNS, HISTORY_ONLY_SECRET_PATTERNS } = require('../secret-patterns');

// Patterns that should never appear in git history
const GIT_SECRET_PATTERNS = [...PROVIDER_SECRET_PATTERNS, ...HISTORY_ONLY_SECRET_PATTERNS];

// Files that should be in .gitignore but often aren't
const SHOULD_BE_GITIGNORED = [
  { pattern: '.env', description: 'Environment file with secrets' },
  { pattern: '.env.local', description: 'Local environment file' },
  { pattern: '.env.production', description: 'Production environment file' },
  { pattern: '*.pem', description: 'PEM certificate/key files' },
  { pattern: '*.key', description: 'Key files' },
  { pattern: 'id_rsa', description: 'SSH private key' },
  { pattern: '.npmrc', description: 'npm config with tokens' },
  { pattern: '.pypirc', description: 'PyPI config with tokens' },
  { pattern: '.docker/config.json', description: 'Docker registry credentials' },
  { pattern: 'credentials.json', description: 'Credentials file' },
  { pattern: 'service-account*.json', description: 'GCP service account key' },
];

function isGitRepo(dir) {
  return fs.existsSync(path.join(dir, '.git'));
}

function getGitignorePatterns(dir) {
  const gitignorePath = path.join(dir, '.gitignore');
  if (!fs.existsSync(gitignorePath)) return [];
  return fs.readFileSync(gitignorePath, 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
}

function isIgnored(pattern, gitignorePatterns) {
  return gitignorePatterns.some(gp => {
    if (gp === pattern) return true;
    if (gp.endsWith('*') && pattern.startsWith(gp.slice(0, -1))) return true;
    if (gp.startsWith('*') && pattern.endsWith(gp.slice(1))) return true;
    return false;
  });
}

async function runGitScan(dir, config = {}) {
  const findings = [];

  if (!isGitRepo(dir)) return findings;

  // Check .gitignore for missing sensitive patterns
  const gitignorePatterns = getGitignorePatterns(dir);

  if (gitignorePatterns.length === 0) {
    findings.push({
      type: 'missing-gitignore',
      severity: 'high',
      file: '.gitignore',
      description: 'No .gitignore file found',
      ecosystem: 'git',
      recommendation: 'Create a .gitignore file to prevent committing sensitive files',
    });
  } else {
    for (const entry of SHOULD_BE_GITIGNORED) {
      if (!isIgnored(entry.pattern, gitignorePatterns)) {
        // Only flag if the file actually exists
        const exists = entry.pattern.includes('*')
          ? false  // Don't check glob patterns for existence
          : fs.existsSync(path.join(dir, entry.pattern));

        if (exists) {
          findings.push({
            type: 'not-gitignored',
            severity: 'high',
            file: entry.pattern,
            description: `${entry.description} exists but is not in .gitignore`,
            ecosystem: 'git',
            recommendation: `Add "${entry.pattern}" to .gitignore`,
          });
        }
      }
    }
  }

  // Scan recent git history for secrets (last 50 commits).
  // Every commit patch is scanned — added files and modifications — but only added lines,
  // so removing a secret does not report it again.
  try {
    const log = execSync(
      'git log -p --no-color --no-ext-diff -n 50 --format="commit %H" -- . 2>/dev/null',
      { cwd: dir, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8', timeout: 30000 }
    );

    const reported = new Set();
    let commit = null;
    let file = null;

    for (const line of log.split('\n')) {
      const commitMatch = line.match(/^commit ([a-f0-9]{40})$/);
      if (commitMatch) {
        commit = commitMatch[1];
        file = null;
        continue;
      }
      const fileMatch = line.match(/^\+\+\+ (?:b\/(.+)|\/dev\/null)$/);
      if (fileMatch) {
        file = fileMatch[1] || null;
        continue;
      }
      if (!commit || !file || !line.startsWith('+')) continue;

      const added = line.slice(1);
      for (const rule of GIT_SECRET_PATTERNS) {
        rule.pattern.lastIndex = 0;
        const matches = added.match(rule.pattern);
        if (!matches) continue;

        const key = `${commit}:${file}:${rule.description}`;
        if (reported.has(key)) continue;
        reported.add(key);

        // Lower severity for test files, examples and fixtures
        const isTestOrExample = /test|example|fixture/i.test(file);

        findings.push({
          type: 'git-secret',
          severity: isTestOrExample ? 'medium' : rule.severity,
          file,
          commit: commit.slice(0, 12),
          description: `${rule.description} found in git history`,
          match: redactSecret(matches[0]),
          ecosystem: 'git',
          recommendation: `Rotate this ${rule.description.toLowerCase()} immediately and remove from git history using git filter-branch or BFG Repo-Cleaner`,
        });
      }
    }
  } catch {
    // Git not available or repo too large, skip history scan
  }

  // Check for signed commits configuration
  try {
    const signConfig = execSync('git config --get commit.gpgsign 2>/dev/null', { cwd: dir, encoding: 'utf8' }).trim();
    // If gpgsign is configured, good
  } catch {
    findings.push({
      type: 'git-config',
      severity: 'low',
      file: '.git/config',
      description: 'Git commit signing not configured',
      ecosystem: 'git',
      recommendation: 'Enable commit signing with: git config commit.gpgsign true',
    });
  }

  return findings;
}

module.exports = { runGitScan };
