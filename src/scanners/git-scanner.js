const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');
const { redactSecret } = require('../redact');

// Patterns that should never appear in git history
const GIT_SECRET_PATTERNS = [
  { pattern: /AKIA[A-Z0-9]{16}/g, description: 'AWS Access Key ID', severity: 'critical' },
  { pattern: /(?:^|[^a-zA-Z0-9])(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/g, description: 'AWS Secret Access Key', severity: 'critical' },
  { pattern: /ghp_[A-Za-z0-9_]{36}/g, description: 'GitHub Personal Access Token', severity: 'critical' },
  { pattern: /gho_[A-Za-z0-9_]{36}/g, description: 'GitHub OAuth Token', severity: 'critical' },
  { pattern: /github_pat_[A-Za-z0-9_]{22,}/g, description: 'GitHub Fine-Grained PAT', severity: 'critical' },
  { pattern: /npm_[A-Za-z0-9]{36}/g, description: 'npm Access Token', severity: 'critical' },
  { pattern: /sk-[a-zA-Z0-9]{48}/g, description: 'OpenAI API Key', severity: 'critical' },
  { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/g, description: 'Anthropic API Key', severity: 'critical' },
  { pattern: /xox[bporas]-[0-9]{10,}-[a-zA-Z0-9-]+/g, description: 'Slack Token', severity: 'critical' },
  { pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, description: 'Private Key', severity: 'critical' },
  { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, description: 'Stripe Live Secret Key', severity: 'critical' },
  { pattern: /sk_test_[a-zA-Z0-9]{24,}/g, description: 'Stripe Test Secret Key', severity: 'high' },
  { pattern: /rk_live_[a-zA-Z0-9]{24,}/g, description: 'Stripe Restricted Key', severity: 'critical' },
  { pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, description: 'SendGrid API Key', severity: 'critical' },
  { pattern: /key-[a-zA-Z0-9]{32}/g, description: 'Mailgun API Key', severity: 'critical' },
  { pattern: /AC[a-f0-9]{32}/g, description: 'Twilio Account SID', severity: 'high' },
  { pattern: /SK[a-f0-9]{32}/g, description: 'Twilio API Key', severity: 'critical' },
  { pattern: /sq0csp-[a-zA-Z0-9_-]{43}/g, description: 'Square OAuth Secret', severity: 'critical' },
  { pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, description: 'JSON Web Token (JWT)', severity: 'medium' },
  { pattern: /AIza[a-zA-Z0-9_-]{35}/g, description: 'Google API Key', severity: 'high' },
  { pattern: /[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com/g, description: 'Google OAuth Client ID', severity: 'medium' },
  { pattern: /ya29\.[a-zA-Z0-9_-]{60,}/g, description: 'Google OAuth Access Token', severity: 'critical' },
  { pattern: /GOCSPX-[a-zA-Z0-9_-]{28}/g, description: 'Google OAuth Client Secret', severity: 'critical' },
  { pattern: /heroku[a-z0-9_-]*[=:]\s*[a-f0-9-]{36}/gi, description: 'Heroku API Key', severity: 'critical' },
  { pattern: /mongodb(\+srv)?:\/\/[^\s:@]+:[^\s@]+@/g, description: 'MongoDB Connection String with credentials', severity: 'critical' },
  { pattern: /postgres:\/\/[^\s:@]+:[^\s@]+@/g, description: 'PostgreSQL Connection String with credentials', severity: 'critical' },
  { pattern: /mysql:\/\/[^\s:@]+:[^\s@]+@/g, description: 'MySQL Connection String with credentials', severity: 'critical' },
  { pattern: /redis:\/\/:[^\s@]+@/g, description: 'Redis Connection String with password', severity: 'critical' },
];

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
