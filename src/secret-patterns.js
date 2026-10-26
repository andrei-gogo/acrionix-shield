// Provider-specific secret formats, shared by the leak scanner (files) and the git scanner (history).
// Each pattern has a distinctive prefix or structure, so it's safe to run over minified bundles.
const PROVIDER_SECRET_PATTERNS = [
  { pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/g, description: 'AWS Access Key ID', severity: 'critical' },
  { pattern: /(?:^|[^a-zA-Z0-9])(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/g, description: 'AWS Secret Access Key', severity: 'critical' },
  { pattern: /ghp_[A-Za-z0-9_]{36}/g, description: 'GitHub Personal Access Token', severity: 'critical' },
  { pattern: /gho_[A-Za-z0-9_]{36}/g, description: 'GitHub OAuth Token', severity: 'critical' },
  { pattern: /github_pat_[A-Za-z0-9_]{22,}/g, description: 'GitHub Fine-Grained PAT', severity: 'critical' },
  { pattern: /npm_[A-Za-z0-9]{36}/g, description: 'npm access token', severity: 'critical' },
  { pattern: /sk-[a-zA-Z0-9]{48}/g, description: 'OpenAI API key', severity: 'critical' },
  { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/g, description: 'Anthropic API key', severity: 'critical' },
  { pattern: /xox[bporas]-[0-9]{10,}-[a-zA-Z0-9-]+/g, description: 'Slack token', severity: 'critical' },
  { pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, description: 'Private key', severity: 'critical' },
  { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, description: 'Stripe live secret key', severity: 'critical' },
  { pattern: /sk_test_[a-zA-Z0-9]{24,}/g, description: 'Stripe test secret key', severity: 'high' },
  { pattern: /rk_live_[a-zA-Z0-9]{24,}/g, description: 'Stripe restricted key', severity: 'critical' },
  { pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, description: 'SendGrid API key', severity: 'critical' },
  { pattern: /sq0csp-[a-zA-Z0-9_-]{43}/g, description: 'Square OAuth secret', severity: 'critical' },
  { pattern: /AIza[a-zA-Z0-9_-]{35}/g, description: 'Google API key', severity: 'high' },
  { pattern: /ya29\.[a-zA-Z0-9_-]{60,}/g, description: 'Google OAuth access token', severity: 'critical' },
  { pattern: /GOCSPX-[a-zA-Z0-9_-]{28}/g, description: 'Google OAuth client secret', severity: 'critical' },
  { pattern: /mongodb(\+srv)?:\/\/[^\s:@/'"]+:[^\s@'"]+@/g, description: 'MongoDB connection string with credentials', severity: 'critical' },
  { pattern: /postgres(?:ql)?:\/\/[^\s:@/'"]+:[^\s@'"]+@/g, description: 'PostgreSQL connection string with credentials', severity: 'critical' },
  { pattern: /mysql:\/\/[^\s:@/'"]+:[^\s@'"]+@/g, description: 'MySQL connection string with credentials', severity: 'critical' },
  { pattern: /rediss?:\/\/:[^\s@'"]+@/g, description: 'Redis connection string with password', severity: 'critical' },
];

// Loose formats (short hex/base64 shapes) that misfire on hashes in built files.
// Used only on lines added in git history, where a match is far more likely to be real.
const HISTORY_ONLY_SECRET_PATTERNS = [
  { pattern: /key-[a-zA-Z0-9]{32}/g, description: 'Mailgun API key', severity: 'critical' },
  { pattern: /AC[a-f0-9]{32}/g, description: 'Twilio Account SID', severity: 'high' },
  { pattern: /SK[a-f0-9]{32}/g, description: 'Twilio API key', severity: 'critical' },
  { pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, description: 'JSON Web Token (JWT)', severity: 'medium' },
  { pattern: /[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com/g, description: 'Google OAuth client ID', severity: 'medium' },
  { pattern: /heroku[a-z0-9_-]*[=:]\s*[a-f0-9-]{36}/gi, description: 'Heroku API key', severity: 'critical' },
];

module.exports = { PROVIDER_SECRET_PATTERNS, HISTORY_ONLY_SECRET_PATTERNS };
