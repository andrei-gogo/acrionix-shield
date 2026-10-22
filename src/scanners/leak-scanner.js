const fs = require('node:fs');
const path = require('node:path');
const { redactSecret } = require('../redact');

// Dangerous file patterns that should never be in an npm package
const DANGEROUS_FILES = [
  { pattern: /\.map$/i, description: 'Source map file', severity: 'critical' },
  { pattern: /\.ts$/i, description: 'TypeScript source file', severity: 'high', exclude: /\.d\.ts$/ },
  { pattern: /\.tsx$/i, description: 'TSX source file', severity: 'high' },
  { pattern: /\.env(\.|$)/i, description: 'Environment file', severity: 'critical' },
  { pattern: /\.pem$/i, description: 'Private key file', severity: 'critical' },
  { pattern: /\.key$/i, description: 'Key file', severity: 'critical' },
  { pattern: /\.p12$/i, description: 'PKCS#12 certificate', severity: 'critical' },
  { pattern: /\.pfx$/i, description: 'PFX certificate', severity: 'critical' },
  { pattern: /\.jks$/i, description: 'Java keystore', severity: 'critical' },
  { pattern: /id_rsa/i, description: 'SSH private key', severity: 'critical' },
  { pattern: /id_ed25519/i, description: 'SSH private key', severity: 'critical' },
  { pattern: /\.sqlite$/i, description: 'SQLite database', severity: 'high' },
  { pattern: /\.db$/i, description: 'Database file', severity: 'medium' },
  { pattern: /\.log$/i, description: 'Log file', severity: 'medium' },
  { pattern: /\.bak$/i, description: 'Backup file', severity: 'medium' },
  { pattern: /\.orig$/i, description: 'Original/backup file', severity: 'low' },
  { pattern: /\.swp$/i, description: 'Vim swap file', severity: 'low' },
  { pattern: /\.DS_Store$/i, description: 'macOS metadata file', severity: 'low' },
  { pattern: /Thumbs\.db$/i, description: 'Windows metadata file', severity: 'low' },
  { pattern: /\.npmrc$/i, description: 'npm config (may contain tokens)', severity: 'critical' },
  { pattern: /\.yarnrc$/i, description: 'Yarn config (may contain tokens)', severity: 'high' },
];

// Cloud storage URL patterns in file contents
const CLOUD_URL_PATTERNS = [
  { pattern: /https?:\/\/[a-z0-9-]+\.s3[.-](?:amazonaws|aws)\.com/gi, description: 'AWS S3 bucket URL', severity: 'high' },
  { pattern: /https?:\/\/storage\.googleapis\.com\/[a-z0-9_.-]+/gi, description: 'Google Cloud Storage URL', severity: 'high' },
  { pattern: /https?:\/\/[a-z0-9-]+\.blob\.core\.windows\.net/gi, description: 'Azure Blob Storage URL', severity: 'high' },
  { pattern: /https?:\/\/[a-z0-9-]+\.r2\.cloudflarestorage\.com/gi, description: 'Cloudflare R2 Storage URL', severity: 'critical' },
  { pattern: /https?:\/\/[a-z0-9-]+\.r2\.dev/gi, description: 'Cloudflare R2 public URL', severity: 'critical' },
  { pattern: /https?:\/\/[a-z0-9-]+\.supabase\.co\/storage/gi, description: 'Supabase Storage URL', severity: 'high' },
];

// Sensitive content patterns in file contents
const SENSITIVE_CONTENT_PATTERNS = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][a-z0-9]{20,}['"]/gi, description: 'Hardcoded API key', severity: 'critical' },
  { pattern: /(?:secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi, description: 'Hardcoded secret/password', severity: 'critical' },
  { pattern: /(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][a-z0-9._-]{20,}['"]/gi, description: 'Hardcoded access token', severity: 'critical' },
  { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, description: 'Embedded private key', severity: 'critical' },
  { pattern: /-----BEGIN CERTIFICATE-----/g, description: 'Embedded certificate', severity: 'medium', public: true },
  { pattern: /\/\/# sourceMappingURL=.+\.map/g, description: 'Source map reference', severity: 'high', public: true },
  { pattern: /\/\/#\s*sourceURL=/g, description: 'Source URL directive', severity: 'high', public: true },
  { pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/g, description: 'AWS Access Key ID', severity: 'critical' },
  { pattern: /ghp_[A-Za-z0-9_]{36}/g, description: 'GitHub Personal Access Token', severity: 'critical' },
  { pattern: /npm_[A-Za-z0-9]{36}/g, description: 'npm access token', severity: 'critical' },
  { pattern: /sk-[a-zA-Z0-9]{48}/g, description: 'OpenAI API key', severity: 'critical' },
  { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/g, description: 'Anthropic API key', severity: 'critical' },
  { pattern: /xox[bporas]-[0-9]{10,}-[a-zA-Z0-9-]+/g, description: 'Slack token', severity: 'critical' },
];

// Internal path patterns that indicate source code exposure
const INTERNAL_PATH_PATTERNS = [
  { pattern: /\/Users\/[a-z0-9._-]+\//gi, description: 'macOS user home path', severity: 'high' },
  { pattern: /C:\\Users\\[a-z0-9._-]+\\/gi, description: 'Windows user home path', severity: 'high' },
  { pattern: /\/home\/[a-z0-9._-]+\//gi, description: 'Linux user home path', severity: 'high' },
  { pattern: /\/internal\//gi, description: 'Internal directory reference', severity: 'medium' },
  { pattern: /\/private\//gi, description: 'Private directory reference', severity: 'medium' },
];

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'coverage',
  '.nyc_output', '.cache', '__pycache__',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.bmp', '.webp',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.zip', '.tar', '.gz', '.br', '.zst',
  '.pdf', '.exe', '.dll', '.so', '.dylib',
  '.mp3', '.mp4', '.wav', '.avi', '.mov',
]);

function walkDir(dir, ignorePatterns = []) {
  const results = [];

  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.relative(dir, fullPath);

      if (ignorePatterns.some(p => relativePath.match(p))) continue;

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        results.push({ fullPath, relativePath, name: entry.name });
      }
    }
  }

  walk(dir);
  return results;
}

async function runLeakScan(dir, config = {}) {
  const findings = [];
  const ignorePatterns = (config.ignorePatterns || []).map(p => new RegExp(p));
  const files = walkDir(dir, ignorePatterns);

  // Check for .npmignore or files field in package.json
  const hasNpmignore = fs.existsSync(path.join(dir, '.npmignore'));
  const pkgJsonPath = path.join(dir, 'package.json');
  let hasFilesField = false;

  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      hasFilesField = Array.isArray(pkg.files);
    } catch {}
  }

  // npm publish advice only applies to npm packages
  if (fs.existsSync(pkgJsonPath) && !hasNpmignore && !hasFilesField) {
    findings.push({
      type: 'config',
      severity: 'medium',
      file: 'package.json',
      description: 'No .npmignore or "files" field in package.json — all files may be published',
      recommendation: 'Add a "files" field to package.json or create a .npmignore to control what gets published',
    });
  }

  for (const file of files) {
    // Check filename against dangerous patterns
    for (const rule of DANGEROUS_FILES) {
      if (rule.exclude && rule.exclude.test(file.name)) continue;
      if (rule.pattern.test(file.name)) {
        findings.push({
          type: 'dangerous-file',
          severity: rule.severity,
          file: file.relativePath,
          description: rule.description,
          recommendation: `Remove ${file.relativePath} before publishing or add it to .npmignore`,
        });
      }
    }

    // Scan file contents for sensitive patterns (skip binaries)
    const ext = path.extname(file.name).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) continue;

    let content;
    try {
      const stat = fs.statSync(file.fullPath);
      if (stat.size > 2 * 1024 * 1024) continue; // Skip files > 2MB
      content = fs.readFileSync(file.fullPath, 'utf8');
    } catch {
      continue;
    }

    const allContentPatterns = [
      ...CLOUD_URL_PATTERNS.map(p => ({ ...p, public: true })),
      ...SENSITIVE_CONTENT_PATTERNS,
      ...INTERNAL_PATH_PATTERNS.map(p => ({ ...p, public: true })),
      ...(config.customCloudPatterns || []).map(p => ({
        pattern: new RegExp(p.pattern, p.flags || 'gi'),
        description: p.description || 'Custom cloud pattern match',
        severity: p.severity || 'high',
      })),
      ...(config.customSensitivePatterns || []).map(p => ({
        pattern: new RegExp(p.pattern, p.flags || 'gi'),
        description: p.description || 'Custom sensitive pattern match',
        severity: p.severity || 'high',
      })),
    ];

    for (const rule of allContentPatterns) {
      // Reset regex lastIndex
      rule.pattern.lastIndex = 0;
      const matches = content.match(rule.pattern);
      if (matches) {
        // Find line number of first match
        const idx = content.indexOf(matches[0]);
        const line = content.substring(0, idx).split('\n').length;

        findings.push({
          type: 'sensitive-content',
          severity: rule.severity,
          file: file.relativePath,
          line,
          description: rule.description,
          match: rule.public
            ? matches[0].substring(0, 100) + (matches[0].length > 100 ? '...' : '')
            : redactSecret(matches[0]),
          count: matches.length,
          recommendation: `Review and remove sensitive content from ${file.relativePath}:${line}`,
        });
      }
    }
  }

  return findings;
}

module.exports = { runLeakScan };
