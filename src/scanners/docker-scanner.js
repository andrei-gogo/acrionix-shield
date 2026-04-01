const fs = require('node:fs');
const path = require('node:path');

// Known vulnerable or deprecated base images
const RISKY_IMAGES = {
  'node:latest': { severity: 'high', reason: 'Unpinned "latest" tag — builds are not reproducible' },
  'python:latest': { severity: 'high', reason: 'Unpinned "latest" tag — builds are not reproducible' },
  'ubuntu:latest': { severity: 'high', reason: 'Unpinned "latest" tag — builds are not reproducible' },
  'alpine:latest': { severity: 'medium', reason: 'Unpinned "latest" tag — prefer pinned version' },
  'nginx:latest': { severity: 'high', reason: 'Unpinned "latest" tag — builds are not reproducible' },
  'redis:latest': { severity: 'high', reason: 'Unpinned "latest" tag — builds are not reproducible' },
  'mongo:latest': { severity: 'high', reason: 'Unpinned "latest" tag — builds are not reproducible' },
  'postgres:latest': { severity: 'high', reason: 'Unpinned "latest" tag — builds are not reproducible' },
  'mysql:latest': { severity: 'high', reason: 'Unpinned "latest" tag — builds are not reproducible' },
};

// Dockerfile security rules
const DOCKERFILE_RULES = [
  {
    pattern: /^USER\s+root\s*$/im,
    description: 'Container runs as root user',
    severity: 'high',
    recommendation: 'Add a non-root USER instruction (e.g., USER node, USER appuser)',
  },
  {
    pattern: /--no-check-certificate/i,
    description: 'SSL certificate verification disabled (wget --no-check-certificate)',
    severity: 'critical',
    recommendation: 'Remove --no-check-certificate — it allows MITM attacks',
  },
  {
    pattern: /curl\s+.*-k\b/i,
    description: 'SSL certificate verification disabled (curl -k)',
    severity: 'critical',
    recommendation: 'Remove -k/--insecure flag from curl — it allows MITM attacks',
  },
  {
    pattern: /npm\s+install\s+.*--unsafe-perm/i,
    description: 'npm install with --unsafe-perm (runs scripts as root)',
    severity: 'high',
    recommendation: 'Remove --unsafe-perm and use a non-root user instead',
  },
  {
    pattern: /pip\s+install\s+.*--trusted-host/i,
    description: 'pip install with --trusted-host (bypasses SSL)',
    severity: 'high',
    recommendation: 'Remove --trusted-host and use HTTPS package indices',
  },
  {
    pattern: /EXPOSE\s+22\b/i,
    description: 'SSH port (22) exposed in container',
    severity: 'high',
    recommendation: 'Do not run SSH in containers — use docker exec or orchestrator tools',
  },
  {
    pattern: /EXPOSE\s+23\b/i,
    description: 'Telnet port (23) exposed — unencrypted protocol',
    severity: 'critical',
    recommendation: 'Never expose Telnet — use SSH or HTTPS instead',
  },
  {
    pattern: /EXPOSE\s+21\b/i,
    description: 'FTP port (21) exposed — unencrypted protocol',
    severity: 'high',
    recommendation: 'Use SFTP or HTTPS for file transfers instead of FTP',
  },
  {
    pattern: /ADD\s+https?:\/\//i,
    description: 'ADD instruction fetches remote URL (unverified)',
    severity: 'high',
    recommendation: 'Use COPY with pre-downloaded and verified files, or RUN curl with checksum verification',
  },
  {
    pattern: /ENV\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=/i,
    description: 'Secret hardcoded in ENV instruction',
    severity: 'critical',
    recommendation: 'Use Docker secrets, build args, or runtime environment variables instead',
  },
  {
    pattern: /ARG\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=/i,
    description: 'Secret in build ARG (visible in image history)',
    severity: 'critical',
    recommendation: 'Use Docker secrets or multi-stage builds to avoid leaking build args',
  },
  {
    pattern: /apt-get\s+install\s+(?!.*--no-install-recommends)/im,
    description: 'apt-get install without --no-install-recommends (bloated image)',
    severity: 'low',
    recommendation: 'Add --no-install-recommends to reduce image size and attack surface',
  },
  {
    pattern: /apk\s+add\s+(?!.*--no-cache)/im,
    description: 'apk add without --no-cache (stale cache in image)',
    severity: 'low',
    recommendation: 'Add --no-cache to reduce image size',
  },
];

function findDockerfiles(dir) {
  const results = [];
  const names = ['Dockerfile', 'dockerfile', 'Dockerfile.dev', 'Dockerfile.prod',
                 'Dockerfile.staging', 'docker/Dockerfile', '.dockerfile'];

  // Check root
  for (const name of names) {
    const filePath = path.join(dir, name);
    if (fs.existsSync(filePath)) {
      results.push({ path: filePath, name });
    }
  }

  // Check for docker-compose
  for (const name of ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']) {
    const filePath = path.join(dir, name);
    if (fs.existsSync(filePath)) {
      results.push({ path: filePath, name, isCompose: true });
    }
  }

  return results;
}

async function runDockerScan(dir, config = {}) {
  const findings = [];
  const dockerfiles = findDockerfiles(dir);

  if (dockerfiles.length === 0) return findings;

  for (const { path: filePath, name, isCompose } of dockerfiles) {
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    if (isCompose) {
      // Docker Compose checks
      if (content.match(/privileged:\s*true/i)) {
        findings.push({
          type: 'docker-insecure',
          severity: 'critical',
          file: name,
          description: 'Container runs in privileged mode (full host access)',
          ecosystem: 'docker',
          recommendation: 'Remove privileged: true — it gives the container full host access',
        });
      }

      if (content.match(/network_mode:\s*["']?host/i)) {
        findings.push({
          type: 'docker-insecure',
          severity: 'high',
          file: name,
          description: 'Container uses host network mode (no network isolation)',
          ecosystem: 'docker',
          recommendation: 'Use bridge or overlay networks instead of host mode',
        });
      }

      if (content.match(/pid:\s*["']?host/i)) {
        findings.push({
          type: 'docker-insecure',
          severity: 'critical',
          file: name,
          description: 'Container shares host PID namespace',
          ecosystem: 'docker',
          recommendation: 'Remove pid: host — it allows the container to see/signal host processes',
        });
      }

      // Check for hardcoded secrets in compose
      const envMatches = content.match(/(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*[:=]\s*["']?[a-zA-Z0-9/+=]{8,}/gi);
      if (envMatches) {
        findings.push({
          type: 'docker-secret',
          severity: 'critical',
          file: name,
          description: 'Hardcoded secrets in docker-compose file',
          match: envMatches[0].substring(0, 60) + '...',
          ecosystem: 'docker',
          recommendation: 'Use .env files (gitignored) or Docker secrets instead of hardcoding',
        });
      }

      continue;
    }

    // Dockerfile checks
    const lines = content.split('\n');

    // Check FROM instructions
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const fromMatch = line.match(/^FROM\s+([^\s]+)/i);
      if (fromMatch) {
        const image = fromMatch[1];

        // Check for :latest or no tag
        if (image.match(/:latest$/i) || (!image.includes(':') && !image.includes('@'))) {
          const imageName = image.replace(/:latest$/i, '') + ':latest';
          const riskInfo = RISKY_IMAGES[imageName];
          findings.push({
            type: 'docker-unpinned',
            severity: riskInfo ? riskInfo.severity : 'high',
            file: name,
            line: i + 1,
            description: riskInfo ? riskInfo.reason : `Unpinned image tag: ${image}`,
            ecosystem: 'docker',
            recommendation: `Pin to a specific version (e.g., ${image.split(':')[0]}:20-alpine)`,
          });
        }

        // Check for digest pinning (good practice)
        if (image.includes('@sha256:')) {
          // This is good! No finding needed.
        }
      }
    }

    // Check if there's a USER instruction (should not run as root)
    const hasUserInstruction = lines.some(l => /^USER\s+(?!root)/im.test(l.trim()));
    const hasFromScratch = lines.some(l => /^FROM\s+scratch/i.test(l.trim()));
    if (!hasUserInstruction && !hasFromScratch) {
      findings.push({
        type: 'docker-root',
        severity: 'high',
        file: name,
        description: 'No non-root USER instruction — container will run as root',
        ecosystem: 'docker',
        recommendation: 'Add USER instruction with a non-root user before CMD/ENTRYPOINT',
      });
    }

    // Apply pattern rules
    for (const rule of DOCKERFILE_RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(content)) {
        // Find line number
        const lineIdx = lines.findIndex(l => rule.pattern.test(l));
        findings.push({
          type: 'docker-insecure',
          severity: rule.severity,
          file: name,
          line: lineIdx + 1,
          description: rule.description,
          ecosystem: 'docker',
          recommendation: rule.recommendation,
        });
      }
    }

    // Check for COPY/ADD of sensitive files
    const sensitivePatterns = [
      { pattern: /(?:COPY|ADD)\s+.*\.env\b/i, desc: '.env file copied into image' },
      { pattern: /(?:COPY|ADD)\s+.*\.npmrc\b/i, desc: '.npmrc copied into image (may contain tokens)' },
      { pattern: /(?:COPY|ADD)\s+.*id_rsa/i, desc: 'SSH private key copied into image' },
      { pattern: /(?:COPY|ADD)\s+.*\.pem\b/i, desc: 'PEM file copied into image' },
      { pattern: /(?:COPY|ADD)\s+.*\.key\b/i, desc: 'Key file copied into image' },
      { pattern: /(?:COPY|ADD)\s+.*\.aws/i, desc: 'AWS credentials directory copied into image' },
    ];

    for (const sp of sensitivePatterns) {
      if (sp.pattern.test(content)) {
        const lineIdx = lines.findIndex(l => sp.pattern.test(l));
        findings.push({
          type: 'docker-secret',
          severity: 'critical',
          file: name,
          line: lineIdx + 1,
          description: sp.desc,
          ecosystem: 'docker',
          recommendation: 'Never copy secrets into Docker images — use build secrets or runtime mounts',
        });
      }
    }
  }

  return findings;
}

module.exports = { runDockerScan };
