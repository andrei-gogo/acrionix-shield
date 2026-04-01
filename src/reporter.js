const SEVERITY_COLORS = {
  critical: '\x1b[41m\x1b[37m',  // White on red bg
  high: '\x1b[31m',               // Red
  medium: '\x1b[33m',             // Yellow
  low: '\x1b[36m',                // Cyan
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

const SEVERITY_ICONS = {
  critical: '🚨',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
};

function severityColor(severity) {
  return SEVERITY_COLORS[severity] || '';
}

function severityBadge(severity) {
  const icon = SEVERITY_ICONS[severity] || '⚪';
  const color = SEVERITY_COLORS[severity] || '';
  return `${icon} ${color}${severity.toUpperCase()}${RESET}`;
}

function printSection(title, findings) {
  if (findings.length === 0) return;

  console.log(`  ${BOLD}━━━ ${title} ━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n`);

  const grouped = groupBySeverity(findings);

  for (const severity of ['critical', 'high', 'medium', 'low']) {
    const items = grouped[severity];
    if (!items || items.length === 0) continue;

    console.log(`  ${severityBadge(severity)} ${BOLD}(${items.length} finding${items.length > 1 ? 's' : ''})${RESET}`);

    for (const finding of items) {
      const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
      console.log(`    ${DIM}├─${RESET} ${finding.description}`);
      console.log(`    ${DIM}│  ${RESET} File: ${BOLD}${location}${RESET}`);
      if (finding.package) {
        console.log(`    ${DIM}│  ${RESET} Package: ${BOLD}${finding.package}@${finding.version}${RESET}`);
      }
      if (finding.advisory) {
        console.log(`    ${DIM}│  ${RESET} Advisory: ${finding.advisory}`);
      }
      if (finding.match) {
        const sanitized = finding.match.replace(/[\n\r]/g, '\\n');
        console.log(`    ${DIM}│  ${RESET} Match: ${DIM}${sanitized}${RESET}`);
      }
      if (finding.count && finding.count > 1) {
        console.log(`    ${DIM}│  ${RESET} Occurrences: ${finding.count}`);
      }
      if (finding.resolved) {
        console.log(`    ${DIM}│  ${RESET} Registry: ${DIM}${finding.resolved}${RESET}`);
      }
      if (finding.packages) {
        console.log(`    ${DIM}│  ${RESET} Packages: ${finding.packages.join(', ')}${finding.packages.length >= 10 ? '...' : ''}`);
      }
      if (finding.ecosystem) {
        console.log(`    ${DIM}│  ${RESET} Ecosystem: ${finding.ecosystem}`);
      }
      console.log(`    ${DIM}│  ${RESET} Fix: ${finding.recommendation}`);
      console.log(`    ${DIM}│${RESET}`);
    }
    console.log('');
  }
}

function formatResults(results) {
  printSection('SOURCE LEAK SCAN', results.leaks || []);
  printSection('NPM SUPPLY CHAIN', results.supplyChain || []);
  printSection('PYTHON DEPENDENCIES', results.python || []);
  printSection('JAVA / MAVEN / GRADLE', results.java || []);
  printSection('.NET / NUGET', results.dotnet || []);
  printSection('RUBY / GEMS', results.ruby || []);
  printSection('GO MODULES', results.go || []);
  printSection('DOCKER SECURITY', results.docker || []);
  printSection('GIT SECRETS', results.git || []);
}

function groupBySeverity(findings) {
  const groups = {};
  for (const f of findings) {
    if (!groups[f.severity]) groups[f.severity] = [];
    groups[f.severity].push(f);
  }
  return groups;
}

module.exports = { formatResults, severityColor };
