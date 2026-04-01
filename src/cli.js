#!/usr/bin/env node

const { parseArgs } = require('node:util');
const path = require('node:path');
const { runLeakScan } = require('./scanners/leak-scanner');
const { runSupplyChainScan } = require('./scanners/supply-chain-scanner');
const { runPythonScan } = require('./scanners/python-scanner');
const { runDockerScan } = require('./scanners/docker-scanner');
const { runGitScan } = require('./scanners/git-scanner');
const { runJavaScan } = require('./scanners/java-scanner');
const { runRubyScan } = require('./scanners/ruby-scanner');
const { runGoScan } = require('./scanners/go-scanner');
const { runDotnetScan } = require('./scanners/dotnet-scanner');
const { formatResults, severityColor } = require('./reporter');

const BANNER = `
  ╔══════════════════════════════════════╗
  ║       ACRIONIX SHIELD v1.0.0        ║
  ║   Pre-Publish Security Scanner      ║
  ╚══════════════════════════════════════╝
`;

const HELP = `
Usage: acrionix-shield <command> [options]

Commands:
  check           Run all security checks (all scanners)
  scan-leaks      Scan for source code leaks only
  scan-deps       Scan dependencies for supply chain attacks only
  scan-python     Scan Python dependencies (requirements.txt, Pipfile, poetry)
  scan-java       Scan Java dependencies (pom.xml, build.gradle)
  scan-dotnet     Scan .NET/C# dependencies (.csproj, packages.config)
  scan-ruby       Scan Ruby dependencies (Gemfile, Gemfile.lock)
  scan-go         Scan Go dependencies (go.mod, go.sum)
  scan-docker     Scan Dockerfiles and docker-compose for security issues
  scan-git        Scan git history for leaked secrets

Options:
  --dir, -d       Target directory (default: current directory)
  --ci            Exit with code 1 on any finding (for CI pipelines)
  --json          Output results as JSON
  --config, -c    Path to config file (.shieldrc.json)
  --severity, -s  Minimum severity to report: low, medium, high, critical (default: low)
  --help, -h      Show this help message
  --version, -v   Show version

Examples:
  npx acrionix-shield check
  npx acrionix-shield check --ci --severity high
  npx acrionix-shield scan-leaks --dir ./dist
  npx acrionix-shield scan-deps --json
`;

function parseCliArgs() {
  const args = process.argv.slice(2);
  const command = args[0] && !args[0].startsWith('-') ? args[0] : 'check';
  const rest = command === args[0] ? args.slice(1) : args;

  if (args.includes('--help') || args.includes('-h')) {
    console.log(BANNER);
    console.log(HELP);
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    const pkg = require('../package.json');
    console.log(pkg.version);
    process.exit(0);
  }

  const options = {
    command,
    dir: process.cwd(),
    ci: false,
    json: false,
    config: null,
    severity: 'low',
  };

  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg === '--dir' || arg === '-d') options.dir = rest[++i];
    else if (arg === '--ci') options.ci = true;
    else if (arg === '--json') options.json = true;
    else if (arg === '--config' || arg === '-c') options.config = rest[++i];
    else if (arg === '--severity' || arg === '-s') options.severity = rest[++i];
  }

  options.dir = path.resolve(options.dir);
  return options;
}

function loadConfig(options) {
  const defaults = {
    ignorePatterns: [],
    customCloudPatterns: [],
    customSensitivePatterns: [],
    knownCompromised: {},
  };

  if (options.config) {
    try {
      const configPath = path.resolve(options.config);
      const userConfig = require(configPath);
      return { ...defaults, ...userConfig };
    } catch (err) {
      console.error(`Warning: Could not load config file: ${options.config}`);
    }
  }

  // Try to load .shieldrc.json from target dir
  try {
    const configPath = path.join(options.dir, '.shieldrc.json');
    const userConfig = require(configPath);
    return { ...defaults, ...userConfig };
  } catch {
    // No config file, use defaults
  }

  return defaults;
}

async function main() {
  const options = parseCliArgs();
  const config = loadConfig(options);

  if (!options.json) {
    console.log(BANNER);
  }

  const results = { leaks: [], supplyChain: [], python: [], java: [], dotnet: [], ruby: [], go: [], docker: [], git: [] };
  const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 };
  const minSeverity = severityOrder[options.severity] || 0;

  const scanAll = options.command === 'check';
  const totalSteps = scanAll ? 9 : 1;
  let step = 0;

  try {
    if (scanAll || options.command === 'scan-leaks') {
      if (!options.json) console.log(`  [${++step}/${totalSteps}] Scanning for source leaks...\n`);
      results.leaks = await runLeakScan(options.dir, config);
    }

    if (scanAll || options.command === 'scan-deps') {
      if (!options.json) console.log(`  [${++step}/${totalSteps}] Scanning npm dependencies...\n`);
      results.supplyChain = await runSupplyChainScan(options.dir, config);
    }

    if (scanAll || options.command === 'scan-python') {
      if (!options.json) console.log(`  [${++step}/${totalSteps}] Scanning Python dependencies...\n`);
      results.python = await runPythonScan(options.dir, config);
    }

    if (scanAll || options.command === 'scan-java') {
      if (!options.json) console.log(`  [${++step}/${totalSteps}] Scanning Java/Maven/Gradle dependencies...\n`);
      results.java = await runJavaScan(options.dir, config);
    }

    if (scanAll || options.command === 'scan-dotnet') {
      if (!options.json) console.log(`  [${++step}/${totalSteps}] Scanning .NET/C# dependencies...\n`);
      results.dotnet = await runDotnetScan(options.dir, config);
    }

    if (scanAll || options.command === 'scan-ruby') {
      if (!options.json) console.log(`  [${++step}/${totalSteps}] Scanning Ruby dependencies...\n`);
      results.ruby = await runRubyScan(options.dir, config);
    }

    if (scanAll || options.command === 'scan-go') {
      if (!options.json) console.log(`  [${++step}/${totalSteps}] Scanning Go modules...\n`);
      results.go = await runGoScan(options.dir, config);
    }

    if (scanAll || options.command === 'scan-docker') {
      if (!options.json) console.log(`  [${++step}/${totalSteps}] Scanning Docker configuration...\n`);
      results.docker = await runDockerScan(options.dir, config);
    }

    if (scanAll || options.command === 'scan-git') {
      if (!options.json) console.log(`  [${++step}/${totalSteps}] Scanning git history for secrets...\n`);
      results.git = await runGitScan(options.dir, config);
    }
  } catch (err) {
    console.error(`Error during scan: ${err.message}`);
    process.exit(2);
  }

  // Filter by severity
  for (const key of Object.keys(results)) {
    results[key] = results[key].filter(r => severityOrder[r.severity] >= minSeverity);
  }

  const totalFindings = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);

  if (options.json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    formatResults(results);

    if (totalFindings === 0) {
      console.log('  ✅ No security issues found. Safe to publish!\n');
    } else {
      console.log(`  ⚠️  Found ${totalFindings} issue(s). Review before publishing.\n`);
    }
  }

  if (options.ci && totalFindings > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(2);
});
