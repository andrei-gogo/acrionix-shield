const fs = require('node:fs');
const path = require('node:path');

// Known vulnerable NuGet packages
const COMPROMISED_NUGET = {
  'log4net': [
    { versions: ['2.0.8', '2.0.9', '2.0.10', '2.0.11', '2.0.12'],
      advisory: 'CVE-2018-1285',
      description: 'XML external entity (XXE) vulnerability in log4net configuration',
      severity: 'high' },
  ],
  'Newtonsoft.Json': [
    { versions: ['6.0.1', '6.0.2', '6.0.3', '6.0.4', '6.0.5', '6.0.6', '6.0.7', '6.0.8', '7.0.1', '8.0.1', '8.0.2', '8.0.3', '9.0.1', '10.0.1', '10.0.2', '10.0.3', '11.0.1'],
      advisory: 'CVE-2024-21907',
      description: 'Stack overflow on deeply nested JSON — denial of service',
      severity: 'high' },
  ],
  'System.Text.RegularExpressions': [
    { versions: ['4.3.0'],
      advisory: 'CVE-2019-0980',
      description: 'Regular expression denial of service (ReDoS)',
      severity: 'high' },
  ],
  'Microsoft.AspNetCore.Authentication.JwtBearer': [
    { versions: ['2.0.0', '2.0.1', '2.0.2', '2.0.3', '2.1.0', '2.1.1', '2.1.2'],
      advisory: 'CVE-2024-21319',
      description: 'Denial of service via crafted JWT tokens',
      severity: 'high' },
  ],
  'System.Net.Http': [
    { versions: ['4.1.0', '4.1.1', '4.3.0', '4.3.1', '4.3.2', '4.3.3'],
      advisory: 'CVE-2018-8292',
      description: 'Information disclosure — credentials sent to wrong host on redirect',
      severity: 'high' },
  ],
  'Microsoft.Data.OData': [
    { versions: ['5.2.0', '5.6.0', '5.6.2', '5.6.3', '5.6.4', '5.7.0', '5.8.0', '5.8.1', '5.8.2', '5.8.3', '5.8.4'],
      advisory: 'CVE-2018-8269',
      description: 'Denial of service via crafted OData request',
      severity: 'high' },
  ],
};

function parseCsproj(dir) {
  const deps = {};

  // Find all .csproj files
  function findCsproj(searchDir, depth = 0) {
    if (depth > 3) return;
    let entries;
    try { entries = fs.readdirSync(searchDir, { withFileTypes: true }); } catch { return; }

    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'bin' || entry.name === 'obj') continue;
      const fullPath = path.join(searchDir, entry.name);
      if (entry.isDirectory()) {
        findCsproj(fullPath, depth + 1);
      } else if (entry.name.endsWith('.csproj') || entry.name.endsWith('.fsproj') || entry.name.endsWith('.vbproj')) {
        parseCsprojFile(fullPath, deps);
      }
    }
  }

  function parseCsprojFile(filePath, deps) {
    const content = fs.readFileSync(filePath, 'utf8');
    const relativePath = path.relative(dir, filePath);

    // Match PackageReference elements
    const pkgRefRegex = /<PackageReference\s+Include=["']([^"']+)["']\s+Version=["']([^"']+)["']/g;
    let match;
    while ((match = pkgRefRegex.exec(content))) {
      deps[match[1]] = { version: match[2], source: relativePath };
    }

    // Match split-attribute style
    const splitRegex = /<PackageReference\s+Include=["']([^"']+)["'][^>]*>\s*<Version>([^<]+)<\/Version>/g;
    while ((match = splitRegex.exec(content))) {
      deps[match[1]] = { version: match[2], source: relativePath };
    }
  }

  findCsproj(dir);

  // Also check packages.config (older .NET)
  const pkgConfigPath = path.join(dir, 'packages.config');
  if (fs.existsSync(pkgConfigPath)) {
    const content = fs.readFileSync(pkgConfigPath, 'utf8');
    const pkgRegex = /<package\s+id=["']([^"']+)["']\s+version=["']([^"']+)["']/g;
    let match;
    while ((match = pkgRegex.exec(content))) {
      deps[match[1]] = { version: match[2], source: 'packages.config' };
    }
  }

  return deps;
}

function versionMatch(version, targets) {
  if (targets.includes('*')) return true;
  return targets.includes(version);
}

async function runDotnetScan(dir, config = {}) {
  const findings = [];

  const deps = parseCsproj(dir);

  if (Object.keys(deps).length === 0) return findings;

  for (const [name, info] of Object.entries(deps)) {
    const compromised = COMPROMISED_NUGET[name];
    if (compromised) {
      for (const entry of compromised) {
        if (versionMatch(info.version, entry.versions)) {
          findings.push({
            type: 'compromised-nuget',
            severity: entry.severity,
            file: info.source,
            package: name,
            version: info.version,
            description: entry.description,
            advisory: entry.advisory,
            ecosystem: 'dotnet',
            recommendation: `Update ${name} to the latest patched version`,
          });
        }
      }
    }
  }

  // Check for insecure NuGet sources
  const nugetConfigPath = path.join(dir, 'nuget.config') || path.join(dir, 'NuGet.Config');
  for (const configName of ['nuget.config', 'NuGet.Config', 'NuGet.config']) {
    const configPath = path.join(dir, configName);
    if (fs.existsSync(configPath)) {
      const content = fs.readFileSync(configPath, 'utf8');
      if (content.match(/value=["']http:\/\//)) {
        findings.push({
          type: 'insecure-source',
          severity: 'high',
          file: configName,
          description: 'NuGet package source uses HTTP instead of HTTPS',
          ecosystem: 'dotnet',
          recommendation: 'Use HTTPS for all NuGet package sources',
        });
      }
    }
  }

  return findings;
}

module.exports = { runDotnetScan };
