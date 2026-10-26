const fs = require('node:fs');
const path = require('node:path');
const { entryMatches } = require('../version-range');

// Known vulnerable NuGet packages
const COMPROMISED_NUGET = {
  'log4net': [
    { below: '2.0.10',
      advisory: 'CVE-2018-1285',
      description: 'XML external entity (XXE) vulnerability in log4net configuration',
      severity: 'high' },
  ],
  'Newtonsoft.Json': [
    { below: '13.0.1',
      advisory: 'CVE-2024-21907',
      description: 'Stack overflow on deeply nested JSON — denial of service',
      severity: 'high' },
  ],
  'System.Text.RegularExpressions': [
    { versions: ['4.3.0'],
      advisory: 'CVE-2019-0820',
      description: 'Regular expression denial of service (ReDoS)',
      severity: 'high' },
  ],
  'System.Net.Http': [
    { below: '4.3.4',
      advisory: 'CVE-2018-8292',
      description: 'Information disclosure — credentials sent to wrong host on redirect',
      severity: 'high' },
  ],
  'Microsoft.Data.OData': [
    { below: '5.8.4',
      advisory: 'CVE-2018-8269',
      description: 'Denial of service via crafted OData request',
      severity: 'high' },
  ],
};

function parseCsproj(dir) {
  const deps = [];

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
      deps.push({ name: match[1], version: match[2], source: relativePath });
    }

    // Match split-attribute style
    const splitRegex = /<PackageReference\s+Include=["']([^"']+)["'][^>]*>\s*<Version>([^<]+)<\/Version>/g;
    while ((match = splitRegex.exec(content))) {
      deps.push({ name: match[1], version: match[2], source: relativePath });
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
      deps.push({ name: match[1], version: match[2], source: 'packages.config' });
    }
  }

  return deps;
}

async function runDotnetScan(dir, config = {}) {
  const findings = [];

  const deps = parseCsproj(dir);

  if (deps.length === 0) return findings;

  for (const info of deps) {
    const name = info.name;
    const compromised = COMPROMISED_NUGET[Object.keys(COMPROMISED_NUGET).find(key => key.toLowerCase() === name.toLowerCase())];
    if (compromised) {
      for (const entry of compromised) {
        if (entryMatches(info.version, entry) === true) {
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
