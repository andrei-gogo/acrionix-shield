const fs = require('node:fs');
const path = require('node:path');

// Known compromised Maven/Gradle packages
const COMPROMISED_JAVA = {
  'log4j-core': [
    { versions: ['2.0-beta9', '2.0-rc1', '2.0-rc2', '2.0', '2.0.1', '2.0.2', '2.1', '2.2', '2.3', '2.4', '2.4.1', '2.5', '2.6', '2.6.1', '2.6.2', '2.7', '2.8', '2.8.1', '2.8.2', '2.9.0', '2.9.1', '2.10.0', '2.11.0', '2.11.1', '2.11.2', '2.12.0', '2.12.1', '2.13.0', '2.13.1', '2.13.2', '2.13.3', '2.14.0', '2.14.1', '2.15.0', '2.16.0'],
      advisory: 'CVE-2021-44228 (Log4Shell)',
      description: 'Remote code execution via JNDI lookup injection — one of the most critical vulnerabilities ever discovered',
      severity: 'critical' },
  ],
  'commons-collections': [
    { versions: ['3.0', '3.1', '3.2', '3.2.1'],
      advisory: 'CVE-2015-6420',
      description: 'Deserialization vulnerability enabling remote code execution',
      severity: 'critical' },
  ],
  'spring-core': [
    { versions: ['5.3.0', '5.3.1', '5.3.2', '5.3.3', '5.3.4', '5.3.5', '5.3.6', '5.3.7', '5.3.8', '5.3.9', '5.3.10', '5.3.11', '5.3.12', '5.3.13', '5.3.14', '5.3.15', '5.3.16', '5.3.17'],
      advisory: 'CVE-2022-22965 (Spring4Shell)',
      description: 'Remote code execution via data binding on JDK 9+',
      severity: 'critical' },
  ],
  'jackson-databind': [
    { versions: ['2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.7.0', '2.7.1', '2.7.2', '2.7.3', '2.7.4', '2.7.5', '2.7.6', '2.7.7', '2.7.8', '2.7.9', '2.8.0', '2.8.1', '2.8.2', '2.8.3', '2.8.4', '2.8.5', '2.8.6', '2.8.7', '2.8.8', '2.8.9', '2.8.10', '2.8.11', '2.9.0', '2.9.1', '2.9.2', '2.9.3', '2.9.4', '2.9.5', '2.9.6', '2.9.7', '2.9.8', '2.9.9'],
      advisory: 'CVE-2017-7525',
      description: 'Deserialization vulnerability — multiple CVEs across versions',
      severity: 'high' },
  ],
  'struts2-core': [
    { versions: ['2.0.0', '2.0.1', '2.0.2', '2.0.3', '2.0.4', '2.0.5', '2.0.6', '2.0.8', '2.0.9', '2.0.11', '2.0.12', '2.0.14', '2.1.2', '2.1.6', '2.1.8', '2.2.1', '2.2.3', '2.3.1', '2.3.4', '2.3.7', '2.3.8', '2.3.12', '2.3.14', '2.3.16', '2.3.20', '2.3.24', '2.3.28', '2.3.30', '2.3.31', '2.3.32', '2.5.0', '2.5.1', '2.5.2', '2.5.5', '2.5.10'],
      advisory: 'CVE-2017-5638',
      description: 'Remote code execution via Content-Type header (Equifax breach vector)',
      severity: 'critical' },
  ],
  'fastjson': [
    { versions: ['*'],
      advisory: 'Multiple CVEs',
      description: 'Alibaba fastjson — multiple deserialization RCE vulnerabilities across all versions',
      severity: 'high' },
  ],
};

function parsePomXml(dir) {
  const deps = {};
  const pomPath = path.join(dir, 'pom.xml');
  if (!fs.existsSync(pomPath)) return deps;

  const content = fs.readFileSync(pomPath, 'utf8');

  // Extract dependencies using regex (no XML parser needed)
  const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
  let match;
  while ((match = depRegex.exec(content))) {
    const name = match[2];
    deps[name] = {
      groupId: match[1],
      version: match[3] || '*',
      source: 'pom.xml',
    };
  }

  return deps;
}

function parseBuildGradle(dir) {
  const deps = {};

  for (const filename of ['build.gradle', 'build.gradle.kts']) {
    const filePath = path.join(dir, filename);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');

    // Match: implementation 'group:artifact:version'
    const singleQuote = /(?:implementation|api|compile|runtimeOnly|testImplementation)\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]/g;
    let match;
    while ((match = singleQuote.exec(content))) {
      deps[match[2]] = {
        groupId: match[1],
        version: match[3],
        source: filename,
      };
    }

    // Match: implementation("group:artifact:version")
    const parenStyle = /(?:implementation|api|compile|runtimeOnly|testImplementation)\(["']([^:'"]+):([^:'"]+):([^'"]+)["']\)/g;
    while ((match = parenStyle.exec(content))) {
      deps[match[2]] = {
        groupId: match[1],
        version: match[3],
        source: filename,
      };
    }
  }

  return deps;
}

function versionInRange(version, targetVersions) {
  if (targetVersions.includes('*')) return true;
  return targetVersions.includes(version);
}

async function runJavaScan(dir, config = {}) {
  const findings = [];

  const pomDeps = parsePomXml(dir);
  const gradleDeps = parseBuildGradle(dir);
  const allDeps = { ...pomDeps, ...gradleDeps };

  if (Object.keys(allDeps).length === 0) return findings;

  for (const [name, info] of Object.entries(allDeps)) {
    const compromised = COMPROMISED_JAVA[name];
    if (compromised) {
      for (const entry of compromised) {
        if (versionInRange(info.version, entry.versions)) {
          findings.push({
            type: 'compromised-java',
            severity: entry.severity,
            file: info.source,
            package: `${info.groupId}:${name}`,
            version: info.version,
            description: entry.description,
            advisory: entry.advisory,
            ecosystem: 'java',
            recommendation: `URGENT: Update ${name} to a patched version immediately`,
          });
        }
      }
    }
  }

  // Check for HTTP repositories in pom.xml
  const pomPath = path.join(dir, 'pom.xml');
  if (fs.existsSync(pomPath)) {
    const content = fs.readFileSync(pomPath, 'utf8');
    if (content.match(/<url>\s*http:\/\//)) {
      findings.push({
        type: 'insecure-repo',
        severity: 'high',
        file: 'pom.xml',
        description: 'Maven repository uses HTTP instead of HTTPS',
        ecosystem: 'java',
        recommendation: 'Use HTTPS for all Maven repository URLs to prevent MITM attacks',
      });
    }
  }

  // Check for HTTP in Gradle
  for (const filename of ['build.gradle', 'build.gradle.kts']) {
    const filePath = path.join(dir, filename);
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      if (content.match(/url\s*[=(]\s*["']http:\/\//)) {
        findings.push({
          type: 'insecure-repo',
          severity: 'high',
          file: filename,
          description: 'Gradle repository uses HTTP instead of HTTPS',
          ecosystem: 'java',
          recommendation: 'Use HTTPS for all repository URLs',
        });
      }
    }
  }

  return findings;
}

module.exports = { runJavaScan };
