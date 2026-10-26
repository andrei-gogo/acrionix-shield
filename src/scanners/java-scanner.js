const fs = require('node:fs');
const path = require('node:path');
const { entryMatches } = require('../version-range');

// Known compromised Maven/Gradle packages
const COMPROMISED_JAVA = {
  'log4j-core': [
    { versions: ['2.0-beta9', '2.0-rc1', '2.0-rc2', '2.0', '2.0.1', '2.0.2', '2.1', '2.2', '2.3', '2.4', '2.4.1', '2.5', '2.6', '2.6.1', '2.6.2', '2.7', '2.8', '2.8.1', '2.8.2', '2.9.0', '2.9.1', '2.10.0', '2.11.0', '2.11.1', '2.11.2', '2.12.0', '2.12.1', '2.13.0', '2.13.1', '2.13.2', '2.13.3', '2.14.0', '2.14.1'],
      advisory: 'CVE-2021-44228 (Log4Shell)',
      description: 'Remote code execution via JNDI lookup injection — one of the most critical vulnerabilities ever discovered',
      severity: 'critical' },
    { versions: ['2.15.0'], advisory: 'CVE-2021-45046', description: 'Incomplete Log4Shell fix in certain configurations', severity: 'critical' },
    { versions: ['2.16.0'], advisory: 'CVE-2021-45105', description: 'Denial of service via recursive lookup in certain configurations', severity: 'high' },
  ],
  'commons-collections': [
    { below: '3.2.2',
      advisory: 'CVE-2015-6420',
      description: 'Deserialization vulnerability enabling remote code execution',
      severity: 'critical' },
  ],
  'spring-webmvc': [
    { atLeast: '5.2.0', below: '5.2.20', advisory: 'CVE-2022-22965 (Spring4Shell)', description: 'Potential RCE via data binding; exploit requires JDK 9+, WAR deployment and a vulnerable servlet container', severity: 'high' },
    { atLeast: '5.3.0', below: '5.3.18', advisory: 'CVE-2022-22965 (Spring4Shell)', description: 'Potential RCE via data binding; exploit requires JDK 9+, WAR deployment and a vulnerable servlet container', severity: 'high' },
  ],
  'spring-webflux': [
    { atLeast: '5.2.0', below: '5.2.20', advisory: 'CVE-2022-22965 (Spring4Shell)', description: 'Potential RCE via data binding; exploit requires JDK 9+, WAR deployment and a vulnerable servlet container', severity: 'high' },
    { atLeast: '5.3.0', below: '5.3.18', advisory: 'CVE-2022-22965 (Spring4Shell)', description: 'Potential RCE via data binding; exploit requires JDK 9+, WAR deployment and a vulnerable servlet container', severity: 'high' },
  ],
  'jackson-databind': [
    { below: '2.6.7.1', advisory: 'CVE-2017-7525', description: 'Unsafe polymorphic deserialization when default typing is enabled', severity: 'critical' },
    { atLeast: '2.7.0', below: '2.7.9.1', advisory: 'CVE-2017-7525', description: 'Unsafe polymorphic deserialization when default typing is enabled', severity: 'critical' },
    { atLeast: '2.8.0', below: '2.8.9', advisory: 'CVE-2017-7525', description: 'Unsafe polymorphic deserialization when default typing is enabled', severity: 'critical' },
  ],
  'struts2-core': [
    { atLeast: '2.3.5', below: '2.3.32',
      advisory: 'CVE-2017-5638',
      description: 'Remote code execution via Content-Type header (Equifax breach vector)',
      severity: 'critical' },
    { atLeast: '2.5.0', below: '2.5.10.1',
      advisory: 'CVE-2017-5638',
      description: 'Remote code execution via Content-Type header (Equifax breach vector)',
      severity: 'critical' },
  ],
  'fastjson': [
    { below: '1.2.25',
      advisory: 'CVE-2017-18349',
      description: 'Remote code execution when parsing crafted untrusted JSON',
      severity: 'critical' },
    { atLeast: '1.2.25', below: '1.2.68',
      advisory: 'CVE-2022-25845',
      description: 'Unsafe deserialization when parsing untrusted JSON',
      severity: 'high' },
    { atLeast: '1.2.68', below: '1.2.84',
      advisory: 'CVE-2026-16723',
      description: 'Remote code execution when parsing untrusted JSON; fixed in 1.2.84',
      severity: 'critical' },
  ],
};

const ADVISORY_GROUPS = {
  'log4j-core': 'org.apache.logging.log4j',
  'commons-collections': 'commons-collections',
  'spring-webmvc': 'org.springframework',
  'spring-webflux': 'org.springframework',
  'jackson-databind': 'com.fasterxml.jackson.core',
  'struts2-core': 'org.apache.struts',
  fastjson: 'com.alibaba',
};

function parsePomXml(dir) {
  const deps = [];
  const pomPath = path.join(dir, 'pom.xml');
  if (!fs.existsSync(pomPath)) return deps;

  const content = fs.readFileSync(pomPath, 'utf8');

  // Extract dependencies using regex (no XML parser needed)
  const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
  let match;
  while ((match = depRegex.exec(content))) {
    const name = match[2];
    deps.push({
      name,
      groupId: match[1],
      version: match[3] || '*',
      source: 'pom.xml',
    });
  }

  return deps;
}

function parseBuildGradle(dir) {
  const deps = [];

  for (const filename of ['build.gradle', 'build.gradle.kts']) {
    const filePath = path.join(dir, filename);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');

    // Match: implementation 'group:artifact:version'
    const singleQuote = /(?:implementation|api|compile|runtimeOnly|testImplementation)\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]/g;
    let match;
    while ((match = singleQuote.exec(content))) {
      deps.push({
        name: match[2],
        groupId: match[1],
        version: match[3],
        source: filename,
      });
    }

    // Match: implementation("group:artifact:version")
    const parenStyle = /(?:implementation|api|compile|runtimeOnly|testImplementation)\(["']([^:'"]+):([^:'"]+):([^'"]+)["']\)/g;
    while ((match = parenStyle.exec(content))) {
      deps.push({
        name: match[2],
        groupId: match[1],
        version: match[3],
        source: filename,
      });
    }
  }

  return deps;
}

async function runJavaScan(dir, config = {}) {
  const findings = [];

  const pomDeps = parsePomXml(dir);
  const gradleDeps = parseBuildGradle(dir);
  const allDeps = [...pomDeps, ...gradleDeps];

  if (allDeps.length === 0) return findings;

  for (const info of allDeps) {
    const name = info.name;
    if (info.groupId !== ADVISORY_GROUPS[name]) continue;
    const compromised = COMPROMISED_JAVA[name];
    if (compromised) {
      for (const entry of compromised) {
        if (entryMatches(info.version, entry) === true) {
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
