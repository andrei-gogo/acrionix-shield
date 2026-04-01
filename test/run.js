const fs = require('node:fs');
const path = require('node:path');
const { runLeakScan } = require('../src/scanners/leak-scanner');
const { runSupplyChainScan } = require('../src/scanners/supply-chain-scanner');
const { runPythonScan } = require('../src/scanners/python-scanner');
const { runDockerScan } = require('../src/scanners/docker-scanner');
const { runGitScan } = require('../src/scanners/git-scanner');
const { runJavaScan } = require('../src/scanners/java-scanner');
const { runRubyScan } = require('../src/scanners/ruby-scanner');
const { runGoScan } = require('../src/scanners/go-scanner');
const { runDotnetScan } = require('../src/scanners/dotnet-scanner');

const FIXTURE_DIR = path.join(__dirname, 'fixtures');
let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  \x1b[32m✅ ${message}\x1b[0m`);
    passed++;
  } else {
    console.log(`  \x1b[31m❌ ${message}\x1b[0m`);
    failed++;
  }
}

function mkdirp(p) {
  fs.mkdirSync(p, { recursive: true });
}

function writeFixture(relativePath, content) {
  const fullPath = path.join(FIXTURE_DIR, relativePath);
  mkdirp(path.dirname(fullPath));
  fs.writeFileSync(fullPath, content);
}

async function setup() {
  // ===== Leak test fixtures =====
  writeFixture('leak-test/bundle.js.map', '{"version":3,"sources":["../src/index.ts"]}');
  writeFixture('leak-test/config.env', 'API_KEY=super_secret_123');
  writeFixture('leak-test/app.js',
    'const url = "https://my-bucket.r2.cloudflarestorage.com/internal/source.tar.gz";\n' +
    'const key = api_key = "sk-ant-abc123def456ghi789jkl012mno345pqr678stu901vwx234";\n' +
    'const home = "/Users/developer/projects/secret-project/src/index.ts";\n'
  );
  writeFixture('leak-test/package.json', '{"name":"test","version":"1.0.0"}');

  // ===== Clean project fixture =====
  writeFixture('clean-project/index.js', 'console.log("hello world");');
  writeFixture('clean-project/package.json', '{"name":"clean","version":"1.0.0","files":["index.js"]}');

  // ===== Supply chain test fixtures =====
  writeFixture('supply-chain-test/package.json', '{"name":"test","version":"1.0.0"}');
  writeFixture('supply-chain-test/package-lock.json', JSON.stringify({
    name: "test", version: "1.0.0", lockfileVersion: 3,
    packages: {
      "": { name: "test", version: "1.0.0" },
      "node_modules/axios": { version: "1.14.1", resolved: "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz", integrity: "sha512-fake" },
      "node_modules/plain-crypto-js": { version: "1.0.0", resolved: "https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-1.0.0.tgz", integrity: "sha512-fake" },
      "node_modules/express": { version: "4.18.2", resolved: "https://registry.npmjs.org/express/-/express-4.18.2.tgz", integrity: "sha512-real" },
      "node_modules/evil-pkg": { version: "1.0.0", resolved: "https://evil-registry.example.com/evil-pkg-1.0.0.tgz" },
    },
  }, null, 2));

  // ===== Python test fixtures =====
  writeFixture('python-test/requirements.txt',
    '# Production deps\n' +
    'flask==2.3.1\n' +
    'requessts==1.0.0\n' +
    'ctx==0.2.6\n' +
    'boto3\n' +
    'pandas\n' +
    'numpy\n' +
    'django\n' +
    'celery\n' +
    'redis\n' +
    'gunicorn\n'
  );

  writeFixture('python-clean/requirements.txt',
    'flask==2.3.1\n' +
    'requests==2.31.0\n' +
    'django==4.2.7\n'
  );

  // ===== Docker test fixtures =====
  writeFixture('docker-test/Dockerfile',
    'FROM node:latest\n' +
    'WORKDIR /app\n' +
    'COPY . .\n' +
    'COPY .env /app/.env\n' +
    'ENV API_KEY=sk-live-1234567890abcdef\n' +
    'EXPOSE 22\n' +
    'RUN curl -k https://example.com/install.sh | bash\n' +
    'CMD ["node", "server.js"]\n'
  );

  writeFixture('docker-test/docker-compose.yml',
    'version: "3"\n' +
    'services:\n' +
    '  app:\n' +
    '    build: .\n' +
    '    privileged: true\n' +
    '    network_mode: host\n' +
    '    environment:\n' +
    '      - PASSWORD=supersecret123456\n'
  );

  writeFixture('docker-clean/Dockerfile',
    'FROM node:20-alpine\n' +
    'WORKDIR /app\n' +
    'COPY package*.json ./\n' +
    'RUN npm ci --only=production\n' +
    'COPY src/ src/\n' +
    'USER node\n' +
    'EXPOSE 3000\n' +
    'CMD ["node", "src/index.js"]\n'
  );

  // ===== Java test fixtures =====
  writeFixture('java-test/pom.xml',
    '<?xml version="1.0"?>\n<project>\n<dependencies>\n' +
    '  <dependency>\n    <groupId>org.apache.logging.log4j</groupId>\n    <artifactId>log4j-core</artifactId>\n    <version>2.14.1</version>\n  </dependency>\n' +
    '  <dependency>\n    <groupId>com.fasterxml.jackson.core</groupId>\n    <artifactId>jackson-databind</artifactId>\n    <version>2.9.8</version>\n  </dependency>\n' +
    '  <dependency>\n    <groupId>org.springframework</groupId>\n    <artifactId>spring-core</artifactId>\n    <version>5.3.17</version>\n  </dependency>\n' +
    '</dependencies>\n' +
    '<repositories><repository><url>http://insecure-repo.example.com</url></repository></repositories>\n' +
    '</project>'
  );

  writeFixture('java-clean/pom.xml',
    '<?xml version="1.0"?>\n<project>\n<dependencies>\n' +
    '  <dependency>\n    <groupId>org.apache.logging.log4j</groupId>\n    <artifactId>log4j-core</artifactId>\n    <version>2.21.0</version>\n  </dependency>\n' +
    '</dependencies></project>'
  );

  writeFixture('gradle-test/build.gradle',
    "plugins { id 'java' }\n" +
    "dependencies {\n" +
    "  implementation 'org.apache.logging.log4j:log4j-core:2.14.1'\n" +
    "  implementation 'org.apache.struts:struts2-core:2.5.10'\n" +
    "}\n"
  );

  // ===== Ruby test fixtures =====
  writeFixture('ruby-test/Gemfile',
    'source "http://rubygems.org"\n' +
    'gem "rails", "7.0.4"\n' +
    'gem "rest-client", "1.6.13"\n' +
    'gem "actionmailer-text"\n'
  );

  writeFixture('ruby-clean/Gemfile',
    'source "https://rubygems.org"\n' +
    'gem "rails", "7.1.2"\n' +
    'gem "puma", "6.4.0"\n'
  );

  // ===== Go test fixtures =====
  writeFixture('go-test/go.mod',
    'module example.com/myapp\n\ngo 1.21\n\n' +
    'require (\n' +
    '  github.com/dgrijalva/jwt-go v3.2.0\n' +
    '  golang.org/x/net v0.0.0-20220722155237-a158d28d115b\n' +
    '  golang.org/x/text v0.3.6\n' +
    ')\n\n' +
    'replace github.com/foo/bar => ../local-bar\n'
  );

  writeFixture('go-clean/go.mod',
    'module example.com/clean\n\ngo 1.21\n\n' +
    'require (\n' +
    '  github.com/google/uuid v1.4.0\n' +
    ')\n'
  );

  // ===== .NET test fixtures =====
  writeFixture('dotnet-test/MyApp.csproj',
    '<Project Sdk="Microsoft.NET.Sdk">\n' +
    '  <ItemGroup>\n' +
    '    <PackageReference Include="Newtonsoft.Json" Version="11.0.1" />\n' +
    '    <PackageReference Include="log4net" Version="2.0.12" />\n' +
    '    <PackageReference Include="System.Net.Http" Version="4.3.0" />\n' +
    '  </ItemGroup>\n' +
    '</Project>'
  );

  writeFixture('dotnet-clean/MyApp.csproj',
    '<Project Sdk="Microsoft.NET.Sdk">\n' +
    '  <ItemGroup>\n' +
    '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n' +
    '  </ItemGroup>\n' +
    '</Project>'
  );

  // ===== Git test fixtures (no actual git repo, just gitignore) =====
  writeFixture('git-test/.git/HEAD', 'ref: refs/heads/main');
  writeFixture('git-test/.env', 'SECRET=value');
  writeFixture('git-test/.gitignore', '# just node_modules\nnode_modules/\n');

  writeFixture('git-clean/.git/HEAD', 'ref: refs/heads/main');
  writeFixture('git-clean/.gitignore', 'node_modules/\n.env\n.env.*\n*.pem\n*.key\n');
}

function cleanup() {
  fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
}

// ===== TEST SUITES =====

async function testLeakScanner() {
  console.log('\n  \x1b[1m📂 Leak Scanner Tests\x1b[0m\n');

  const results = await runLeakScan(path.join(FIXTURE_DIR, 'leak-test'), {});

  assert(results.some(r => r.file === 'bundle.js.map'), 'Detects .map source map files');
  assert(results.some(r => r.file === 'bundle.js.map' && r.severity === 'critical'), 'Source maps rated as critical');
  assert(results.some(r => r.file === 'config.env'), 'Detects .env files');
  assert(results.some(r => r.description === 'Cloudflare R2 Storage URL'), 'Detects Cloudflare R2 storage URLs');
  assert(results.some(r => r.description === 'Anthropic API key'), 'Detects Anthropic API keys');
  assert(results.some(r => r.description === 'macOS user home path'), 'Detects internal macOS user paths');
  assert(results.some(r => r.type === 'config'), 'Warns when no .npmignore/files field');

  const cleanResults = await runLeakScan(path.join(FIXTURE_DIR, 'clean-project'), {});
  assert(cleanResults.length === 0, 'Clean project produces no findings');
}

async function testSupplyChainScanner() {
  console.log('\n  \x1b[1m📦 NPM Supply Chain Tests\x1b[0m\n');

  const results = await runSupplyChainScan(path.join(FIXTURE_DIR, 'supply-chain-test'), {});

  assert(results.some(r => r.package === 'axios'), 'Detects compromised axios@1.14.1');
  assert(results.some(r => r.package === 'axios' && r.severity === 'critical'), 'Compromised axios rated as critical');
  assert(results.some(r => r.package === 'plain-crypto-js'), 'Detects malicious plain-crypto-js');
  assert(results.some(r => r.type === 'suspicious-registry'), 'Detects non-standard registries');
  assert(results.some(r => r.package === 'evil-pkg'), 'Identifies suspicious package correctly');
  assert(!results.some(r => r.package === 'express'), 'Does not flag clean packages');
}

async function testPythonScanner() {
  console.log('\n  \x1b[1m🐍 Python Scanner Tests\x1b[0m\n');

  const results = await runPythonScan(path.join(FIXTURE_DIR, 'python-test'), {});

  assert(results.some(r => r.package === 'requessts'), 'Detects Python typosquat (requessts)');
  assert(results.some(r => r.package === 'requessts' && r.severity === 'critical'), 'Python typosquat rated as critical');
  assert(results.some(r => r.package === 'ctx'), 'Detects compromised PyPI package (ctx)');
  assert(results.some(r => r.type === 'unpinned-deps'), 'Warns about unpinned dependencies');

  const cleanResults = await runPythonScan(path.join(FIXTURE_DIR, 'python-clean'), {});
  assert(cleanResults.length === 0, 'Clean Python project produces no findings');

  const emptyResults = await runPythonScan(path.join(FIXTURE_DIR, 'clean-project'), {});
  assert(emptyResults.length === 0, 'Non-Python project produces no findings');
}

async function testDockerScanner() {
  console.log('\n  \x1b[1m🐳 Docker Scanner Tests\x1b[0m\n');

  const results = await runDockerScan(path.join(FIXTURE_DIR, 'docker-test'), {});

  assert(results.some(r => r.description && r.description.includes('latest')), 'Detects unpinned :latest image tag');
  assert(results.some(r => r.description && r.description.includes('root')), 'Detects missing non-root USER');
  assert(results.some(r => r.description && r.description.includes('.env')), 'Detects .env file copied into image');
  assert(results.some(r => r.description && r.description.includes('SSH port')), 'Detects exposed SSH port');
  assert(results.some(r => r.description && r.description.includes('curl -k')), 'Detects disabled SSL verification');
  assert(results.some(r => r.description && r.description.includes('Secret hardcoded')), 'Detects hardcoded ENV secrets');
  assert(results.some(r => r.description && r.description.includes('privileged')), 'Detects privileged mode in compose');
  assert(results.some(r => r.description && r.description.includes('host network')), 'Detects host network mode in compose');

  const cleanResults = await runDockerScan(path.join(FIXTURE_DIR, 'docker-clean'), {});
  assert(cleanResults.length === 0, 'Clean Dockerfile produces no findings');

  const emptyResults = await runDockerScan(path.join(FIXTURE_DIR, 'clean-project'), {});
  assert(emptyResults.length === 0, 'Non-Docker project produces no findings');
}

async function testJavaScanner() {
  console.log('\n  \x1b[1m☕ Java Scanner Tests\x1b[0m\n');

  const pomResults = await runJavaScan(path.join(FIXTURE_DIR, 'java-test'), {});
  assert(pomResults.some(r => r.package && r.package.includes('log4j-core')), 'Detects vulnerable Log4j (Log4Shell)');
  assert(pomResults.some(r => r.advisory && r.advisory.includes('Log4Shell')), 'Identifies Log4Shell CVE');
  assert(pomResults.some(r => r.package && r.package.includes('spring-core')), 'Detects vulnerable Spring (Spring4Shell)');
  assert(pomResults.some(r => r.type === 'insecure-repo'), 'Detects HTTP Maven repository');

  const gradleResults = await runJavaScan(path.join(FIXTURE_DIR, 'gradle-test'), {});
  assert(gradleResults.some(r => r.package && r.package.includes('log4j-core')), 'Detects Log4j in build.gradle');
  assert(gradleResults.some(r => r.package && r.package.includes('struts2-core')), 'Detects vulnerable Struts2');

  const cleanResults = await runJavaScan(path.join(FIXTURE_DIR, 'java-clean'), {});
  assert(cleanResults.length === 0, 'Clean Java project produces no findings');

  const emptyResults = await runJavaScan(path.join(FIXTURE_DIR, 'clean-project'), {});
  assert(emptyResults.length === 0, 'Non-Java project produces no findings');
}

async function testRubyScanner() {
  console.log('\n  \x1b[1m💎 Ruby Scanner Tests\x1b[0m\n');

  const results = await runRubyScan(path.join(FIXTURE_DIR, 'ruby-test'), {});
  assert(results.some(r => r.package === 'rest-client'), 'Detects compromised rest-client gem');
  assert(results.some(r => r.package === 'actionmailer-text' && r.type === 'typosquat'), 'Detects Ruby typosquat');
  assert(results.some(r => r.type === 'insecure-source'), 'Detects HTTP gem source');

  const cleanResults = await runRubyScan(path.join(FIXTURE_DIR, 'ruby-clean'), {});
  assert(cleanResults.length === 0, 'Clean Ruby project produces no findings');

  const emptyResults = await runRubyScan(path.join(FIXTURE_DIR, 'clean-project'), {});
  assert(emptyResults.length === 0, 'Non-Ruby project produces no findings');
}

async function testGoScanner() {
  console.log('\n  \x1b[1m🐹 Go Scanner Tests\x1b[0m\n');

  const results = await runGoScan(path.join(FIXTURE_DIR, 'go-test'), {});
  assert(results.some(r => r.package && r.package.includes('dgrijalva/jwt-go')), 'Detects deprecated jwt-go');
  assert(results.some(r => r.package && r.package.includes('golang.org/x/net')), 'Detects vulnerable golang.org/x/net');
  assert(results.some(r => r.package && r.package.includes('golang.org/x/text')), 'Detects vulnerable golang.org/x/text');
  assert(results.some(r => r.type === 'local-replace'), 'Detects local replace directive');

  const cleanResults = await runGoScan(path.join(FIXTURE_DIR, 'go-clean'), {});
  assert(cleanResults.length === 0, 'Clean Go project produces no findings');

  const emptyResults = await runGoScan(path.join(FIXTURE_DIR, 'clean-project'), {});
  assert(emptyResults.length === 0, 'Non-Go project produces no findings');
}

async function testDotnetScanner() {
  console.log('\n  \x1b[1m🔷 .NET Scanner Tests\x1b[0m\n');

  const results = await runDotnetScan(path.join(FIXTURE_DIR, 'dotnet-test'), {});
  assert(results.some(r => r.package === 'Newtonsoft.Json'), 'Detects vulnerable Newtonsoft.Json');
  assert(results.some(r => r.package === 'log4net'), 'Detects vulnerable log4net');
  assert(results.some(r => r.package === 'System.Net.Http'), 'Detects vulnerable System.Net.Http');

  const cleanResults = await runDotnetScan(path.join(FIXTURE_DIR, 'dotnet-clean'), {});
  assert(cleanResults.length === 0, 'Clean .NET project produces no findings');

  const emptyResults = await runDotnetScan(path.join(FIXTURE_DIR, 'clean-project'), {});
  assert(emptyResults.length === 0, 'Non-.NET project produces no findings');
}

async function testGitScanner() {
  console.log('\n  \x1b[1m🔐 Git Scanner Tests\x1b[0m\n');

  const results = await runGitScan(path.join(FIXTURE_DIR, 'git-test'), {});

  assert(results.some(r => r.type === 'not-gitignored' && r.file === '.env'), 'Detects .env not in .gitignore');

  const emptyResults = await runGitScan(path.join(FIXTURE_DIR, 'clean-project'), {});
  assert(emptyResults.length === 0, 'Non-git project produces no findings');
}

// ===== MAIN =====

async function main() {
  console.log('\n  ╔══════════════════════════════════════╗');
  console.log('  ║     ACRIONIX SHIELD — TEST SUITE     ║');
  console.log('  ╚══════════════════════════════════════╝');

  setup();

  try {
    await testLeakScanner();
    await testSupplyChainScanner();
    await testPythonScanner();
    await testDockerScanner();
    await testJavaScanner();
    await testRubyScanner();
    await testGoScanner();
    await testDotnetScanner();
    await testGitScanner();
  } finally {
    cleanup();
  }

  console.log(`\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log(`  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

  process.exit(failed > 0 ? 1 : 0);
}

main();
