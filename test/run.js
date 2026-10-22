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
const { runPhpScan } = require('../src/scanners/php-scanner');

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

  // ===== PHP test fixtures =====
  writeFixture('php-test/Dockerfile',
    'FROM php:8.3.30-fpm\n' +
    'USER www-data\n'
  );
  writeFixture('php-test/docker-compose.yml',
    'services:\n' +
    '  legacy:\n' +
    '    image: php:7.4-apache\n' +
    '  web:\n' +
    '    image: php:8.4-apache\n'
  );
  writeFixture('php-test/composer.json', JSON.stringify({
    require: { php: '^8.3', 'monolog/monolog': '^3.0' },
    config: { 'secure-http': false },
    repositories: [{ type: 'composer', url: 'http://packages.example.com' }],
  }));

  writeFixture('php-clean/Dockerfile',
    'FROM php:8.3.36-fpm\n' +
    'USER www-data\n'
  );
  writeFixture('php-clean/.php-version', '8.5.12\n');
  writeFixture('php-clean/composer.json', JSON.stringify({
    require: { php: '^8.3', 'monolog/monolog': '^3.0' },
    config: { platform: { php: '8.4.27' } },
  }));

  writeFixture('php-unpinned/Dockerfile', 'FROM php\nUSER www-data\n');

  // Regression cases from Codex review (CODEX_HANDOFF.md)
  writeFixture('php-other-image/Dockerfile', 'FROM phpmyadmin:5.2.1\nUSER www-data\n');
  writeFixture('php-prerelease/Dockerfile', 'FROM php:8.6.0RC3-cli\nUSER www-data\n');
  writeFixture('php-malformed/Dockerfile', 'FROM php:8.3.36garbage\nUSER www-data\n');
  writeFixture('php-platform-only/composer.json', JSON.stringify({ type: 'project', config: { platform: { php: '8.3.36' } } }));
  writeFixture('php-library/composer.json', JSON.stringify({ name: 'acme/lib', config: { platform: { php: '8.3.36' } } }));
  writeFixture('php-library/.php-version', '8.3.36\n');
  writeFixture('php-devpin-project/composer.json', JSON.stringify({ type: 'project' }));
  writeFixture('php-devpin-project/.php-version', '8.4.27\n');
  writeFixture('php-devpin-vulnerable/.tool-versions', 'php 8.2.20\nnodejs 20.11.0\n');
  writeFixture('php-disable-tls/composer.json', JSON.stringify({ config: { 'disable-tls': true } }));
  writeFixture('php-disable-tls/Dockerfile', 'FROM php:8.3.36-fpm\nUSER www-data\n');
  writeFixture('php-dotdockerfile/.dockerfile', 'FROM --platform=linux/amd64 docker.io/library/php:8.3.30-fpm AS base\nUSER www-data\n');
  writeFixture('php-constraint/composer.json', JSON.stringify({ require: { 'acme/widget': '^1.0' } }));
  writeFixture('php-constraint-exact/composer.json', JSON.stringify({ require: { 'acme/widget': '1.4.3' } }));
  writeFixture('php-constraint-exact-bad/composer.json', JSON.stringify({ require: { 'acme/widget': '1.4.2' } }));
  writeFixture('php-constraint-outside/composer.json', JSON.stringify({ require: { 'acme/widget': '^2.0' } }));
  writeFixture('php-constraint-dev/composer.json', JSON.stringify({ require: { 'acme/widget': 'dev-main' } }));
  writeFixture('php-constraint/Dockerfile', 'FROM php:8.3.36-fpm\nUSER www-data\n');

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

// ===== Regression cases from Codex wider review (CODEX_HANDOFF.md) =====
async function testCrossScannerRegressions() {
  console.log('\n  \x1b[1m🔁 Cross-Scanner Regression Tests\x1b[0m\n');
  const { execSync } = require('node:child_process');

  // Secrets are redacted in findings (and therefore in CLI and JSON output)
  const fakePassword = 'example-password-123456';
  writeFixture('redact-test/config.js', `const password = "${fakePassword}";\n`);
  writeFixture('redact-test/package.json', '{"name":"r","version":"1.0.0","files":["config.js"]}');
  writeFixture('redact-test/docker-compose.yml', 'services:\n  db:\n    environment:\n      PASSWORD: supersecretvalue123\n');
  const leak = await runLeakScan(path.join(FIXTURE_DIR, 'redact-test'), {});
  const docker = await runDockerScan(path.join(FIXTURE_DIR, 'redact-test'), {});
  assert(leak.some(r => r.description === 'Hardcoded secret/password'), 'Still detects hardcoded password');
  assert(!JSON.stringify(leak).includes(fakePassword), 'Leak scanner output does not contain the secret value');
  assert(!JSON.stringify(docker).includes('supersecretvalue123'), 'Docker compose output does not contain the secret value');
  const leakTest = await runLeakScan(path.join(FIXTURE_DIR, 'leak-test'), {});
  assert(leakTest.some(r => r.description === 'macOS user home path' && r.match.includes('/Users/developer/')),
    'Non-secret matches (paths, URLs) are not redacted');

  // Non-npm projects don't get npm lockfile or publish warnings
  writeFixture('php-only/composer.json', JSON.stringify({ name: 'acme/lib' }));
  const phpOnlyDeps = await runSupplyChainScan(path.join(FIXTURE_DIR, 'php-only'), {});
  const phpOnlyLeak = await runLeakScan(path.join(FIXTURE_DIR, 'php-only'), {});
  assert(phpOnlyDeps.length === 0, 'No npm missing-lockfile warning without package.json');
  assert(!phpOnlyLeak.some(r => r.type === 'config'), 'No npm publish advice without package.json');

  // pip config is checked without any requirements file
  writeFixture('pip-conf-only/pip.conf', '[global]\nindex-url = http://example.invalid/simple\n');
  const pipConf = await runPythonScan(path.join(FIXTURE_DIR, 'pip-conf-only'), {});
  assert(pipConf.some(r => r.type === 'insecure-config'), 'Detects insecure pip.conf without dependency files');

  // A nested safe copy must not hide a vulnerable top-level copy
  writeFixture('npm-nested/package.json', '{"name":"n","version":"1.0.0"}');
  writeFixture('npm-nested/package-lock.json', JSON.stringify({
    name: 'n', version: '1.0.0', lockfileVersion: 3,
    packages: {
      '': { name: 'n', version: '1.0.0' },
      'node_modules/axios': { version: '1.14.1', resolved: 'https://registry.npmjs.org/axios/-/axios-1.14.1.tgz', integrity: 'sha512-a' },
      'node_modules/foo': { version: '1.0.0', resolved: 'https://registry.npmjs.org/foo/-/foo-1.0.0.tgz', integrity: 'sha512-b' },
      'node_modules/foo/node_modules/axios': { version: '1.14.0', resolved: 'https://registry.npmjs.org/axios/-/axios-1.14.0.tgz', integrity: 'sha512-c' },
    },
  }));
  const nested = await runSupplyChainScan(path.join(FIXTURE_DIR, 'npm-nested'), {});
  assert(nested.some(r => r.package === 'axios' && r.version === '1.14.1'), 'Detects vulnerable axios despite nested safe copy');

  // go.sum history does not override go.mod's selected version
  writeFixture('go-sum-history/go.mod', 'module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.4.0\n');
  writeFixture('go-sum-history/go.sum',
    'golang.org/x/text v0.3.6 h1:aaaa=\ngolang.org/x/text v0.3.6/go.mod h1:bbbb=\n' +
    'golang.org/x/text v0.4.0 h1:cccc=\ngolang.org/x/text v0.4.0/go.mod h1:dddd=\n');
  const goHistory = await runGoScan(path.join(FIXTURE_DIR, 'go-sum-history'), {});
  assert(!goHistory.some(r => r.package === 'golang.org/x/text'), 'Ignores historical go.sum versions when go.mod selects a fixed one');

  // Secrets added by modifying an existing file are found in git history
  const repo = path.join(FIXTURE_DIR, 'git-modified');
  mkdirp(repo);
  const git = cmd => execSync(`git -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false ${cmd}`, { cwd: repo, stdio: 'pipe' });
  let gitAvailable = true;
  try {
    git('init -q');
    fs.writeFileSync(path.join(repo, 'app.js'), 'const a = 1;\n');
    git('add app.js');
    git('commit -q -m first');
    const token = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
    fs.writeFileSync(path.join(repo, 'app.js'), `const a = 1;\nconst token = "${token}";\n`);
    git('commit -q -am second');
    const history = await runGitScan(repo, {});
    assert(history.some(r => r.type === 'git-secret' && r.file === 'app.js'), 'Detects secret added by modifying an existing file');
    assert(!JSON.stringify(history).includes(token), 'Git history output does not contain the secret value');
  } catch (err) {
    gitAvailable = false;
  }
  if (!gitAvailable) console.log('  (skipped git history regression: git not available)');

  // Round 2 (CODEX_HANDOFF.md): prerelease PHP tag, exact Go matching, credentials in registry URLs
  writeFixture('php-rc-tag/Dockerfile', 'FROM php:8.3.36-rc1\nUSER www-data\n');
  const rcTag = await runPhpScan(path.join(FIXTURE_DIR, 'php-rc-tag'), {});
  assert(rcTag.some(r => r.type === 'php-runtime-unverified'), 'Prerelease php:8.3.36-rc1 is unverified, not patched');
  writeFixture('php-variant-tag/Dockerfile', 'FROM php:8.3.36-fpm-alpine3.20\nUSER www-data\n');
  const variantTag = await runPhpScan(path.join(FIXTURE_DIR, 'php-variant-tag'), {});
  assert(variantTag.length === 0, 'Official variant php:8.3.36-fpm-alpine3.20 is recognised as patched');

  writeFixture('go-exact/go.mod', 'module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.60\n');
  const goExact = await runGoScan(path.join(FIXTURE_DIR, 'go-exact'), {});
  assert(!goExact.some(r => r.package === 'golang.org/x/text'), 'Go v0.3.60 does not match advisory version 0.3.6');

  writeFixture('npm-cred-url/package.json', '{"name":"c","version":"1.0.0"}');
  writeFixture('npm-cred-url/package-lock.json', JSON.stringify({
    name: 'c', version: '1.0.0', lockfileVersion: 3,
    packages: {
      '': { name: 'c', version: '1.0.0' },
      'node_modules/demo': { version: '1.0.0', resolved: 'https://user:fake-password@evil.example/demo.tgz?token=fake-token-value', integrity: 'sha512-d' },
    },
  }));
  const credUrl = await runSupplyChainScan(path.join(FIXTURE_DIR, 'npm-cred-url'), {});
  const credJson = JSON.stringify(credUrl);
  assert(credUrl.some(r => r.type === 'suspicious-registry' && r.resolved.includes('evil.example/demo.tgz')),
    'Suspicious registry finding keeps host and path');
  assert(!credJson.includes('fake-password') && !credJson.includes('fake-token-value'),
    'Registry URL credentials are redacted from JSON output');
  const { redactUrl } = require('../src/redact');
  const unlisted = redactUrl('https://evil.example/pkg.tgz?private_token=fake-secret-value#fragment');
  assert(unlisted === 'https://evil.example/pkg.tgz', 'Registry URL query string and fragment are dropped, whatever the key');
  assert(!redactUrl('not a url?private_token=fake-secret-value').includes('fake-secret-value'),
    'Unparseable URL query string is dropped');

  writeFixture('npm-php-name/package.json', '{"name":"p","version":"1.0.0"}');
  writeFixture('npm-php-name/package-lock.json', JSON.stringify({
    name: 'p', version: '1.0.0', lockfileVersion: 3,
    packages: { '': { name: 'p', version: '1.0.0' }, 'node_modules/php': { version: '1.0.0', integrity: 'sha512-e' } },
  }));
  let phpNameOk = true;
  try {
    await runSupplyChainScan(path.join(FIXTURE_DIR, 'npm-php-name'), { knownCompromised: { php: { 'acme/x': [] } } });
  } catch {
    phpNameOk = false;
  }
  assert(phpNameOk, 'knownCompromised.php does not break npm scanning of a package named "php"');

  // Every scanner is part of the public API
  const api = require('../src/index');
  const expected = ['runLeakScan', 'runSupplyChainScan', 'runPythonScan', 'runJavaScan', 'runDotnetScan',
                    'runRubyScan', 'runGoScan', 'runPhpScan', 'runDockerScan', 'runGitScan', 'formatResults'];
  assert(expected.every(fn => typeof api[fn] === 'function'), 'src/index.js exports every scanner');
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

  assert(results.filter(r => r.type === 'docker-root').length === 1, 'Reports each Dockerfile once (case-insensitive FS)');
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

async function testPhpScanner() {
  console.log('\n  \x1b[1m🐘 PHP Scanner Tests\x1b[0m\n');

  const results = await runPhpScan(path.join(FIXTURE_DIR, 'php-test'), {});
  assert(results.some(r => r.type === 'php-runtime-vulnerable' && r.version === '8.3.30-fpm' && r.severity === 'critical'), 'Detects PHP2Shell-vulnerable PHP 8.3.30');
  assert(results.some(r => r.type === 'php-runtime-vulnerable' && r.version === '7.4-apache'), 'Detects end-of-life PHP 7.4 as vulnerable');
  assert(results.some(r => r.type === 'php-runtime-unverified' && r.version === '8.4-apache'), 'Flags floating php:8.4 tag as unverified');
  assert(results.filter(r => r.type === 'insecure-source').length === 2, 'Detects insecure Composer config');

  const configResults = await runPhpScan(path.join(FIXTURE_DIR, 'php-test'), {
    knownCompromised: { php: { 'monolog/monolog': [{ versions: ['*'], advisory: 'test', description: 'test', severity: 'critical' }] } },
  });
  assert(configResults.some(r => r.type === 'compromised-composer' && r.package === 'monolog/monolog'), 'Detects compromised Composer package from config');

  const cleanResults = await runPhpScan(path.join(FIXTURE_DIR, 'php-clean'), {});
  assert(cleanResults.length === 0, 'Patched PHP project produces no findings');

  const unpinnedResults = await runPhpScan(path.join(FIXTURE_DIR, 'php-unpinned'), {});
  assert(unpinnedResults.some(r => r.type === 'php-runtime-unverified'), 'Flags unpinned php image');

  const emptyResults = await runPhpScan(path.join(FIXTURE_DIR, 'clean-project'), {});
  assert(emptyResults.length === 0, 'Non-PHP project produces no findings');

  const otherImage = await runPhpScan(path.join(FIXTURE_DIR, 'php-other-image'), {});
  assert(otherImage.length === 0, 'Ignores non-php images like phpmyadmin');

  const prerelease = await runPhpScan(path.join(FIXTURE_DIR, 'php-prerelease'), {});
  assert(prerelease.some(r => r.type === 'php-runtime-unverified'), 'Flags prerelease/unknown PHP branch as unverified');

  const malformed = await runPhpScan(path.join(FIXTURE_DIR, 'php-malformed'), {});
  assert(malformed.some(r => r.type === 'php-runtime-unverified'), 'Flags malformed PHP tag as unverified');

  const platformOnly = await runPhpScan(path.join(FIXTURE_DIR, 'php-platform-only'), {});
  assert(platformOnly.some(r => r.type === 'php-runtime-unverified' && r.severity === 'medium'),
    'config.platform.php alone does not verify the runtime');

  const disableTls = await runPhpScan(path.join(FIXTURE_DIR, 'php-disable-tls'), {});
  assert(disableTls.some(r => r.type === 'insecure-source' && r.description.includes('disable-tls')), 'Detects Composer disable-tls');

  const dotDockerfile = await runPhpScan(path.join(FIXTURE_DIR, 'php-dotdockerfile'), {});
  assert(dotDockerfile.filter(r => r.type === 'php-runtime-vulnerable').length === 1,
    'Scans .dockerfile with --platform and registry prefix');

  const constraint = await runPhpScan(path.join(FIXTURE_DIR, 'php-constraint'), {
    knownCompromised: { php: { 'acme/widget': [{ versions: ['1.4.2'], advisory: 'test', description: 'test', severity: 'critical' }] } },
  });
  assert(constraint.some(r => r.type === 'compromised-composer-unverified' && r.severity === 'high'), 'Flags range that can reach a compromised version');

  const widgetConfig = {
    knownCompromised: { php: { 'acme/widget': [{ versions: ['1.4.2'], advisory: 'test', description: 'test', severity: 'critical' }] } },
  };
  const exact = await runPhpScan(path.join(FIXTURE_DIR, 'php-constraint-exact'), widgetConfig);
  assert(exact.length === 0, 'Exact constraint 1.4.3 is not flagged for blocklisted 1.4.2');
  const exactBad = await runPhpScan(path.join(FIXTURE_DIR, 'php-constraint-exact-bad'), widgetConfig);
  assert(exactBad.some(r => r.type === 'compromised-composer'), 'Exact constraint 1.4.2 is flagged as compromised');
  const outside = await runPhpScan(path.join(FIXTURE_DIR, 'php-constraint-outside'), widgetConfig);
  assert(outside.length === 0, 'Range ^2.0 that cannot reach 1.4.2 is not flagged');
  const devBranch = await runPhpScan(path.join(FIXTURE_DIR, 'php-constraint-dev'), widgetConfig);
  assert(devBranch.some(r => r.type === 'compromised-composer-unverified' && r.description.includes('not evaluated')),
    'Unparseable constraint is reported as not evaluated');

  const library = await runPhpScan(path.join(FIXTURE_DIR, 'php-library'), {});
  assert(library.length === 0, 'Composer library without deployment evidence is not flagged');

  const devPinProject = await runPhpScan(path.join(FIXTURE_DIR, 'php-devpin-project'), {});
  assert(devPinProject.some(r => r.type === 'php-runtime-unverified' && r.severity === 'medium'),
    'Patched .php-version alone does not verify a deployable project');

  const devPinVulnerable = await runPhpScan(path.join(FIXTURE_DIR, 'php-devpin-vulnerable'), {});
  assert(devPinVulnerable.some(r => r.type === 'php-runtime-vulnerable' && r.description.includes('development pin')),
    'Unpatched development pin is still reported');
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
    await testPhpScanner();
    await testDotnetScanner();
    await testGitScanner();
    await testCrossScannerRegressions();
  } finally {
    cleanup();
  }

  console.log(`\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log(`  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

  process.exit(failed > 0 ? 1 : 0);
}

main();
