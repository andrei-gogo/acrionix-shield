# Acrionix Shield

[![npm version](https://img.shields.io/npm/v/acrionix-shield.svg)](https://www.npmjs.com/package/acrionix-shield)
[![npm downloads](https://img.shields.io/npm/dw/acrionix-shield.svg)](https://www.npmjs.com/package/acrionix-shield)
[![license](https://img.shields.io/npm/l/acrionix-shield.svg)](https://github.com/andrei-gogo/acrionix-shield/blob/main/LICENSE)

> If you find this useful, please give it a star on GitHub — it helps others discover the project and keeps us motivated to improve it!

**Pre-publish security scanner — catches source leaks, leaked secrets and known-bad dependencies across seven dependency ecosystems, plus Docker and git history checks.**

Built by [Acrionix Technologies](https://acrionix.com) in response to the [Anthropic/Claude Code source leak](https://www.cnbc.com/2026/03/31/anthropic-leak-claude-code-internal-source.html) and the [axios supply chain attack](https://socket.dev/blog/axios-supply-chain-attack) of March 2026.

---

## The Problem

On March 31, 2026, two major security incidents shook the npm ecosystem:

1. **Anthropic's Claude Code** accidentally published a `.map` file containing references to 500,000 lines of unobfuscated source code on a public cloud bucket
2. **axios** (400M+ weekly downloads) was compromised — versions `1.14.1` and `0.30.4` injected a malicious `plain-crypto-js` dependency that harvested credentials

**Acrionix Shield** is a zero-dependency CLI that catches both types of issues before they reach production.

## Quick Start

```bash
npx acrionix-shield check
```

That's it. No config needed.

## What It Scans

### Source Leak Scanner
- `.map` source map files that expose your source code
- `.env`, `.pem`, `.key` files with secrets
- Cloud storage URLs (AWS S3, Google Cloud, Azure Blob, **Cloudflare R2**)
- Hardcoded API keys (AWS, GitHub, npm, OpenAI, Anthropic, Slack)
- Embedded private keys and certificates
- Internal file paths (`/Users/...`, `C:\Users\...`)
- `sourceMappingURL` references in compiled code
- Missing `.npmignore` or `files` field warnings

### Supply Chain Scanner
- **Known compromised packages** (axios, event-stream, ua-parser-js, coa, rc, colors, faker, node-ipc, and more)
- **Typosquatting detection** (catches `axois` instead of `axios`, `1odash` instead of `lodash`)
- **Suspicious registries** (packages resolved from non-standard URLs)
- **Missing integrity hashes** in lockfiles
- Supports `package-lock.json`, classic Yarn v1 `yarn.lock`, and `pnpm-lock.yaml` (Yarn Berry lockfiles are not parsed yet)
- Every installed copy is checked, so a safe nested copy cannot hide a vulnerable top-level one
- Registry URLs in findings are shown as scheme, host and path only — credentials, query string and fragment are removed

### Dependency Ecosystems

Offline, curated rules for seven dependency ecosystems:

| Ecosystem | Files read | Checks |
|---|---|---|
| npm | `package-lock.json`, `yarn.lock` (v1), `pnpm-lock.yaml` | Compromised packages, typosquats, registries, integrity |
| Python / PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pip.conf` / `pip.ini` | Compromised packages, typosquats, insecure pip config |
| Java | `pom.xml`, `build.gradle` | Log4Shell, Spring4Shell, Struts2, jackson-databind, fastjson |
| .NET / NuGet | `.csproj`, `.fsproj`, `.vbproj`, `packages.config` | Known-vulnerable package versions |
| Ruby | `Gemfile`, `Gemfile.lock` | Hijacked gems, typosquats, HTTP sources |
| Go | `go.mod` (`go.sum` only without `go.mod`) | Known-vulnerable module versions, local `replace` |
| PHP | Dockerfile / compose `php` images, `.php-version`, `.tool-versions`, `composer.json`, `composer.lock` | PHP runtime advisories (PHP2Shell), Composer TLS settings, optional custom Composer blocklist |

### PHP Runtime (PHP2Shell)

[PHP2Shell](https://www.php.net/archive/2026.php#2026-10-21-5) (CVE-2026-109618, CVE-2026-109619) is a remote code execution bug in the PHP interpreter itself, fixed in 8.2.35, 8.3.36, 8.4.27 and 8.5.12. `scan-php` reads the PHP version a project declares:

- **Critical:** official `php` image or development pin below the fixed release, or PHP 8.1 and older (end-of-life)
- **High (unverified):** floating tags like `php:8.4-apache` or `php:latest`, prerelease or unrecognised tags
- **Medium (unverified):** a deployable app (`"type": "project"` or a Dockerfile) with no `php` base image. `.php-version`, `.tool-versions` and `config.platform.php` are development hints and never prove the deployed runtime is patched.

### Docker
- Unpinned or `latest` base images, containers running as root
- Privileged mode, host network or PID namespace in compose files
- Secrets in `ENV`/`ARG`, sensitive files copied into images, insecure `curl`/`wget`/`pip` flags

### Git
- Secrets added in the last 50 commits (new files and edits to existing files)
- Sensitive files missing from `.gitignore`

Secret values that the scanners detect are redacted in CLI and JSON output (for example `pass…[redacted 36 chars]`). Redaction applies to detected matches; a secret no rule recognises is not found and therefore not reported at all.

## Coverage Limits

Acrionix Shield is an offline scanner with curated rules. A clean result means none of its rules matched, not that a project is free of vulnerabilities.

- **No full advisory database.** Ecosystem checks use built-in lists of known-bad versions. The scanner does not query npm, PyPI, Packagist or other advisory feeds, and does not replace `npm audit`, `pip-audit` or `composer audit`.
- **Composer:** there is no built-in Composer package blocklist. You can add entries under `knownCompromised.php`. Without `composer.lock`, constraints like `^1.0` are evaluated as ranges; constraints the scanner can't evaluate are reported as "not evaluated".
- **PHP runtime:** only versions declared in the repo are checked. A server or image that installs PHP another way still needs `php -v` in the real environment. Vendor backports (Debian, Ubuntu, RHEL) are not recognised.
- **Yarn Berry** (`yarn.lock` v2+) is not parsed.

## Usage

```bash
# Run all checks
npx acrionix-shield check

# Scan for source leaks only
npx acrionix-shield scan-leaks

# Scan npm dependencies only
npx acrionix-shield scan-deps

# Scan one ecosystem or area
npx acrionix-shield scan-python
npx acrionix-shield scan-java
npx acrionix-shield scan-dotnet
npx acrionix-shield scan-ruby
npx acrionix-shield scan-go
npx acrionix-shield scan-php
npx acrionix-shield scan-docker
npx acrionix-shield scan-git

# CI mode — exit code 1 on any finding
npx acrionix-shield check --ci

# Only report high and critical issues
npx acrionix-shield check --severity high

# JSON output for programmatic use
npx acrionix-shield check --json

# Scan a specific directory
npx acrionix-shield check --dir ./dist
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Check
on: [push, pull_request]
jobs:
  shield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npx acrionix-shield check --ci --severity high
```

`--severity high` gates the build on high and critical findings only. Medium and low findings (for example a secret in a test fixture, or an unidentified PHP runtime) are hidden by that flag but still deserve review.

### Pre-publish Hook

Add to your `package.json`:

```json
{
  "scripts": {
    "prepublishOnly": "npx acrionix-shield check --ci"
  }
}
```

## Configuration

Create a `.shieldrc.json` in your project root for custom rules:

```json
{
  "ignorePatterns": ["test/fixtures/.*", "docs/.*"],
  "customCloudPatterns": [
    {
      "pattern": "https://my-internal-cdn\\.example\\.com",
      "description": "Internal CDN URL",
      "severity": "high"
    }
  ],
  "customSensitivePatterns": [
    {
      "pattern": "INTERNAL_SECRET_[A-Z0-9]+",
      "description": "Internal secret token",
      "severity": "critical"
    }
  ],
  "knownCompromised": {
    "my-internal-pkg": [
      {
        "versions": ["2.0.0"],
        "advisory": "Internal advisory #42",
        "description": "Compromised build artifact",
        "severity": "critical"
      }
    ],
    "php": {
      "acme/widget": [
        {
          "versions": ["1.4.2"],
          "advisory": "Internal advisory #43",
          "description": "Compromised Composer release",
          "severity": "critical"
        }
      ]
    }
  }
}
```

Top-level entries in `knownCompromised` are npm packages. Composer packages go under `knownCompromised.php`.

## Programmatic API

```js
const { runPhpScan, runLeakScan } = require('acrionix-shield');

const findings = await runPhpScan('/path/to/project');
```

Exports: `runLeakScan`, `runSupplyChainScan`, `runPythonScan`, `runJavaScan`, `runDotnetScan`, `runRubyScan`, `runGoScan`, `runPhpScan`, `runDockerScan`, `runGitScan`, `formatResults`.

## Severity Levels

| Level | Icon | Meaning |
|-------|------|---------|
| **Critical** | 🚨 | Immediate action required — active exploit, leaked secrets, compromised package |
| **High** | 🔴 | Serious risk — source code exposure, cloud storage URLs, suspicious registries |
| **Medium** | 🟡 | Should fix — missing lockfile, missing integrity hashes, config issues |
| **Low** | 🔵 | Informational — metadata files, backup files |

## Zero Dependencies

Acrionix Shield has **zero npm dependencies**. It uses only Node.js built-in modules. This is intentional — a security tool should not itself be vulnerable to supply chain attacks.

## License

MIT — [Acrionix Technologies](https://acrionix.com)
