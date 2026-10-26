# Acrionix Shield

[![npm version](https://img.shields.io/npm/v/acrionix-shield.svg)](https://www.npmjs.com/package/acrionix-shield)
[![npm downloads](https://img.shields.io/npm/dw/acrionix-shield.svg)](https://www.npmjs.com/package/acrionix-shield)
[![license](https://img.shields.io/npm/l/acrionix-shield.svg)](https://github.com/andrei-gogo/acrionix-shield/blob/main/LICENSE)

> If you find this useful, please give it a star on GitHub — it helps others discover the project and keeps us motivated to improve it!

**Pre-publish security scanner — catches source leaks, leaked secrets and known-bad dependencies across seven dependency ecosystems, plus Node.js/PHP runtime, Docker, git history and GitHub Actions checks.**

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

### See a real scan

This repository includes an [intentionally vulnerable PHP Dockerfile](https://github.com/andrei-gogo/acrionix-shield/blob/main/examples/php-runtime/Dockerfile). From a directory outside the Shield checkout, run:

```bash
git clone https://github.com/andrei-gogo/acrionix-shield.git
npx acrionix-shield@1.2.2 scan-php --dir acrionix-shield/examples/php-runtime
```

Shield reports the affected runtime and the precise patch to use:

```text
[1/1] Scanning PHP runtime and Composer dependencies...
CRITICAL (1 finding)
  PHP2Shell — PHP 8.3.30 is unpatched
  File: Dockerfile:1
  Advisory: CVE-2026-109618, CVE-2026-109619
  Fix: Upgrade to PHP 8.3.36 or later
Found 1 issue(s). Review before publishing.
```

The example contains no real application or secrets. See the [reproduction and fix](https://github.com/andrei-gogo/acrionix-shield/blob/main/examples/php-runtime/README.md). Shield uses a finite offline advisory list; a clean scan does not replace your ecosystem's full audit tools. [Coverage limits](#coverage-limits) explain what it can and cannot check.

## What It Scans

### Source Leak Scanner
- `.map` source map files that expose your source code
- `.env`, `.pem`, `.key` files with secrets
- Cloud storage URLs (AWS S3, Google Cloud, Azure Blob, **Cloudflare R2**)
- Hardcoded secrets and provider keys: AWS, GitHub, npm, OpenAI, Anthropic, Slack, Stripe, SendGrid, Square, Google, and database URLs with credentials (22 provider formats, shared with the git scanner)
- Embedded private keys and certificates
- Internal file paths (`/Users/...`, `C:\Users\...`)
- `sourceMappingURL` references in compiled code
- Missing `.npmignore` or `files` field warnings

### Supply Chain Scanner
- **Known compromised packages** (axios, event-stream, ua-parser-js, coa, rc, colors, faker, node-ipc, tensorlake, @subql/common, the MALFEX packages, and more)
- **Typosquatting detection** (catches `axois` instead of `axios`, `1odash` instead of `lodash`)
- **Suspicious registries** (packages resolved from non-standard URLs)
- **Missing integrity hashes** in lockfiles
- Supports `package-lock.json`, classic Yarn v1 `yarn.lock`, and `pnpm-lock.yaml` (Yarn Berry lockfiles are not parsed yet)
- Every installed copy is checked, so a safe nested copy cannot hide a vulnerable top-level one
- Registry URLs in findings are shown as scheme, host and path only — credentials, query string and fragment are removed
- **Node.js runtime (Node2Shell, CVE-2026-111497):** official `node` images in Dockerfile/compose, `.nvmrc`, `.node-version` and `.tool-versions` are checked against the fixed releases 22.23.4, 24.22.1 and 26.12.1. Lines before 22 and odd lines (23, 25) are end-of-life. Floating tags such as `node:22` or `node:lts` are reported as unverified, because the patch level depends on when the image was pulled. `engines.node` ranges are not evaluated.

### Dependency Ecosystems

Offline, curated rules for seven dependency ecosystems:

| Ecosystem | Files read | Checks |
|---|---|---|
| npm | `package-lock.json`, `yarn.lock` (v1), `pnpm-lock.yaml` | Compromised packages, typosquats, registries, integrity |
| Python / PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pip.conf` / `pip.ini` | Compromised packages (incl. litellm 1.82.7/1.82.8/1.107.0), known-vulnerable ranges (Brotli/brotlicffi CVE-2026-111497, Pillow < 13.0.0), typosquats, insecure pip config |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts` | Curated Log4j, Spring web, Struts, Jackson and fastjson advisories, including fastjson CVE-2026-16723 |
| .NET / NuGet | `.csproj`, `.fsproj`, `.vbproj`, `packages.config` | Curated NuGet advisory ranges (log4net, Newtonsoft.Json, OData and others) |
| Ruby | `Gemfile`, `Gemfile.lock` | Curated hijacked gem releases (including rest-client 1.6.10–1.6.13), typosquats, HTTP sources |
| Go | `go.mod` (`go.sum` only without `go.mod`) | Curated module advisory ranges, local `replace` |
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
- Secrets added in the last 50 commits (new files and edits to existing files): 28 rules, the 22 provider formats plus looser ones (Mailgun, Twilio, JWT, Heroku) that would misfire on minified files
- Sensitive files missing from `.gitignore`

### GitHub Actions
Reads `.github/workflows/*.yml` and a root `action.yml`:
- **Critical:** an action whose tags still point at malware: `actions-cool/issues-helper` and `actions-cool/maintain-one-comment` (every tag moved to an imposter commit that steals runner credentials, May 2026; never cleaned up). A SHA pin of these is medium: check the commit is a legitimate release.
- **Medium (past incident):** `aquasecurity/trivy-action` below 0.35.0 and `aquasecurity/setup-trivy` below 0.2.6 served a credential stealer on March 19-20 2026 ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)). The tags have since been restored, so Shield reports the exposure window: if the workflow ran then, rotate its secrets. A repo scan cannot tell whether it did.
- **High:** untrusted input such as `${{ github.event.pull_request.title }}` interpolated into a `run:` or `github-script` block (script injection), and `pull_request_target` workflows that check out the pull request's code.
- **Medium / low:** actions pinned to a tag or branch instead of a full commit SHA (low for GitHub's own `actions/*` and `github/*`).

Secret values that the scanners detect are redacted in CLI and JSON output (for example `pass…[redacted 36 chars]`). Redaction applies to detected matches; a secret no rule recognises is not found and therefore not reported at all.

## Coverage Limits

Acrionix Shield is an offline scanner with curated rules. A clean result means none of its rules matched, not that a project is free of vulnerabilities.

- **No full advisory database.** Ecosystem checks use a finite, curated list of high-impact incidents with affected versions or ranges taken from vendor advisories, GHSA/OSV and the original researchers. The scanner works offline and does not query any feed, so new or less-known vulnerabilities are not covered until a release adds them. Run it alongside each ecosystem's own audit:

  | Ecosystem | Full advisory check |
  |---|---|
  | npm | `npm audit` |
  | Python | `pip-audit` |
  | PHP | `composer audit` |
  | Ruby | `bundle-audit` |
  | Go | `govulncheck ./...` |
  | .NET | `dotnet list package --vulnerable` |
  | Java | OWASP Dependency-Check or `mvn org.owasp:dependency-check-maven:check` |
  | Any | [osv-scanner](https://google.github.io/osv-scanner/) |

- **Version ranges** are checked against plain numeric versions; Python requirements need exact pins (`==`) or lockfile versions. A loose requirement like `pillow>=10` is reported as "not verified" (low), never as safe or vulnerable. Pre-release and post-release versions are not compared.
- **Java / .NET / Ruby / Go parsers:** Java reads direct Maven/Gradle declarations but does not parse Gradle map-style coordinates (`group:`, `name:`, `version:`), resolve property substitutions, transitive dependencies or the final build graph. .NET scans project references but may miss centrally managed package versions. Both check each parsed declaration, even if another file names a patched version of the same package. Ruby prefers `Gemfile.lock` when present. Go reads `go.mod` requirements, which may differ from the build's final selected versions after minimal-version selection and `replace`; Go pseudo-versions outside the few exact seeds are not range-compared. Use the ecosystem audit commands above for resolved dependency checks.
- **Node.js runtime:** only versions declared in the repo are checked; `engines.node` ranges and runtimes installed another way need `node -v` in the real environment.
- **Composer:** there is no built-in Composer package blocklist. You can add entries under `knownCompromised.php`. Without `composer.lock`, constraints like `^1.0` are evaluated as ranges; constraints the scanner can't evaluate are reported as "not evaluated".
- **PHP runtime:** only versions declared in the repo are checked. A server or image that installs PHP another way still needs `php -v` in the real environment. Vendor backports (Debian, Ubuntu, RHEL) are not recognised.
- **Yarn Berry** (`yarn.lock` v2+) is not parsed.
- **GitHub Actions** workflows are read line by line, without a YAML parser: flow-style step lists and YAML anchors are not followed, and `pull_request_target` detection covers the whole file.
- **npm Trusted Publishing** (["SlugFest"](https://bloom.security/blog/slugfest-millions-of-ai-agents-download-exposed-npm-packages)): the affected package list is not public, so there is nothing to block. Maintainers should check that their trusted-publisher repo and workflow are still theirs after renames or transfers. Provenance alone does not prove a release is safe: the malicious tensorlake 0.5.144 had valid provenance.

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
npx acrionix-shield scan-actions

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

Shield's own Actions check reports these `@v4` tags as low (unpinned first-party actions). Pin them to a full commit SHA if your policy requires it.

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
    "actions": ["my-org/old-deploy-action"],
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

Top-level entries in `knownCompromised` are npm packages. Composer packages go under `knownCompromised.php`, and GitHub Actions (`owner/repo`, any tag) under `knownCompromised.actions`.

## Programmatic API

```js
const { runPhpScan, runLeakScan } = require('acrionix-shield');

const findings = await runPhpScan('/path/to/project');
```

Exports: `runLeakScan`, `runSupplyChainScan`, `runPythonScan`, `runJavaScan`, `runDotnetScan`, `runRubyScan`, `runGoScan`, `runPhpScan`, `runDockerScan`, `runGitScan`, `runActionsScan`, `formatResults`.

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
