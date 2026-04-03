# Acrionix Shield

[![npm version](https://img.shields.io/npm/v/acrionix-shield.svg)](https://www.npmjs.com/package/acrionix-shield)
[![npm downloads](https://img.shields.io/npm/dw/acrionix-shield.svg)](https://www.npmjs.com/package/acrionix-shield)
[![license](https://img.shields.io/npm/l/acrionix-shield.svg)](https://github.com/andrei-gogo/acrionix-shield/blob/main/LICENSE)

> If you find this useful, please give it a star on GitHub — it helps others discover the project and keeps us motivated to improve it!

**Pre-publish security scanner — prevents source leaks and detects supply chain attacks across 7 languages.**

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
- Supports `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`

## Usage

```bash
# Run all checks
npx acrionix-shield check

# Scan for source leaks only
npx acrionix-shield scan-leaks

# Scan dependencies only
npx acrionix-shield scan-deps

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
    ]
  }
}
```

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
