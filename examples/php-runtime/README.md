# PHP runtime scan example

This intentionally vulnerable Dockerfile declares `php:8.3.30-fpm`. PHP2Shell affects this runtime; PHP 8.3.36 is the first fixed release in the 8.3 line. The example has no application code or secrets.

From the Shield repository root:

```bash
npx acrionix-shield@1.2.1 scan-php --dir examples/php-runtime
```

Expected result: one critical finding at `Dockerfile:1` for PHP2Shell (CVE-2026-109618 and CVE-2026-109619), with advice to upgrade to PHP 8.3.36 or later. To try the fix locally, change the `FROM` line to `php:8.3.36-fpm` and run the same command again; it should report no PHP findings. Restore the original line if you want to keep the vulnerable demo.

This detects the version declared in the repository. It cannot verify a separately installed production runtime or vendor backports. See [Coverage Limits](../../README.md#coverage-limits) for the rest of Shield's scope.
