# ReconForge 4.3.0

## Burp-style crawl + safe audit upgrade

- Added bounded same-origin GET crawler with depth/page/rate/concurrency limits.
- Forms are inventoried but never submitted by the crawler.
- Cross-host redirects are blocked.
- Added deterministic web audit rules for security headers, cookies, CORS, clickjacking, HSTS, verbose errors, directory listing, mixed content, exposed source maps, sensitive paths, insecure password forms, and public-cache candidates.
- Added explicit candidate rules for CSRF, reflected input/XSS review, open redirect, and SSRF-style URL fetch parameters; these remain `NEEDS_VALIDATION`.
- Added manual review queue for authentication/session, authorization/IDOR/BOLA, privilege boundaries, file upload, business logic, and rate limiting.
- Added `--audit-only` mode so the operator can generate an attack-surface/vulnerability audit without running the external active scanner stack.
- Reports now include endpoint-level evidence, manual validation guidance, remediation, CWE/OWASP metadata, crawl coverage, and manual-only review areas.
- No exploit delivery, form submission, credential attacks, or destructive actions were added.
- Local verification: 23 automated tests pass, including two dedicated web-audit/crawler tests and an audit-only end-to-end local HTTP run.
