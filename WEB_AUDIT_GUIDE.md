# ReconForge Web Crawl + Audit

ReconForge 4.3 adds a Burp-style **crawl + audit** pass for web targets. The goal is to build a useful vulnerability inventory without turning the crawler into an exploitation engine.

## What the web audit does

- Crawls same-origin links/resources with bounded depth, page count, rate, and concurrency.
- Follows same-host redirects only.
- Discovers forms, methods, input names, query parameters, API documentation markers, GraphQL markers, and script-referenced paths.
- Does **not** submit forms or change application state.
- Audits response headers, cookies, CORS, CSP, mixed content, directory listings, verbose errors, source maps, sensitive discovered paths, insecure password forms, and cache-control signals.
- Marks CSRF, reflected-input/XSS, open redirect, and SSRF-style cases as `NEEDS_VALIDATION` when they cannot be proven safely from a GET-only crawl.
- Adds manual-review queues for authentication/session management, authorization/IDOR/BOLA, privilege boundaries, file upload, business logic, and rate limiting.

## Safe audit-only mode

```bash
python3 -m reconforge https://app.example.test \\
  --authorized \\
  --audit-only
```

This mode runs the web crawl/audit and report pipeline while skipping Nmap, Nikto, Wapiti, Nuclei, fuzzing, adaptive scanner actions, and SQLMap.

## Normal full assessment with crawl/audit

```bash
python3 -m reconforge https://app.example.test \\
  --authorized \\
  --mode deep \\
  --crawl-depth 3 \\
  --crawl-pages 100 \\
  --crawl-rate 2 \\
  --crawl-concurrency 4
```

The crawl is enabled by default in 4.3 for web targets. Use `--no-crawl` to disable it.

## Reading a finding

Every finding should answer:

1. **What was observed?**
2. **Where was it observed?**
3. **What evidence state does ReconForge assign?**
4. **What manual validation is still required?**
5. **What remediation is recommended?**

Common evidence states remain:

- `CONFIRMED_OBSERVED`: directly observed or deterministically derived from a safe request/response.
- `CONFIRMED_DERIVED`: deterministically derived from multiple observations.
- `SCANNER_REPORTED`: emitted by a scanner but not independently proven by a safe validator.
- `NEEDS_VALIDATION`: plausible candidate requiring operator-controlled testing.
- `FALSE_POSITIVE`: suppressed after validation.

## Operator boundary

ReconForge's web audit does not provide exploit payloads, submit discovered forms, perform credential attacks, or claim that a scanner result is exploitable merely because a template matched. The report is intended to hand the operator a clean list of issues plus the evidence and manual checks needed to investigate them safely.
