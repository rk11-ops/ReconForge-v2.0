# ReconForge 4.2.0

## Target handling
- Accepts raw URL, hostname, IPv4/IPv6, and schemeless `host:port` targets.
- Preserves explicit web ports for HTTP tooling and focused Nmap discovery.
- Keeps bare host/IP targets as network assessments unless an explicit web surface is supplied.

## First-class HTTP evidence
- Passive HTTP collection now emits deterministic findings for high-signal response properties such as missing clickjacking protection, missing CSP/HSTS/X-Content-Type-Options, wildcard CORS, weak cookie flags, and version-disclosing Server headers.
- HTTPS certificate verification failures are retained as evidence while allowing a read-only unverified fallback to collect response metadata.
- Passive findings are normalized and correlated through the same evidence pipeline as scanner findings.

## Adaptive execution
- Adaptive SQLMap actions now preserve the full parameterized URL and are actually dispatched to the bounded SQLMap runner.
- Initial recon and web validation stages use bounded parallel execution while preserving stage dependencies.

## Evidence integrity
- Each run receives a SHA-256 artifact manifest covering scanner artifacts, logs, command records, evidence, and local Qwen output.
- Reported evidence states remain explicit: `CONFIRMED_OBSERVED`, `CONFIRMED_DERIVED`, `SCANNER_REPORTED`, `NEEDS_VALIDATION`, `FALSE_POSITIVE`.

## Compatibility
- Existing v4.1.x CLI options remain compatible.
- No new Python dependencies were added.
