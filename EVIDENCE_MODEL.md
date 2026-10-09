# ReconForge Evidence Model

ReconForge treats observations, scanner claims, and vulnerability validation as separate concepts.

| State | Meaning | Report treatment |
|---|---|---|
| `CONFIRMED_OBSERVED` | Direct protocol, HTTP, TLS, or scanner observation with concrete evidence | Report |
| `CONFIRMED_DERIVED` | Deterministically derived from captured evidence | Report |
| `SCANNER_REPORTED` | Scanner reported a candidate but no deterministic validator ran | Report as scanner-reported |
| `NEEDS_VALIDATION` | Vulnerability-specific hypothesis that still needs validation | Report as candidate |
| `FALSE_POSITIVE` | Explicitly rejected | Suppress |

The v4.2 HTTP probe is now part of this same pipeline. Missing security headers, cookie-flag observations, wildcard CORS, and TLS certificate verification failures are kept as evidence rather than being silently discarded because no second scanner agreed.

Historical CVEs and named protocol attacks remain validation candidates unless an appropriate validator provides supporting evidence.
