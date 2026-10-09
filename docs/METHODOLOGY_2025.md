# ReconForge 4.4 Methodology Engine

## Purpose

ReconForge uses a versioned methodology layer to answer two questions:

1. Which current security taxonomy areas were assessed or surfaced by the run?
2. Which observations are strong enough to report, and which require manual validation?

The engine is a **coverage and classification layer**, not an exploit engine.

## Methodology packs

### OWASP Top 10:2025

The pack contains all ten 2025 categories:

1. A01:2025 Broken Access Control
2. A02:2025 Security Misconfiguration
3. A03:2025 Software Supply Chain Failures
4. A04:2025 Cryptographic Failures
5. A05:2025 Injection
6. A06:2025 Insecure Design
7. A07:2025 Authentication Failures
8. A08:2025 Software or Data Integrity Failures
9. A09:2025 Security Logging & Alerting Failures
10. A10:2025 Mishandling of Exceptional Conditions

### MITRE CWE Top 25:2025

The current official Top 25 is maintained by MITRE CWE. ReconForge includes all 25 entries from the 2025 ranking, with a dynamic/source/manual capability marker.

## Coverage semantics

- `detected` — mapped evidence exists; evidence strength is suitable for reporting at the current validation level.
- `candidate` — a relevant signal was observed, but vulnerability-specific validation is still required.
- `review` / `manual-review` — the surface exists, but an identity, workflow, or configuration comparison is required.
- `source-review` — the weakness is mainly a source/binary/runtime-memory concern and is not reliably proven by ordinary web DAST.
- `not_observed` — no mapped evidence was observed in this run; this is not a negative security assurance.

## Safe Explore / Test model

ReconForge's web workflow is deliberately similar in shape to an enterprise DAST scanner:

`Explore → Analyze → Safe Test / Validate → Correlate → Report`

Explore consists of bounded same-origin GET crawling. Safe Test/Validate consists of deterministic response analysis, passive checks, scanner correlation, and candidate classification. The methodology layer does not submit state-changing forms or deliver exploit payloads.

## Why some CWE Top 25 entries are source-review

The CWE Top 25 mixes web/application weaknesses with memory-safety weaknesses. A web crawler cannot honestly confirm `CWE-787`, `CWE-416`, `CWE-125`, `CWE-120`, `CWE-476`, `CWE-121`, or `CWE-122` merely from HTTP responses. ReconForge labels those as source-review so the report is explicit about coverage boundaries.

## Sources

- OWASP Top 10:2025: https://top10.owasp.org/2025/
- OWASP Top 10:2025 introduction/methodology: https://top10.owasp.org/2025/0x00_2025-Introduction/
- MITRE CWE Top 25: https://cwe.mitre.org/top25/
- MITRE CWE Top 25 2025 methodology: https://cwe.mitre.org/top25/archive/2025/2025_methodology.html
- HCL AppScan on Cloud DAST overview: https://help.hcl-software.com/appscan/ASoC/r_dast_scanning.html
