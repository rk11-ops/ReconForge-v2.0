# ReconForge 4.5.0

## Methodology engine

- Added OWASP Top 10:2025 coverage pack.
- Added MITRE CWE Top 25:2025 coverage pack (canonical current Top 25 source).
- Added finding-to-taxonomy mapping fields for every normalized finding.
- Added methodology coverage matrix to JSON and HTML reports.
- Added `--methodology {all,owasp-top10-2025,cwe-top25-2025}`.
- Added safe methodology-oriented candidates for SQL injection, path traversal, OS command injection, file upload surfaces, object-level authorization, dependency/build manifests, and sensitive secret exposure.
- Kept state-changing forms, exploit payloads and destructive tests out of the methodology layer.
- Added explicit `source-review` / `manual-review` semantics for weaknesses that ordinary DAST cannot honestly prove.
