# ReconForge 4.1.2

## Finding pipeline / TestSSL semantics fix

- Preserves scanner finding identifiers and structured evidence state.
- Distinguishes `CONFIRMED_OBSERVED`, `CONFIRMED_DERIVED`, `SCANNER_REPORTED`, and `NEEDS_VALIDATION`.
- Quality gate now reports scanner-observed candidates instead of hiding them solely because no second validator was available.
- Vulnerability-specific claims such as historical CVEs remain explicitly marked as `NEEDS_VALIDATION`.
- testssl.sh parser no longer promotes arbitrary JSON metadata strings into reportable findings.
- Informational testssl telemetry is retained as observations instead of flooding the findings list.
- HTML reports now show Evidence and Validation columns.
