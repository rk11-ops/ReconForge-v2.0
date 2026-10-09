# ReconForge 4.5.0

- Added target-aware auto workflow and `reconforge` no-argument target prompt.
- Added operator-facing red/offensive terminal banner and target plan preview.
- Added post-assessment report format prompt: HTML, PDF, or skip.
- Added ReportLab PDF report generation.
- Reduced HTML/PDF reports to findings-focused content; removed raw scanner JSON and large technical dumps from the operator report.
- Added concise `why_reported` rationale for each reportable finding.
- Added Description/Impact/Remediation only for confirmed or deterministically derived findings.
- Added exact source command display per finding where an external scanner produced the evidence.
- Added concise suppressed/false-positive reasons.
- Kept internal evidence/state artifacts for traceability without exposing raw JSON in the final report.
