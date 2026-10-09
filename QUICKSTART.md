# ReconForge 4.5.0 — Quick Start

ReconForge is an evidence-driven adaptive reconnaissance orchestrator for authorized assessments and controlled labs. Start with `--dry-run`, then move to a real run only after scope and tool availability look correct.

## 1. Install on Kali

```bash
chmod +x scripts/install_all_kali.sh
./scripts/install_all_kali.sh
source .venv/bin/activate
```

Check the toolchain:

```bash
command -v nmap nikto wapiti nuclei ffuf feroxbuster sqlmap
```

## 2. Run against an authorized URL

```bash
python3 -m reconforge https://app.example.test --authorized --mode deep
```

A URL with a custom port works too:

```bash
python3 -m reconforge https://app.example.test:8443/api/v1 --authorized --mode basic
```

## 3. Run an authorized IP / host:port

```bash
python3 -m reconforge 192.0.2.10 --authorized --mode basic
python3 -m reconforge 192.0.2.10:8080 --authorized --mode basic
```

For a bare IP/hostname, ReconForge treats the target as a network surface and can auto-detect web exposure after Nmap. For `host:port` or an explicit URL, the web surface is treated as explicit and the provided port is focused in Nmap when no manual `--nmap-ports` override is supplied.

## 4. Preview everything first

```bash
python3 -m reconforge https://app.example.test:8443 --authorized --dry-run --mode deep
```

No scanner process or passive network request is started. Planned commands are printed and saved under the run's `commands/` directory.

## 5. Scope enforcement

Create `scope.txt`:

```text
app.example.test
*.api.example.test
192.0.2.0/28
```

Then:

```bash
python3 -m reconforge app.example.test --authorized --scope scope.txt --mode deep
```

## 6. Adaptive behaviour

The flow is: Nmap discovery → HTTP/TLS validation → adaptive follow-up → bounded validation → quality gate/correlation → report.

Examples of adaptive decisions:

- Web service found → HTTP-focused tooling becomes eligible.
- WordPress / Swagger / GraphQL evidence → focused Nuclei templates.
- `/api/` or OpenAPI-like paths → path-focused content discovery.
- Parameterized endpoints → bounded SQLMap validation when SQLMap is enabled.

Every adaptive action is printed with a reason and consumes a profile-specific budget.

## 7. Qwen 4B GGUF

```bash
python3 -m reconforge https://app.example.test --authorized --mode deep \
  --qwen-gguf /path/to/qwen4b.gguf
```

Qwen is only the local triage/summarization layer. ReconForge's deterministic policy, execution, evidence, and quality-gate pipeline remains authoritative.

## 8. Reports and evidence

Each run creates a timestamped directory under `reconforge-results/` with:

```text
artifacts/   scanner outputs
logs/        stdout/stderr and tool logs
commands/    redacted command records
evidence/    manifest + evidence files
state.json   stage/tool checkpoint state
report.html / report.pdf  operator-facing final report (chosen after scanning)
report.html  operator-friendly report
```

`evidence/manifest.json` contains SHA-256 hashes for the run evidence files.

## 9. Evidence semantics

ReconForge distinguishes direct observations from vulnerability hypotheses:

- `CONFIRMED_OBSERVED` — directly captured evidence; report it.
- `CONFIRMED_DERIVED` — deterministic derivation; report it.
- `SCANNER_REPORTED` — scanner signal without a deterministic validator; report as such.
- `NEEDS_VALIDATION` — vulnerability-specific candidate such as a historical CVE.
- `FALSE_POSITIVE` — explicitly rejected; suppress it.

The HTML report also includes a **Why ReconForge Did NOT Report This** section for suppressed candidates.

## Burp-style web crawl + audit (4.3)

Safe audit-only run:

```bash
python3 -m reconforge https://<AUTHORIZED_TARGET> --authorized --audit-only
```

Normal web assessment with bounded crawling:

```bash
python3 -m reconforge https://<AUTHORIZED_TARGET> \\
  --authorized \\
  --mode deep \\
  --crawl-depth 3 \\
  --crawl-pages 100 \\
  --crawl-rate 2 \\
  --crawl-concurrency 4
```

Disable crawling when you only want the legacy scanner flow:

```bash
python3 -m reconforge https://<AUTHORIZED_TARGET> --authorized --no-crawl
```

The HTML/JSON report now includes crawl coverage, observed findings, candidate findings that still need manual validation, remediation guidance, and a manual-review queue. Forms are discovered but never submitted by the crawler.

## 4.4 methodology coverage

For a Burp/AppScan-style web audit with methodology mapping:

```bash
python3 -m reconforge https://YOUR-AUTHORIZED-TARGET \
  --authorized \
  --audit-only \
  --methodology all \
  --crawl-depth 3 \
  --crawl-pages 100
```

Open `report.html` and see **METHODOLOGY COVERAGE** for OWASP Top 10:2025 and MITRE CWE Top 25:2025, plus the manual/source-review queues.

## 4.5 operator workflow

Type `reconforge` with no target to enter the target prompt. ReconForge automatically classifies a URL/API versus a bare IP/hostname and selects the bounded assessment flow. URL/API targets prioritize HTTP/TLS discovery, same-origin crawling, safe audit, Nuclei/Wapiti, content discovery, and parameter review; bare IP targets start with Nmap service discovery and enable web/TLS checks only when a web surface is detected.

After scanning, ReconForge asks whether the final report should be HTML, PDF, or skipped. The operator report contains findings only: why each finding was reported, evidence state, affected endpoint, OWASP/CWE mapping, description/impact/remediation for confirmed observations, manual-validation guidance for candidates, and the command(s) used. Raw scanner JSON is not embedded in the report. Suppressed/false-positive candidates are listed with only a concise reason.

Direct command forms remain supported:

```bash
reconforge https://app.example.test --authorized
reconforge 192.0.2.10 --authorized
reconforge 192.0.2.10:8080 --authorized
```
