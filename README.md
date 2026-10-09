# ReconForge 4.5.0

# ReconForge — Advanced Evidence-Driven Recon CLI

ReconForge is a modular, CLI-first reconnaissance and authorized security-assessment orchestrator.
## 4.2 improvements

- Direct target handling: URL, hostname, IPv4/IPv6, and schemeless `host:port`.
- Explicit ports from a URL/`host:port` are carried into focused Nmap discovery.
- HTTP response metadata is now first-class evidence: high-signal header, cookie, CORS, and TLS verification observations enter the same normalizer/correlator as scanner findings.
- Adaptive SQLMap actions preserve the full parameterized URL and are dispatched through the existing bounded SQLMap runner.
- Initial recon and web-validation workers execute with bounded parallelism.
- Each run gets a SHA-256 evidence manifest for artifacts, logs, command records, and local Qwen output.

 The key design is **evidence-driven sequencing**: scanners are workers, the evidence layer builds a shared attack-surface model, the adaptive engine chooses follow-up work, validators try to reproduce deterministic issues, and a quality gate decides what is reportable.

## Architecture

```text
reconforge/
├── cli.py
├── config.py
├── models.py
├── utils.py
│
├── engine/
│   ├── orchestrator.py
│   ├── scheduler.py
│   ├── state.py
│   └── lifecycle.py
│
├── scanners/
│   ├── base.py
│   ├── nmap.py
│   ├── nikto.py
│   ├── wapiti.py
│   ├── nuclei.py
│   ├── ffuf.py
│   ├── sqlmap.py
│   └── http_probe.py
│
├── evidence/
│   ├── engine.py
│   ├── graph.py
│   ├── normalize.py
│   └── correlate.py
│
├── adaptive/
│   ├── rules.py
│   └── decision_engine.py
│
├── validation/
│   ├── headers.py
│   ├── tls.py
│   ├── cookies.py
│   └── findings.py
│
├── reporting/
│   ├── builder.py
│   └── html.py
│
└── ai/
    └── qwen.py
```

## Runtime pipeline

```text
PRECHECK
  ↓
1. RECON DISCOVERY
  └── Nmap
  ↓
2. WEB VALIDATION
  └── Nikto → Wapiti → Nuclei → ffuf/Feroxbuster
  ↓
EVIDENCE ENGINE
  └── attack surface + endpoint inventory + normalized candidates
  ↓
3. ADAPTIVE FOLLOW-UP
  ├── technology-focused Nuclei
  ├── API-path content discovery
  └── parameterized-endpoint eligibility for SQLMap
  ↓
4. SAFE VALIDATION + PoC GATE
  ├── headers
  ├── cookies
  ├── TLS
  └── bounded SQLMap
  ↓
5. QUALITY GATE + CORRELATION
  ├── confirmed/corroborated → reportable
  └── scanner-only/unverified → Why ReconForge Did NOT Report This
  ↓
6. REPORTING
  ├── report.json
  ├── report.html
  └── optional Qwen GGUF summary
```

## Why it is different from a simple scanner wrapper

ReconForge does not treat tool output as the final answer. Each adapter returns a common `ToolResult`; `EvidenceEngine` merges those results into an evidence graph; `AdaptiveDecisionEngine` converts evidence into bounded next actions; validation adds a second proof layer; and the reporting gate keeps unverified candidates out of the main finding list.

## CLI usage

The safest first run is a dry-run. It shows the real command line without starting scanner processes or passive network probes:

```bash
python3 reconforge.py 127.0.0.1 \
  --authorized \
  --mode advanced \
  --dry-run

Direct URL / custom port targets are supported:

```bash
python3 reconforge.py https://app.example.test:8443/api/v1 --authorized --mode deep
python3 reconforge.py 192.0.2.10:8080 --authorized --mode basic
```
```

You will see lines such as:

```text
=== STAGE 1/6 • RECON DISCOVERY ===
COMMAND > nmap -Pn -T4 -sV -O -p- -oX ... 127.0.0.1

=== STAGE 2/6 • WEB VALIDATION ===
COMMAND > nikto -host http://127.0.0.1 ...
COMMAND > wapiti -u http://127.0.0.1 ...
COMMAND > nuclei -u http://127.0.0.1 ...
COMMAND > ffuf -w ... -u http://127.0.0.1/FUZZ ...
```

Each real command is copied into that run's `commands/` directory.

## Kali install

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

sudo apt update
sudo apt install nmap nikto wapiti sqlmap ffuf feroxbuster seclists
```

Verify:

```bash
command -v nmap nikto wapiti sqlmap ffuf feroxbuster nuclei
```

## Advanced assessment

```bash
python3 reconforge.py 127.0.0.1 \
  --authorized \
  --scope scope.example.txt \
  --mode advanced \
  --fuzzer feroxbuster \
  --sqlmap auto \
  --report yes
```

For a parameterized endpoint that has already been discovered, bounded SQLMap can be explicitly forced:

```bash
python3 reconforge.py 'https://app.example.test/item?id=1' \
  --authorized \
  --mode advanced \
  --sqlmap force
```

The SQLMap adapter caps the profile at low risk and does not expose dump, shell, or file-read/write post-exploitation flags.

## Nmap controls

```text
--nmap-scan-type {S,T,U,A,W,M}
--nmap-service
--nmap-os
--nmap-aggressive
--nmap-no-ping
--nmap-ports 80,443,8000-8100
--nmap-web-ports
--nmap-script http-title,http-headers
--nmap-script-args '...'
--nmap-arg=--reason
```

ReconForge reserves machine-readable output flags so the framework-owned XML artifact is not replaced by an operator argument.

## Qwen 4B GGUF

The Qwen component is optional and local. It is a **presentation/triage layer only**; the deterministic engine remains authoritative.

```bash
python3 reconforge.py 127.0.0.1 \
  --authorized \
  --mode advanced \
  --qwen-gguf ~/models/qwen4b.gguf
```

A ZIP containing the GGUF is accepted too:

```bash
python3 reconforge.py 127.0.0.1 \
  --authorized \
  --mode advanced \
  --qwen-gguf ~/models/qwen4b-gguf.zip
```

By default the module looks for `llama-cli`; override it with:

```text
--qwen-bin /path/to/llama-cli
```

The exact local model command is printed as:

```text
COMMAND > llama-cli -m /path/qwen4b.gguf ...
```

## Output

```text
reconforge-results/
└── <host>-<mode>-<scan-id>/
    ├── artifacts/
    ├── logs/
    ├── commands/
    ├── evidence/
    ├── state.json
    ├── report.json
    ├── report.html
    └── qwen-summary.txt
```

The persistent `.history/latest/` snapshot stores enough normalized state to show attack-surface changes between repeated runs.

## Validation and false-positive control

Deterministic checks such as clickjacking, CSP, CORS, cookie flags, directory listing, verbose-error markers, and TLS observations are rechecked with lightweight requests/handshakes. Non-deterministic classes are not presented as confirmed from one scanner hit; they need independent corroboration before entering the main report.

The final HTML report includes:

```text
Why ReconForge Did NOT Report This
```

with the candidate, severity, validation state, and suppression reason.

## Development checks

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
```

Tests are offline/synthetic and do not attack a network target.

## Safety boundary

Use only on assets you are explicitly authorized to assess. The CLI enforces an authorization flag, supports scope files, uses non-shell process execution, limits concurrency, applies process timeouts, and keeps SQLMap in a bounded validation configuration.

## Report templates

ReconForge selects a report template by assessment type. Use `--report-type auto` (default) to infer `web`, `api`, or `network`, or explicitly choose one:

```bash
python3 reconforge.py https://app.example.test --authorized --report-type web
python3 reconforge.py 192.0.2.10 --authorized --report-type network
python3 reconforge.py https://api.example.test/api/v1 --authorized --report-type api
```

The generated HTML report follows the supplied template structure: `EXECUTIVE SUMMARY`, `VULNERABILITY OVERVIEW`, `FINDINGS LOG`, and `Scope & Methodology`, with the findings-table category column adjusted for web/API/network assessments.

## testssl.sh integration

ReconForge integrates the official `testssl.sh` project as a TLS/SSL assessment worker. The upstream project supports TLS/SSL protocol, cipher, certificate, HTTP-header and vulnerability checks and provides machine-readable JSON output. See the upstream documentation for current options. https://github.com/testssl/testssl.sh

Install it from the official GitHub repository:

```bash
./scripts/install_testssl.sh
```

The equivalent upstream clone is:

```bash
git clone --depth 1 https://github.com/testssl/testssl.sh.git tools/testssl.sh
chmod +x tools/testssl.sh/testssl.sh
```

Or point ReconForge to an existing executable:

```bash
python3 reconforge.py https://app.example.test --authorized --testssl-path ~/tools/testssl.sh/testssl.sh
```

For an HTTPS URL ReconForge runs testssl.sh during the web/TLS stage. For a raw IP/host network assessment, it can select an open TLS service discovered by Nmap (for example 443 or 8443). The raw JSON artifact is stored under `artifacts/testssl.json`.


## One-command workflow

Install once on Kali:

```bash
chmod +x scripts/install_reconforge.sh
./scripts/install_reconforge.sh
```

Then simply run:

```bash
reconforge
```

ReconForge prompts for the authorized target once. It infers network/IP versus web versus API-like input, runs the relevant toolchain, and prints every external command as `COMMAND > ...`. Use `--mode basic`, `--mode deep`, or `--mode advanced` to change depth; advanced is the default.


### Fastest operator flow

After installing, the shortest command is:

```bash
reconforge
```

Enter the authorized target when prompted. ReconForge infers `network`, `web`, or `api`, starts with Nmap, then enables web tooling only when HTTP/TLS exposure is actually discovered. `advanced` is the default; `--mode basic` and `--mode deep` remain available.

Nmap NSE coverage is selected from the locally installed Nmap script catalog: `basic` uses `default,discovery,safe`; `deep` adds `vuln`; `advanced` selects all local NSE categories except `brute`, `dos`, `exploit`, and `intrusive`. A filtering/rate-limit signal schedules an adaptive `-T3` retry after the initial `-T4` discovery. Advanced mode also uses Nmap `-A`.

Every external command is printed as `COMMAND > ...` and saved under the run's `commands/` directory.


### One-time Kali toolchain bootstrap

To install the scanner toolchain in one step:

```bash
chmod +x scripts/bootstrap_kali.sh
./scripts/bootstrap_kali.sh
```

This installs the common ReconForge command-line dependencies and pulls the local testssl.sh dependency. After that, the operator command remains simply `reconforge`.


## 4.1.2 finding-pipeline fix

ReconForge now distinguishes direct observations from vulnerability hypotheses.
Structured scanner findings keep identifiers and evidence state, and the quality gate reports scanner-observed candidates instead of hiding them solely because a second validator was not available. Vulnerability-specific claims such as historical CVEs remain explicitly marked `NEEDS_VALIDATION`.

## Burp-style crawl + audit mode (4.3)

For a web-first assessment, ReconForge now performs a bounded same-origin crawl and safe audit. It discovers links, resources, forms, query parameters, API documentation markers, and common security-control weaknesses. Forms are never submitted by the crawler. Candidate classes such as CSRF, reflected input/XSS, open redirect, and SSRF are reported as `NEEDS_VALIDATION` rather than exploited.

Safe web audit only:

```bash
python3 -m reconforge https://app.example.test --authorized --audit-only
```

Tune the crawler:

```bash
python3 -m reconforge https://app.example.test --authorized \
  --crawl-depth 3 --crawl-pages 100 --crawl-rate 2 --crawl-concurrency 4
```

The report contains:

- crawl coverage and discovered endpoints/forms
- observed vulnerabilities/misconfigurations with evidence state
- candidate findings requiring manual validation
- manual validation guidance (without exploit payloads)
- remediation guidance
- a manual-review queue for authentication, authorization/IDOR/BOLA, privilege boundaries, uploads, business logic, and rate limiting

## OWASP Top 10:2025 + CWE Top 25:2025 methodology coverage

ReconForge 4.4 adds a versioned methodology engine inspired by enterprise DAST workflows: **Explore → observe → run safe/deterministic checks → classify → provide manual validation guidance**. It does not submit exploit payloads or perform destructive proof-of-concept actions as part of this methodology layer.

The default pack is:

- OWASP Top 10:2025 (all 10 categories)
- MITRE CWE Top 25:2025 (all 25 weaknesses)

> Note: the current official Top 25 is maintained by MITRE as the **CWE Top 25**. "SANS Top 25" is a common informal label in some training material; ReconForge uses the current MITRE 2025 list as the canonical source.

Run all methodology mappings (default):

```bash
python3 -m reconforge https://YOUR-AUTHORIZED-TARGET --authorized --methodology all
```

OWASP only:

```bash
python3 -m reconforge https://YOUR-AUTHORIZED-TARGET --authorized --methodology owasp-top10-2025
```

CWE Top 25 only:

```bash
python3 -m reconforge https://YOUR-AUTHORIZED-TARGET --authorized --methodology cwe-top25-2025
```

Each finding can carry:

- `owasp_2025_id` / `owasp_2025_name`
- `cwe_top25_2025_rank` / `cwe_top25_2025_id`
- `methodology_status`

The report also contains a coverage matrix. Statuses deliberately distinguish **detected**, **candidate**, **review/manual**, **source-review**, and **not observed**. "Not observed" does not mean the application is secure for that category.

### What is realistically testable dynamically

DAST can directly observe many web misconfigurations and input/response signals. Other items—especially memory-safety weaknesses such as out-of-bounds access, use-after-free, and buffer overflows—are primarily source-code, binary-analysis, fuzzing, or runtime-instrumentation concerns. ReconForge therefore marks those as source-review rather than pretending a normal web crawl proved them.

Likewise, access-control, authentication, business-logic, and resource-limit weaknesses often need approved identities and workflow-specific validation. ReconForge inventories the relevant surfaces and provides a manual review queue instead of changing state or exploiting them.

### Enterprise DAST-style workflow

HCL AppScan's public DAST documentation describes an Explore stage that crawls the application, analyzes responses for potential vulnerabilities, and then a Test stage that sends generated site-specific tests and validates responses. ReconForge follows the same high-level separation concept, but its 4.4 methodology pack is intentionally bounded to passive observation, deterministic checks, and non-destructive candidate discovery; manual validation is left to the operator. See `docs/METHODOLOGY_2025.md` for the exact coverage philosophy.

## 4.5 operator workflow

Type `reconforge` with no target to enter the target prompt. ReconForge automatically classifies a URL/API versus a bare IP/hostname and selects the bounded assessment flow. URL/API targets prioritize HTTP/TLS discovery, same-origin crawling, safe audit, Nuclei/Wapiti, content discovery, and parameter review; bare IP targets start with Nmap service discovery and enable web/TLS checks only when a web surface is detected.

After scanning, ReconForge asks whether the final report should be HTML, PDF, or skipped. The operator report contains findings only: why each finding was reported, evidence state, affected endpoint, OWASP/CWE mapping, description/impact/remediation for confirmed observations, manual-validation guidance for candidates, and the command(s) used. Raw scanner JSON is not embedded in the report. Suppressed/false-positive candidates are listed with only a concise reason.

Direct command forms remain supported:

```bash
reconforge https://app.example.test --authorized
reconforge 192.0.2.10 --authorized
reconforge 192.0.2.10:8080 --authorized
```

## 4.5 operator report UX

Running `reconforge` with no target prompts for the target and auto-classifies URLs/APIs versus bare IP/host targets. After scanning, the operator is asked to generate HTML, PDF, or no final report. Final reports contain findings, concise report rationale, evidence state, endpoint, OWASP/CWE mapping, description/impact/remediation for confirmed findings, manual-validation guidance for candidates, and source command(s). Raw scanner payloads are not embedded. Suppressed/false-positive items receive only a concise reason.
