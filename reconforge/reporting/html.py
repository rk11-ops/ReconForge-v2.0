from __future__ import annotations

import html
from pathlib import Path
from typing import Any

REPORT_TYPES = {
    "web": {
        "title": "Web Application Security Assessment",
        "surface": "Web application",
        "accent": "#dc2626",
    },
    "network": {
        "title": "Network Security Assessment",
        "surface": "Network / infrastructure",
        "accent": "#dc2626",
    },
    "api": {
        "title": "API Security Assessment",
        "surface": "API",
        "accent": "#dc2626",
    },
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {sev: sum(1 for f in findings if str(f.get("severity", "")).lower() == sev) for sev in SEVERITY_ORDER}


def _is_confirmed(f: dict[str, Any]) -> bool:
    state = str(f.get("evidence_state") or "").upper()
    validation = str(f.get("validation_status") or "").lower()
    return state in {"CONFIRMED_OBSERVED", "CONFIRMED_DERIVED"} or validation in {"confirmed", "corroborated"}


def _finding_reason(f: dict[str, Any]) -> str:
    return str(f.get("why_reported") or "Observed by the ReconForge evidence pipeline.")


def _finding_commands(f: dict[str, Any]) -> str:
    commands = f.get("source_commands") or {}
    if not commands:
        return "No external command; built-in ReconForge observation."
    blocks = []
    for source, command in commands.items():
        blocks.append(
            f"<div class='command'><div class='command-source'>{_escape(source)}</div><pre>{_escape(command)}</pre></div>"
        )
    return "".join(blocks)


def _finding_card(idx: int, f: dict[str, Any]) -> str:
    sev = str(f.get("severity") or "info").lower()
    endpoint = f.get("endpoint") or (f.get("endpoints") or ["-"])[0]
    sources = ", ".join(f.get("sources") or []) or "ReconForge audit"
    evidence_state = f.get("evidence_state") or "SCANNER_REPORTED"
    owasp = f.get("owasp_category") or f.get("owasp_2025_id") or "Not mapped"
    cwe = f.get("cwe") or f.get("cwe_top25_2025_id") or "Not mapped"
    status = "Confirmed evidence" if _is_confirmed(f) else "Validation required"

    parts = [
        f"<article class='finding'>",
        f"<div class='finding-head'><div><span class='severity sev-{_escape(sev)}'>{_escape(sev.upper())}</span> <span class='status'>{_escape(status)}</span></div><h3>{idx}. {_escape(f.get('name') or 'Unnamed finding')}</h3></div>",
        "<div class='facts'>",
        f"<div><b>Affected endpoint</b><span>{_escape(endpoint)}</span></div>",
        f"<div><b>Why this was reported</b><span>{_escape(_finding_reason(f))}</span></div>",
        f"<div><b>Evidence state</b><span>{_escape(evidence_state)}</span></div>",
        f"<div><b>Source(s)</b><span>{_escape(sources)}</span></div>",
        f"<div><b>OWASP / CWE</b><span>{_escape(owasp)} / {_escape(cwe)}</span></div>",
        "</div>",
    ]

    if _is_confirmed(f):
        description = f.get("description") or f"{f.get('name')} was directly observed or deterministically derived from assessment evidence."
        impact = f.get("impact") or "The observed weakness can affect the application's security boundary or expose protected functionality/data depending on context."
        remediation = f.get("remediation") or "Apply the appropriate security control and retest the affected endpoint."
        parts.extend([
            f"<section><h4>Description</h4><p>{_escape(description)}</p></section>",
            f"<section><h4>Impact</h4><p>{_escape(impact)}</p></section>",
            f"<section><h4>Remediation</h4><p>{_escape(remediation)}</p></section>",
        ])
    else:
        guidance = f.get("manual_validation") or "Validate the candidate in a controlled authorized workflow before treating it as confirmed."
        parts.append(f"<section><h4>Manual validation</h4><p>{_escape(guidance)}</p></section>")

    parts.append(f"<section><h4>Command used</h4>{_finding_commands(f)}</section>")
    parts.append("</article>")
    return "".join(parts)


def _suppressed(report: dict[str, Any]) -> str:
    items = report.get("not_reported", [])
    if not items:
        return "<p class='muted'>No findings were suppressed in this run.</p>"
    rows = []
    for item in items:
        candidate = item.get("candidate") or "Unnamed candidate"
        reason = item.get("reason") or "Not reproduced by validation."
        rows.append(f"<tr><td>{_escape(candidate)}</td><td>{_escape(reason)}</td></tr>")
    return "<table class='suppressed'><thead><tr><th>Check</th><th>Why it was not reported</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def write_reports(report: dict[str, Any], output_dir: Path, html_enabled: bool = True) -> dict[str, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    if not html_enabled:
        return paths

    meta = report.get("meta", {})
    report_type = meta.get("report_type", "web")
    config = REPORT_TYPES.get(report_type, REPORT_TYPES["web"])
    findings = report.get("findings", [])
    counts = _counts(findings)
    target = meta.get("target") or "-"
    date = str(meta.get("started_at") or "")[:10] or "-"

    cards = "".join(_finding_card(i, f) for i, f in enumerate(findings, start=1))
    if not cards:
        cards = "<div class='empty'>No reportable findings were identified by the configured assessment pipeline.</div>"

    page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconForge - {_escape(config['title'])}</title>
<style>
:root {{--accent:{config['accent']};--ink:#e5e7eb;--muted:#9ca3af;--bg:#09090b;--panel:#111318;--line:#27272a;--danger:#ef4444;--amber:#f59e0b;--blue:#60a5fa}}
* {{box-sizing:border-box}}
body {{margin:0;background:linear-gradient(180deg,#050507 0%,#0b0d10 100%);color:var(--ink);font-family:Inter,Arial,Helvetica,sans-serif}}
.page {{width:min(1080px,calc(100% - 34px));margin:26px auto 54px}}
.hero {{border:1px solid #3f1111;background:radial-gradient(circle at 15% 20%,rgba(220,38,38,.18),transparent 42%),#0d0e12;padding:24px 25px;box-shadow:0 0 0 1px rgba(255,255,255,.02) inset}}
.brand {{font-size:31px;font-weight:900;letter-spacing:2.5px;color:#f5f5f5}}
.brand span {{color:#ef4444}}
.kicker {{font-size:11px;letter-spacing:2px;color:#ef4444;font-weight:800;margin-bottom:9px}}
.meta {{margin-top:14px;display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:#a1a1aa}}
.meta strong {{color:#e4e4e7}}
h2 {{font-size:15px;letter-spacing:1px;margin:26px 0 11px;color:#f4f4f5;text-transform:uppercase;border-bottom:1px solid var(--line);padding-bottom:8px}}
.summary {{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}}
.metric {{border:1px solid var(--line);background:#0f1115;padding:14px 10px;text-align:center}}
.metric .n {{font-size:25px;font-weight:900}}
.metric .l {{font-size:10px;letter-spacing:1px;color:var(--muted);margin-top:5px}}
.finding {{border:1px solid #292b31;background:linear-gradient(180deg,#111318,#0e1014);margin:14px 0;padding:18px 19px;box-shadow:0 7px 24px rgba(0,0,0,.16)}}
.finding-head h3 {{margin:8px 0 12px;font-size:18px;color:#fafafa}}
.severity,.status {{display:inline-block;font-size:10px;font-weight:900;letter-spacing:1px;padding:4px 8px;border-radius:2px}}
.severity {{background:#1f2937;color:#dbeafe}}
.sev-critical {{background:#7f1d1d;color:#fecaca}}.sev-high {{background:#7c2d12;color:#fed7aa}}.sev-medium {{background:#713f12;color:#fde68a}}.sev-low {{background:#1e3a8a;color:#dbeafe}}.sev-info {{background:#334155;color:#e2e8f0}}
.status {{background:#18181b;color:#a1a1aa;margin-left:5px}}
.facts {{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:10px 0 14px}}
.facts div {{border:1px solid #23252a;background:#0d0f13;padding:10px 11px}}
.facts b {{display:block;font-size:10px;letter-spacing:.8px;text-transform:uppercase;color:#71717a;margin-bottom:5px}}
.facts span {{display:block;font-size:12px;line-height:1.5;overflow-wrap:anywhere}}
section {{margin-top:13px}}h4 {{font-size:12px;letter-spacing:.8px;text-transform:uppercase;color:#fca5a5;margin:0 0 5px}}p {{font-size:13px;line-height:1.62;color:#d4d4d8;margin:0}}
.command {{margin-top:7px}}.command-source {{font-size:10px;color:#a1a1aa;margin-bottom:3px}}pre {{margin:0;padding:10px 11px;border:1px solid #27272a;background:#07080a;color:#d4d4d8;white-space:pre-wrap;overflow-wrap:anywhere;font:11px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
.suppressed {{width:100%;border-collapse:collapse;font-size:12px}}.suppressed th,.suppressed td {{border:1px solid var(--line);padding:9px 10px;text-align:left;vertical-align:top}}.suppressed th {{color:#a1a1aa;font-size:10px;text-transform:uppercase;letter-spacing:.8px;background:#0f1115}}
.muted {{color:var(--muted)}}.empty {{border:1px dashed #33363d;padding:26px;text-align:center;color:#a1a1aa}}
.footer {{margin-top:27px;color:#71717a;font-size:10px;border-top:1px solid var(--line);padding-top:10px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}}
@media(max-width:720px){{.summary{{grid-template-columns:repeat(2,1fr)}}.facts{{grid-template-columns:1fr}}}}
@media print{{body{{background:white;color:#111}}.page{{width:100%;margin:0}}.hero,.finding,.metric{{box-shadow:none;background:white;color:#111}}p,.facts span{{color:#222}}pre{{color:#111;background:#f6f6f6}}}}
</style>
</head>
<body><main class="page">
<header class="hero"><div class="kicker">OFFENSIVE SECURITY ASSESSMENT</div><div class="brand">RECON<span>FORGE</span></div><div style="margin-top:5px;color:#a1a1aa;font-size:12px">{_escape(config['title'])}</div>
<div class="meta"><span><strong>Target</strong> {_escape(target)}</span><span><strong>Type</strong> {_escape(config['surface'])}</span><span><strong>Date</strong> {_escape(date)}</span><span><strong>Mode</strong> {_escape(meta.get('mode') or '-')}</span><span><strong>Scan ID</strong> {_escape(meta.get('scan_id') or '-')}</span></div></header>

<h2>Findings</h2>
<section class="summary">
<div class="metric"><div class="n">{counts['critical']}</div><div class="l">Critical</div></div>
<div class="metric"><div class="n">{counts['high']}</div><div class="l">High</div></div>
<div class="metric"><div class="n">{counts['medium']}</div><div class="l">Medium</div></div>
<div class="metric"><div class="n">{counts['low']}</div><div class="l">Low</div></div>
<div class="metric"><div class="n">{len(findings)}</div><div class="l">Total</div></div>
</section>
{cards}

<h2>Suppressed / False-Positive Checks</h2>
{_suppressed(report)}

<footer class="footer"><span>ReconForge 4.5.0</span><span>Raw scanner payloads are intentionally excluded from the operator report.</span></footer>
</main></body></html>'''
    html_path = output_dir / "report.html"
    html_path.write_text(page, encoding="utf-8")
    paths["html"] = html_path
    return paths
