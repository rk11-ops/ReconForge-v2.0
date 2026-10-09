from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from typing import Any

OWASP_TOP10_2025 = [
    {"id": "A01:2025", "name": "Broken Access Control", "web_testable": True, "guidance": "Compare access decisions across approved roles/accounts and review object/function authorization boundaries."},
    {"id": "A02:2025", "name": "Security Misconfiguration", "web_testable": True, "guidance": "Review security headers, error handling, default content, exposed files, dangerous methods, TLS and deployment configuration."},
    {"id": "A03:2025", "name": "Software Supply Chain Failures", "web_testable": True, "guidance": "Inspect exposed dependency/version signals and, where source/build metadata is available, review dependency provenance, integrity and CI/CD controls."},
    {"id": "A04:2025", "name": "Cryptographic Failures", "web_testable": True, "guidance": "Review transport security, certificate validation, cookie transport, sensitive data exposure and cryptographic configuration."},
    {"id": "A05:2025", "name": "Injection", "web_testable": True, "guidance": "Inventory parameters and inputs, identify reflection/error signals, then manually validate the appropriate interpreter context."},
    {"id": "A06:2025", "name": "Insecure Design", "web_testable": False, "guidance": "Review trust boundaries, abuse cases, business rules and architecture; dynamic scanning can surface clues but cannot prove design flaws comprehensively."},
    {"id": "A07:2025", "name": "Authentication Failures", "web_testable": True, "guidance": "Review authentication flows, session cookies, logout/reset/MFA behavior and lockout controls with approved test identities."},
    {"id": "A08:2025", "name": "Software or Data Integrity Failures", "web_testable": False, "guidance": "Review update/deployment integrity, signed artifacts, deserialization and trust-boundary enforcement; source/build evidence is often required."},
    {"id": "A09:2025", "name": "Security Logging & Alerting Failures", "web_testable": False, "guidance": "Review application/security logging, alert generation, audit trails and incident-detection workflows; runtime evidence or source/config review is needed."},
    {"id": "A10:2025", "name": "Mishandling of Exceptional Conditions", "web_testable": True, "guidance": "Review error paths, malformed-input handling, fail-open behavior, inconsistent status handling and resource exhaustion controls."},
]

# Canonical current list: MITRE's 2025 CWE Top 25. This is often informally called the
# "SANS Top 25" in training material, but the current official Top 25 is maintained by MITRE CWE.
CWE_TOP25_2025 = [
    {"rank": 1, "id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "dynamic": "candidate"},
    {"rank": 2, "id": "CWE-89", "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "dynamic": "candidate"},
    {"rank": 3, "id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "dynamic": "candidate"},
    {"rank": 4, "id": "CWE-862", "name": "Missing Authorization", "dynamic": "manual"},
    {"rank": 5, "id": "CWE-787", "name": "Out-of-bounds Write", "dynamic": "source"},
    {"rank": 6, "id": "CWE-22", "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "dynamic": "candidate"},
    {"rank": 7, "id": "CWE-416", "name": "Use After Free", "dynamic": "source"},
    {"rank": 8, "id": "CWE-125", "name": "Out-of-bounds Read", "dynamic": "source"},
    {"rank": 9, "id": "CWE-78", "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "dynamic": "candidate"},
    {"rank": 10, "id": "CWE-94", "name": "Improper Control of Generation of Code ('Code Injection')", "dynamic": "candidate"},
    {"rank": 11, "id": "CWE-120", "name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')", "dynamic": "source"},
    {"rank": 12, "id": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type", "dynamic": "manual"},
    {"rank": 13, "id": "CWE-476", "name": "NULL Pointer Dereference", "dynamic": "source"},
    {"rank": 14, "id": "CWE-121", "name": "Stack-based Buffer Overflow", "dynamic": "source"},
    {"rank": 15, "id": "CWE-502", "name": "Deserialization of Untrusted Data", "dynamic": "candidate"},
    {"rank": 16, "id": "CWE-122", "name": "Heap-based Buffer Overflow", "dynamic": "source"},
    {"rank": 17, "id": "CWE-863", "name": "Incorrect Authorization", "dynamic": "manual"},
    {"rank": 18, "id": "CWE-20", "name": "Improper Input Validation", "dynamic": "candidate"},
    {"rank": 19, "id": "CWE-284", "name": "Improper Access Control", "dynamic": "manual"},
    {"rank": 20, "id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "dynamic": "candidate"},
    {"rank": 21, "id": "CWE-306", "name": "Missing Authentication for Critical Function", "dynamic": "manual"},
    {"rank": 22, "id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "dynamic": "candidate"},
    {"rank": 23, "id": "CWE-77", "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')", "dynamic": "candidate"},
    {"rank": 24, "id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key", "dynamic": "manual"},
    {"rank": 25, "id": "CWE-770", "name": "Allocation of Resources Without Limits or Throttling", "dynamic": "manual"},
]

CWE_INDEX = {x["id"]: x for x in CWE_TOP25_2025}

# Existing ReconForge rule IDs mapped to 2025 OWASP root categories.
RULE_MAP = {
    "RF-WEB-001": ("A01:2025", "A01:2025 Broken Access Control"),
    "RF-WEB-002": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-003": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-004": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-005": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-006": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-007": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-008": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-009": ("A07:2025", "A07:2025 Authentication Failures"),
    "RF-WEB-010": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-011": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-012": ("A10:2025", "A10:2025 Mishandling of Exceptional Conditions"),
    "RF-WEB-013": ("A01:2025", "A01:2025 Broken Access Control"),
    "RF-WEB-014": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-015": ("A04:2025", "A04:2025 Cryptographic Failures"),
    "RF-WEB-016": ("A04:2025", "A04:2025 Cryptographic Failures"),
    "RF-WEB-017": ("A01:2025", "A01:2025 Broken Access Control"),
    "RF-WEB-018": ("A05:2025", "A05:2025 Injection"),
    "RF-WEB-019": ("A01:2025", "A01:2025 Broken Access Control"),
    "RF-WEB-020": ("A01:2025", "A01:2025 Broken Access Control"),
    "RF-WEB-021": ("A02:2025", "A02:2025 Security Misconfiguration"),
    "RF-WEB-022": ("A01:2025", "A01:2025 Broken Access Control"),
    "RF-WEB-023": ("A02:2025", "A02:2025 Security Misconfiguration"),
}

CWE_TO_OWASP = {
    "CWE-79": "A05:2025", "CWE-89": "A05:2025", "CWE-352": "A01:2025",
    "CWE-862": "A01:2025", "CWE-787": "A05:2025", "CWE-22": "A01:2025",
    "CWE-416": "A10:2025", "CWE-125": "A10:2025", "CWE-78": "A05:2025",
    "CWE-94": "A05:2025", "CWE-120": "A10:2025", "CWE-434": "A01:2025",
    "CWE-476": "A10:2025", "CWE-121": "A10:2025", "CWE-502": "A08:2025",
    "CWE-122": "A10:2025", "CWE-863": "A01:2025", "CWE-20": "A05:2025",
    "CWE-284": "A01:2025", "CWE-200": "A01:2025", "CWE-306": "A07:2025",
    "CWE-918": "A01:2025", "CWE-77": "A05:2025", "CWE-639": "A01:2025",
    "CWE-770": "A10:2025",
}

OWASP_BY_ID = {x["id"]: x for x in OWASP_TOP10_2025}

def _clean_cwe(value: Any) -> str | None:
    if not value:
        return None
    import re
    m = re.search(r"CWE-?\d+", str(value), re.I)
    return m.group(0).upper().replace("CWE-", "CWE-") if m else None


def methodology_annotations(finding: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(finding.get("rule_id") or "")
    cwe = _clean_cwe(finding.get("cwe") or finding.get("identifier"))
    owasp_id, owasp_label = RULE_MAP.get(rule_id, (None, None))
    if not owasp_id and cwe:
        owasp_id = CWE_TO_OWASP.get(cwe)
        owasp_label = f"{owasp_id} {OWASP_BY_ID[owasp_id]['name']}" if owasp_id else None
    if not owasp_id:
        raw = str(finding.get("owasp_category") or "")
        for item in OWASP_TOP10_2025:
            if item["id"] in raw or item["name"].lower() in raw.lower():
                owasp_id = item["id"]
                owasp_label = f"{item['id']} {item['name']}"
                break
    top25 = CWE_INDEX.get(cwe) if cwe else None
    out = {
        "owasp_2025_id": owasp_id,
        "owasp_2025_name": OWASP_BY_ID[owasp_id]["name"] if owasp_id in OWASP_BY_ID else None,
        "cwe_top25_2025_rank": top25["rank"] if top25 else None,
        "cwe_top25_2025_id": top25["id"] if top25 else None,
        "cwe_top25_2025_name": top25["name"] if top25 else None,
        "methodology_status": "mapped" if (owasp_id or top25) else "unmapped",
    }
    return out


def _status_for_owasp(item: dict[str, Any], findings: list[dict[str, Any]], pages: list[dict[str, Any]]) -> tuple[str, int, str]:
    fid = item["id"]
    hits = [f for f in findings if f.get("owasp_2025_id") == fid]
    if hits:
        strong = any(f.get("evidence_state") in {"CONFIRMED_OBSERVED", "CONFIRMED_DERIVED"} for f in hits)
        return ("detected" if strong else "candidate"), len(hits), f"{len(hits)} mapped finding(s)"
    if fid == "A07:2025" and any(p.get("forms") for p in pages):
        return "review", 0, "Authentication/session surfaces discovered; controlled identity testing is required."
    if fid == "A01:2025" and any((p.get("forms") or p.get("url")) for p in pages):
        return "review", 0, "Access-control weaknesses require comparison across authorized identities and functions."
    if fid in {"A05:2025", "A10:2025"} and pages:
        return "review", 0, "Input/error surfaces observed; safe dynamic signals exist but full weakness confirmation is context-dependent."
    if not item.get("web_testable"):
        return "manual/source-review", 0, "Not reliably provable from unauthenticated GET crawling alone."
    return "not_observed", 0, "No mapped evidence observed in this run."


def build_methodology_coverage(*, findings: list[dict[str, Any]], pages: list[dict[str, Any]] | None = None, selected: str = "all") -> dict[str, Any]:
    pages = pages or []
    enriched = []
    for f in findings:
        item = dict(f)
        item.update(methodology_annotations(item))
        enriched.append(item)
    selected_owasp = selected in {"all", "owasp-top10-2025"}
    selected_cwe = selected in {"all", "cwe-top25-2025"}
    owasp = []
    if selected_owasp:
        for item in OWASP_TOP10_2025:
            status, count, detail = _status_for_owasp(item, enriched, pages)
            owasp.append({**item, "status": status, "finding_count": count, "detail": detail})
    cwe_rows = []
    if selected_cwe:
        for item in CWE_TOP25_2025:
            hits = [f for f in enriched if f.get("cwe_top25_2025_id") == item["id"]]
            if hits:
                evidence = "confirmed/derived" if any(f.get("evidence_state") in {"CONFIRMED_OBSERVED", "CONFIRMED_DERIVED"} for f in hits) else "candidate/scanner"
                status = "detected" if evidence == "confirmed/derived" else "candidate"
                detail = f"{len(hits)} mapped finding(s); evidence={evidence}."
            elif item["dynamic"] == "source":
                status = "source-review"
                detail = "Primarily a code/runtime-memory weakness; dynamic web crawling alone cannot establish root cause."
            elif item["dynamic"] == "manual":
                status = "manual-review"
                detail = "Requires controlled workflow, authorization comparison, upload behavior or resource-limit testing."
            else:
                status = "not_observed"
                detail = "No mapped evidence observed in this run."
            cwe_rows.append({**item, "status": status, "finding_count": len(hits), "detail": detail})
    counts = Counter(x["status"] for x in owasp + cwe_rows)
    return {
        "selected": selected,
        "source": {
            "owasp": "OWASP Top 10:2025",
            "cwe": "MITRE CWE Top 25:2025",
            "note": "The current official Top 25 is MITRE CWE Top 25; 'SANS Top 25' is a common informal label in training material.",
        },
        "owasp_top10_2025": owasp,
        "cwe_top25_2025": cwe_rows,
        "finding_mappings": enriched,
        "summary": {
            "owasp_categories": len(owasp),
            "cwe_entries": len(cwe_rows),
            "detected": counts.get("detected", 0),
            "candidate": counts.get("candidate", 0),
            "review": counts.get("review", 0) + counts.get("manual-review", 0),
            "manual_or_source_review": counts.get("manual/source-review", 0) + counts.get("source-review", 0),
            "not_observed": counts.get("not_observed", 0),
        },
    }


def apply_methodology_annotations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for finding in findings:
        item = dict(finding)
        annotations = methodology_annotations(item)
        item.update(annotations)
        if annotations.get("owasp_2025_id") and annotations.get("owasp_2025_name"):
            item["owasp_category"] = f"{annotations['owasp_2025_id']} {annotations['owasp_2025_name']}"
        out.append(item)
    return out
