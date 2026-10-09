from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlparse


MANUAL_GUIDANCE = {
    "sql-injection": "Review the affected parameter in a controlled test account and determine whether input reaches a database query without safe parameterization. Do not treat scanner output as proof of exploitability.",
    "xss": "Determine the output context and whether user-controlled input is reflected or stored without correct context-sensitive encoding. Validate only in an isolated authorized workflow.",
    "ssrf": "Review the server-side fetch path and verify that destination URLs are constrained and internal network access is denied by policy and egress controls.",
    "cors": "Determine whether the endpoint exposes sensitive data and whether the application intentionally permits the observed cross-origin policy. Verify browser-enforced credential behavior before rating impact.",
    "csrf": "Use a controlled authenticated workflow to confirm that state-changing requests require an appropriate anti-CSRF defense or equivalent browser-origin protection.",
    "clickjacking": "Verify framing behavior with a controlled browser test and identify whether sensitive authenticated content can be embedded by an untrusted origin.",
    "directory-listing": "Review the exposed directory contents and confirm that all listed resources are intentionally public.",
    "sensitive-file-disclosure": "Manually confirm the discovered resource is accessible and determine whether it contains secrets, source, credentials, deployment metadata, or internal documentation. Do not modify the resource.",
    "open-redirect": "Verify that redirect destinations are restricted to approved internal paths or trusted origins and cannot be controlled arbitrarily.",
    "insecure-form": "Confirm the complete credential submission path and ensure no password data is ever sent over an unencrypted connection.",
    "reflected-input": "Identify the response context receiving the input and verify context-sensitive output encoding; a reflection alone does not prove XSS.",
    "verbose-errors": "Repeat the request in a controlled environment and determine whether stack traces, internal paths, framework details, or query information are exposed to untrusted users.",
    "tls": "Review certificate validity, protocol support, cipher configuration, hostname coverage, and trust-chain behavior; distinguish configuration observations from vulnerability claims.",
}

REMEDIATION_GUIDANCE = {
    "sql-injection": "Use parameterized queries/prepared statements and server-side input handling; avoid concatenating untrusted input into database queries.",
    "xss": "Use context-sensitive output encoding and safe templating; adopt a restrictive CSP as a defense in depth.",
    "ssrf": "Use destination allowlists, strict URL parsing, network egress controls, and deny-by-default access to internal address space where applicable.",
    "csrf": "Use framework-supported CSRF defenses for state-changing browser requests and appropriate SameSite cookie settings.",
    "open-redirect": "Allow only approved redirect destinations or use server-side route identifiers instead of arbitrary URLs.",
    "sensitive-file-disclosure": "Remove sensitive artifacts from the web root and add deployment checks preventing accidental publication.",
    "insecure-form": "Serve credential collection exclusively over HTTPS and redirect or reject insecure requests.",
}


IMPACT_GUIDANCE = {
    "sql-injection": "A database query may be influenced by untrusted input, which can expose or alter application data depending on backend controls.",
    "xss": "Untrusted content may execute in a user's browser context, potentially exposing session data or enabling unauthorized actions in that user's context.",
    "reflected-input": "User-controlled input is reflected by the response; if it reaches an executable output context, script execution may become possible.",
    "ssrf": "Server-side requests may be influenced by untrusted input, potentially reaching internal or otherwise protected services.",
    "csrf": "A state-changing action may be triggerable from an unintended origin when the application does not enforce an appropriate browser-origin defense.",
    "clickjacking": "Sensitive pages may be embedded in an untrusted frame if framing protections are absent or insufficient.",
    "cors": "An overly permissive cross-origin policy may expose response data to an unintended origin when other browser conditions allow it.",
    "sensitive-file-disclosure": "Public access to sensitive artifacts can expose credentials, source material, internal metadata, or deployment information.",
    "directory-listing": "Directory indexing can reveal files and paths that were not intended to be discoverable through the web interface.",
    "open-redirect": "An attacker-controlled redirect can be abused for phishing, trust-boundary bypass, or redirect-based workflow abuse.",
    "insecure-form": "Credentials or other sensitive form input may traverse an unencrypted connection and become exposed in transit.",
    "verbose-errors": "Detailed errors can disclose internal paths, framework details, stack traces, or implementation information useful to an attacker.",
    "version-disclosure": "Detailed component version information can make targeted vulnerability matching and attack planning easier.",
    "cookie-flags": "Missing cookie security attributes can increase the exposure of session material to browser-based interception or unintended transmission.",
    "hsts": "Without HSTS, users may remain susceptible to downgrade or first-connection transport attacks when an HTTPS deployment is otherwise expected.",
    "mixed-content": "Insecure subresources can weaken the confidentiality and integrity guarantees of an otherwise HTTPS page.",
    "source-map": "Published source maps can reveal client-side source code structure, internal paths, and implementation details.",
    "cache-control": "Improper shared-cache behavior can expose sensitive responses to unintended users or intermediaries.",
    "self-signed-certificate": "A self-signed certificate is not trusted by normal public trust stores and can cause trust failures or unsafe trust exceptions when used outside a controlled environment.",
    "certificate-mismatch": "The presented certificate does not match the requested hostname, which can break trust validation and indicate a TLS deployment problem.",
    "tls-cipher": "Weak or outdated cryptographic configuration can reduce the security margin of encrypted connections.",
}

def dedupe_ordered(items: Iterable[str]) -> list[str]:
    out=[]; seen=set()
    for item in items:
        if item not in seen:
            seen.add(item); out.append(item)
    return out


def extract_technologies(text: str) -> list[str]:
    low=text.lower()
    mapping={
        "nginx":r"\bnginx\b", "apache":r"\bapache(?:/|\s|$)", "iis":r"\bmicrosoft-iis\b|\biis\b",
        "php":r"\bphp(?:[/ -]|\d)", "wordpress":r"\bwordpress\b|wp-content|wp-includes|wp-admin",
        "tomcat":r"\btomcat\b", "node.js":r"\bnode(?:\.js)?\b", "express":r"\bexpress(?:\.js)?\b",
        "django":r"\bdjango\b", "laravel":r"\blaravel\b", "jetty":r"\bjetty\b", "gunicorn":r"\bgunicorn\b",
        "openresty":r"\bopenresty\b", "swagger":r"\bswagger(?:-ui)?\b|swagger\.json", "openapi":r"\bopenapi\b|openapi\.json",
        "graphql":r"\bgraphql\b|/graphql(?:/|$)", "next.js":r"\b_next/static\b|\bnext(?:\.js)?\b", "react":r"\breact\b|react-dom",
        "vue":r"\bvue(?:\.js)?\b", "asp.net":r"\basp\.net\b|__viewstate", "java":r"\bjava\b|jsessionid",
    }
    return [name for name,p in mapping.items() if re.search(p, low)]


def extract_body_markers(body: str) -> list[str]:
    patterns=((r"wp-content|wp-includes|wp-admin","WordPress"),(r"swagger-ui|swagger\.json","Swagger"),(r"openapi\.json|openapi:","OpenAPI"),(r"/graphql","GraphQL"),(r"/_next/","Next.js"))
    return dedupe_ordered([label for pattern,label in patterns if re.search(pattern, body, re.I)])


def redact_http_headers(headers: dict[str,str]) -> dict[str,str]:
    blocked={"authorization","proxy-authorization","cookie","set-cookie","x-api-key"}
    return {k:("<redacted>" if k.lower() in blocked else v) for k,v in headers.items()}


def is_same_target_url(url: str, host: str) -> bool:
    try:
        parsed=urlparse(url)
        return parsed.hostname and parsed.hostname.lower().rstrip(".") == host.lower().rstrip(".")
    except Exception:
        return False


def extract_urls_from_lines(lines: Iterable[str]) -> list[str]:
    urls=[]
    for line in lines:
        urls.extend(re.findall(r"https?://[^\s'\"<>]+", line))
    return dedupe_ordered([u.rstrip(").,;]") for u in urls])


def infer_severity(text: str) -> str:
    low=text.lower()
    if re.search(r"\bcritical\b|remote code|\brce\b|command injection", low): return "critical"
    if re.search(r"\bhigh\b|sql injection|ssrf|auth bypass|arbitrary file", low): return "high"
    if re.search(r"\bmedium\b|xss|cors|csrf|directory listing", low): return "medium"
    if re.search(r"\blow\b|header|cookie|clickjack|information disclosure|self.?signed|hsts|cipher", low): return "low"
    return "info"


def classify_issue(text: str) -> str:
    low=text.lower()
    patterns=(
        ("missing-csp",r"content-security-policy.*(?:absent|missing)|(?:absent|missing).*content-security-policy"),
        ("missing-xcto",r"x-content-type-options.*(?:absent|missing)|(?:absent|missing).*x-content-type-options"),
        ("missing-referrer-policy",r"referrer-policy.*(?:absent|missing)|(?:absent|missing).*referrer-policy"),
        ("missing-permissions-policy",r"permissions-policy.*(?:absent|missing)|(?:absent|missing).*permissions-policy"),
        ("csp-unsafe-inline",r"unsafe-inline"),
        ("sql-injection",r"sql injection|sqli|injectable parameter|boolean-based|time-based blind"),
        ("xss",r"cross.?site scripting|xss"),
        ("ssrf",r"server.?side request forgery|\bssrf\b"),
        ("cors",r"cors|cross-origin resource sharing"),
        ("clickjacking",r"x-frame-options|clickjack|frame-ancestors"),
        ("hsts",r"strict-transport-security|hsts"),
        ("security-headers",r"security header|permissions-policy|referrer-policy|x-content-type-options"),
        ("sensitive-file-disclosure",r"\.bash_history|\.sh_history|shell history retrieved|\.env(?:\b|\.)|/\.git/"),
        ("certificate-mismatch",r"certificate.*does not match|hostname.*does not match|domain name mismatch|hostname mismatch"),
        ("self-signed-certificate",r"self.?signed ssl certificate|self.?signed certificate"),
        ("tls-cipher",r"cipherlist_|weak cipher|cbc cipher|potentially vulnerable, uses tls cbc"),
        ("cookie-flags",r"secure flag|httponly|samesite|cookie flag"),
        ("directory-listing",r"directory listing|autoindex|index of /"),
        ("verbose-errors",r"stack trace|debug mode|verbose error|exception disclosure"),
        ("version-disclosure",r"appears to be outdated|server.*version|version disclosure"),
        ("exposed-admin",r"admin panel|administrator|admin interface|\bjamonadmin\b"),
        ("csrf",r"csrf|cross-site request forgery|anti-csrf"),
        ("open-redirect",r"open redirect|redirect candidate"),
        ("ssrf",r"server-side fetch|server-side request forgery|\bssrf\b"),
        ("reflected-input",r"reflected input|reflected parameter|cross-site scripting|\bxss\b"),
        ("mixed-content",r"mixed content|insecure reference"),
        ("source-map",r"source map|javascript source map"),
        ("insecure-form",r"password form.*http|form.*over http"),
        ("cache-control",r"public-cacheable|public cache|shared cache"),
        ("tls",r"weak tls|obsolete protocol|tls/ssl misconfiguration|certificate|tlsv1|ssl"),
    )
    for key,pattern in patterns:
        if re.search(pattern,low): return key
    return re.sub(r"[^a-z0-9]+","-",low).strip("-")[:90] or "generic-finding"


def extract_endpoint_from_text(text: str) -> str:
    m=re.search(r"https?://[^\s'\"<>]+", text)
    if m: return m.group(0).rstrip(".,;)]")
    m=re.search(r"(/[A-Za-z0-9_./?=&%-]{1,200})",text)
    return m.group(1) if m else ""


def normalize_endpoint(value: str) -> str:
    if not value: return "/"
    try:
        p=urlparse(value)
        return p.path or "/"
    except Exception:
        return value[:200]


def _evidence_state(item: dict[str, Any], name: str) -> str:
    explicit=str(item.get("evidence_state") or item.get("evidence_type") or "").strip().upper()
    if explicit in {"CONFIRMED_OBSERVED","CONFIRMED_DERIVED","SCANNER_REPORTED","NEEDS_VALIDATION","FALSE_POSITIVE"}:
        return explicit
    # CVE/vulnerability-family claims are hypotheses until an appropriate validator confirms them.
    if re.search(r"\bCVE[- ]\d{4}-\d+\b|\b(BEAST|BREACH|CRIME|DROWN|FREAK|ROBOT|SWEET32|POODLE|LUCKY13|LOGJAM)\b", name, re.I):
        return "NEEDS_VALIDATION"
    # Scanner output that describes concrete protocol/HTTP observations is reportable as observed evidence.
    return "CONFIRMED_OBSERVED" if item.get("direct_observation") else "SCANNER_REPORTED"


def normalize_finding(source: str, item: dict[str,Any]) -> dict[str,Any] | None:
    name=str(item.get("name") or item.get("template_name") or item.get("category") or item.get("issue") or item.get("finding") or "").strip()
    if not name: return None
    endpoint=str(item.get("matched_at") or item.get("url") or item.get("path") or item.get("endpoint") or "").strip()
    if not endpoint:
        endpoint=extract_endpoint_from_text(str(item.get("info") or item.get("description") or name))
    severity=str(item.get("severity") or infer_severity(name)).lower()
    if severity not in {"critical","high","medium","low","info","unknown"}: severity=infer_severity(name)
    issue_key=classify_issue(name + " " + str(item.get("info") or item.get("description") or ""))
    endpoint_norm=normalize_endpoint(endpoint)
    fingerprint=f"{issue_key}|{endpoint_norm}"
    manual_validation = item.get("manual_validation") or MANUAL_GUIDANCE.get(issue_key, "Review the affected endpoint and independently validate security impact using a controlled, authorized workflow.")
    remediation = item.get("remediation") or REMEDIATION_GUIDANCE.get(issue_key, "Apply the appropriate secure configuration or application control for the affected component.")
    description = item.get("description") or item.get("info") or f"{name} was observed by the ReconForge assessment pipeline."
    impact = item.get("impact") or IMPACT_GUIDANCE.get(issue_key, "The observed condition may weaken the application's security boundary or expose information or functionality; impact depends on application context.")
    state = _evidence_state(item,name)
    if state == "CONFIRMED_OBSERVED":
        why_reported = "Directly observed in assessment evidence."
    elif state == "CONFIRMED_DERIVED":
        why_reported = "Deterministically derived from observed assessment evidence."
    elif state == "SCANNER_REPORTED":
        why_reported = f"Reported by {source}; retained as scanner evidence."
    elif state == "NEEDS_VALIDATION":
        why_reported = f"Candidate detected by {source}; vulnerability-specific confirmation is still required."
    else:
        why_reported = "Retained for evidence traceability."
    return {
        "issue_key":issue_key,
        "name":name,
        "severity":severity,
        "source":source,
        "endpoint":endpoint,
        "endpoint_path":endpoint_norm,
        "fingerprint":fingerprint,
        "identifier":item.get("identifier") or item.get("id"),
        "evidence_state":state,
        "raw":item,
        "rule_id": item.get("rule_id"),
        "description": description,
        "impact": impact,
        "why_reported": why_reported,
        "manual_validation": manual_validation,
        "remediation": remediation,
        "owasp_category": item.get("owasp_category", ""),
        "cwe": item.get("cwe"),
        "audit_confidence": item.get("confidence", ""),
    }
