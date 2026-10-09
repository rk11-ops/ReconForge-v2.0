from __future__ import annotations

import asyncio
import hashlib
import json
import re
import ssl
import time
import threading
from html.parser import HTMLParser
from pathlib import Path
from urllib import error, request
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlunparse

from ..evidence.normalize import extract_body_markers, extract_technologies, redact_http_headers
from ..models import ToolResult


MAX_BODY = 256 * 1024
DEFAULT_USER_AGENT = "ReconForge/4.3 web-audit"


class _ScopedRedirectHandler(request.HTTPRedirectHandler):
    def __init__(self, allowed_host: str):
        self.allowed_host = allowed_host.lower().rstrip(".")

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        if (parsed.hostname or "").lower().rstrip(".") != self.allowed_host:
            raise error.HTTPError(req.full_url, code, "cross-host redirect blocked", headers, None)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.resources: list[str] = []
        self.forms: list[dict] = []
        self.current_form: dict | None = None
        self.scripts: list[str] = []
        self.inline_script = False
        self.inline_buffer: list[str] = []
        self.title = ""
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in {"link", "img", "iframe", "object", "embed", "source", "video", "audio"} and a.get("src") or tag == "link" and a.get("href"):
            value = a.get("src") or a.get("href")
            if value:
                self.resources.append(value)
        elif tag == "script":
            if a.get("src"):
                self.resources.append(a["src"])
            else:
                self.inline_script = True
                self.inline_buffer = []
        elif tag == "form":
            self.current_form = {
                "action": a.get("action") or "",
                "method": (a.get("method") or "GET").upper(),
                "enctype": a.get("enctype") or "application/x-www-form-urlencoded",
                "inputs": [],
            }
        elif tag in {"input", "textarea", "select", "button"} and self.current_form is not None:
            self.current_form["inputs"].append({
                "name": a.get("name") or "",
                "type": (a.get("type") or tag).lower(),
                "autocomplete": a.get("autocomplete") or "",
            })
        elif tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "script" and self.inline_script:
            self.scripts.append("".join(self.inline_buffer)[:20000])
            self.inline_script = False
            self.inline_buffer = []
        elif tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None
        elif tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data[:500]
        if self.inline_script:
            self.inline_buffer.append(data[:5000])


def _same_host(url: str, host: str) -> bool:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".") == host.lower().rstrip(".")
    except Exception:
        return False


def _normalise_url(raw: str, base: str, host: str) -> str | None:
    if not raw:
        return None
    value = urljoin(base, raw.strip())
    value, _ = urldefrag(value)
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not _same_host(value, host):
        return None
    query = []
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        query.append((key, val[:500]))
    clean = parsed._replace(fragment="", query="&".join(f"{k}={v}" for k, v in query))
    return urlunparse(clean)


def _safe_query_names(url: str) -> list[str]:
    try:
        return sorted({k.lower() for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if k})
    except Exception:
        return []


def _excerpt(body: str, patterns: list[str], limit: int = 1200) -> str:
    low = body.lower()
    for pattern in patterns:
        m = re.search(pattern, body, re.I | re.M)
        if m:
            start = max(0, m.start() - 180)
            return body[start:min(len(body), m.end() + 420)][:limit]
    return body[:limit]


class WebCrawler:
    """Bounded same-origin GET crawler. Never submits forms or mutates application state."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.host = ctx.host
        self.max_pages = max(1, min(int(getattr(ctx, "crawl_pages", 50)), 1000))
        self.max_depth = max(0, min(int(getattr(ctx, "crawl_depth", 2)), 8))
        self.rate = max(0.1, min(float(getattr(ctx, "crawl_rate", 2.0)), 25.0))
        self.concurrency = max(1, min(int(getattr(ctx, "crawl_concurrency", 4)), 12))
        self.user_agent = DEFAULT_USER_AGENT
        self.last_request = 0.0
        self.rate_lock = asyncio.Lock()
        self.sync_rate_lock = threading.Lock()
        self.semaphore = asyncio.Semaphore(self.concurrency)

    async def run(self) -> ToolResult:
        started = time.monotonic()
        output = Path(self.ctx.output_dir) / "artifacts" / "web_crawl.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        if self.ctx.dry_run:
            payload = {
                "status": "dry-run",
                "start_url": self.ctx.web_url,
                "max_depth": self.max_depth,
                "max_pages": self.max_pages,
                "rate_per_second": self.rate,
                "form_submission": False,
                "cross_host_redirects": False,
            }
            output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return ToolResult(tool="web-crawler", status="dry-run", duration_seconds=time.monotonic() - started, artifacts=[str(output)], summary={"crawl": payload}, phase="web-audit")

        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        seen: set[str] = set()
        pages: list[dict] = []
        start = self._normalise_start(self.ctx.web_url)
        await queue.put((start, 0))
        seen.add(start)

        claim_lock = asyncio.Lock()
        claimed = 0

        async def worker():
            nonlocal claimed
            while True:
                try:
                    current, depth = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    async with claim_lock:
                        if claimed >= self.max_pages:
                            continue
                        claimed += 1
                    async with self.semaphore:
                        item = await asyncio.to_thread(self._fetch, current, depth)
                    if item:
                        pages.append(item)
                        if depth < self.max_depth:
                            candidates = item.get("discovered_urls", [])
                            for nxt in candidates:
                                if len(seen) >= self.max_pages:
                                    break
                                if nxt not in seen:
                                    seen.add(nxt)
                                    await queue.put((nxt, depth + 1))
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(min(self.concurrency, 6))]
        await queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        pages.sort(key=lambda x: (x.get("depth", 0), x.get("url", "")))
        all_endpoints = sorted({p["url"] for p in pages if p.get("url")})
        all_forms = []
        all_findings = []
        technologies = set()
        for p in pages:
            all_forms.extend(p.get("forms", []))
            all_findings.extend(p.get("audit_findings", []))
            technologies.update(p.get("technologies", []))

        manual = _manual_review_queue(pages)
        summary = {
            "status": "completed",
            "start_url": start,
            "pages_crawled": len(pages),
            "page_limit": self.max_pages,
            "max_depth": self.max_depth,
            "rate_per_second": self.rate,
            "endpoints": all_endpoints,
            "forms": all_forms,
            "technologies": sorted(technologies),
            "findings": all_findings,
            "manual_review": manual,
            "pages": pages,
            "form_submission": False,
            "same_origin_only": True,
        }
        output.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        return ToolResult(
            tool="web-crawler",
            status="completed",
            duration_seconds=time.monotonic() - started,
            artifacts=[str(output)],
            summary={"crawl": summary, "endpoints": all_endpoints, "findings": all_findings, "technologies": sorted(technologies), "observations": [f"Crawled {len(pages)} same-origin web pages"]},
            notes=["GET-only crawler; forms were discovered but never submitted.", "Cross-host redirects are blocked."],
            phase="web-audit",
        )

    def _normalise_start(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return f"http://{self.host}/"
        path = parsed.path or "/"
        return urlunparse(parsed._replace(path=path, fragment=""))

    async def _pace(self):
        async with self.rate_lock:
            now = time.monotonic()
            interval = 1.0 / self.rate
            wait = interval - (now - self.last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self.last_request = time.monotonic()

    def _fetch(self, url: str, depth: int) -> dict | None:
        # Execute the pacing sleep in sync context via a monotonic guard; requests remain bounded.
        with self.sync_rate_lock:
            now = time.monotonic()
            interval = 1.0 / self.rate
            wait = interval - (now - self.last_request)
            if wait > 0:
                time.sleep(wait)
            self.last_request = time.monotonic()
        opener = request.build_opener(_ScopedRedirectHandler(self.host))
        req = request.Request(url, headers={"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5"}, method="GET")
        try:
            with opener.open(req, timeout=12) as r:
                headers_raw = r.headers
                headers = dict(headers_raw.items())
                cookies = headers_raw.get_all("Set-Cookie") or []
                content_type = headers.get("Content-Type", "")
                raw = r.read(MAX_BODY)
                body = raw.decode("utf-8", errors="replace")
                final_url = r.geturl()
                status = r.status
                error_text = None
        except error.HTTPError as e:
            headers_raw = e.headers
            headers = dict(headers_raw.items()) if headers_raw else {}
            cookies = headers_raw.get_all("Set-Cookie") if headers_raw else []
            try:
                raw = e.read(MAX_BODY)
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            final_url = url
            status = e.code
            content_type = headers.get("Content-Type", "")
            error_text = f"HTTP {e.code}"
        except error.URLError as e:
            if url.lower().startswith("https://") and isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                return self._fetch_unverified(url, depth, str(e.reason))
            return {"url": url, "depth": depth, "status": "error", "error": str(e), "audit_findings": [], "discovered_urls": []}
        except ssl.SSLCertVerificationError as e:
            return self._fetch_unverified(url, depth, str(e))
        except Exception as e:
            return {"url": url, "depth": depth, "status": "error", "error": str(e), "audit_findings": [], "discovered_urls": []}

        return self._build_page(url, final_url, depth, status, content_type, headers, cookies, body, error_text)

    def _fetch_unverified(self, url: str, depth: int, tls_error: str) -> dict | None:
        context = ssl._create_unverified_context()
        opener = request.build_opener(_ScopedRedirectHandler(self.host), request.HTTPSHandler(context=context))
        req = request.Request(url, headers={"User-Agent": self.user_agent}, method="GET")
        try:
            with opener.open(req, timeout=12) as r:
                headers_raw = r.headers
                headers = dict(headers_raw.items())
                cookies = headers_raw.get_all("Set-Cookie") or []
                body = r.read(MAX_BODY).decode("utf-8", errors="replace")
                return self._build_page(url, r.geturl(), depth, r.status, headers.get("Content-Type", ""), headers, cookies, body, f"TLS verification failed: {tls_error[:400]}")
        except Exception as exc:
            return {"url": url, "depth": depth, "status": "tls-error", "error": str(exc), "audit_findings": [], "discovered_urls": []}

    def _build_page(self, requested, final_url, depth, status, content_type, headers, cookies, body, fetch_note=None):
        parser = SurfaceParser()
        is_html = "html" in content_type.lower() or re.search(r"<!doctype html|<html\b", body[:20000], re.I)
        if is_html:
            try:
                parser.feed(body)
            except Exception:
                pass
        discovered = []
        if is_html:
            for raw in parser.links + parser.resources:
                normalized = _normalise_url(raw, final_url, self.host)
                if normalized:
                    discovered.append(normalized)
            # GET form actions are safe to discover/crawl; state-changing forms are inventoried only.
            for form in parser.forms:
                if str(form.get("method") or "GET").upper() == "GET":
                    normalized = _normalise_url(form.get("action") or final_url, final_url, self.host)
                    if normalized:
                        discovered.append(normalized)
            for script in parser.scripts:
                for raw in re.findall(r"(?:https?://[^\s'\"<>]+|/[A-Za-z0-9_./?=&%:-]{1,220})", script):
                    normalized = _normalise_url(raw, final_url, self.host)
                    if normalized:
                        discovered.append(normalized)
        discovered = sorted(set(discovered))
        technologies = sorted(set(extract_technologies(" ".join(headers.values()) + " " + body)))
        findings = audit_response(
            url=final_url,
            status=status,
            headers=headers,
            cookies=cookies,
            body=body,
            forms=parser.forms,
            discovered_urls=discovered,
            title=parser.title.strip(),
        )
        page = {
            "url": final_url,
            "requested_url": requested,
            "depth": depth,
            "status": status,
            "content_type": content_type,
            "headers": redact_http_headers(headers),
            "technologies": technologies,
            "title": parser.title.strip()[:500],
            "forms": [_normalise_form(f, final_url, self.host) for f in parser.forms],
            "discovered_urls": discovered[:500],
            "query_parameters": _safe_query_names(final_url),
            "audit_findings": findings,
            "body_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
            "evidence_excerpt": _excerpt(body, [r"Traceback \(most recent call last\)", r"Index of /", r"SQLSTATE\[", r"Exception in thread", r"Fatal error", r"Stack trace"], 1400),
        }
        if fetch_note:
            page["fetch_note"] = fetch_note
        return page


def _normalise_form(form: dict, base: str, host: str) -> dict:
    action = _normalise_url(form.get("action") or base, base, host) or base
    return {
        "action": action,
        "method": str(form.get("method") or "GET").upper(),
        "enctype": form.get("enctype") or "application/x-www-form-urlencoded",
        "inputs": form.get("inputs", [])[:80],
    }


def audit_response(*, url: str, status: int, headers: dict[str, str], cookies: list[str], body: str, forms: list[dict], discovered_urls: list[str], title: str) -> list[dict]:
    lower = {str(k).lower(): str(v) for k, v in headers.items()}
    findings: list[dict] = []

    def add(rule_id, name, severity, state, description, guidance, remediation, category, cwe=None, evidence=None, confidence="high"):
        findings.append({
            "rule_id": rule_id,
            "name": name,
            "severity": severity,
            "evidence_state": state,
            "direct_observation": state == "CONFIRMED_OBSERVED",
            "description": description,
            "manual_validation": guidance,
            "remediation": remediation,
            "owasp_category": category,
            "cwe": cwe,
            "confidence": confidence,
            "evidence": evidence or {},
            "endpoint": url,
        })

    csp = lower.get("content-security-policy", "")
    frame_ancestors = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I)
    if not lower.get("x-frame-options") and not frame_ancestors:
        add("RF-WEB-001", "Missing clickjacking protection", "low", "CONFIRMED_OBSERVED", "The response does not advertise X-Frame-Options or a CSP frame-ancestors directive.", "Verify framing behavior in a controlled browser test page and confirm whether authenticated or sensitive content can be framed.", "Set an appropriate CSP frame-ancestors policy and/or X-Frame-Options where legacy support is required.", "A02:2025 Security Misconfiguration", "CWE-1021")
    if not lower.get("content-security-policy"):
        add("RF-WEB-002", "Content-Security-Policy is absent", "low", "CONFIRMED_OBSERVED", "No Content-Security-Policy response header was observed.", "Review whether the application has untrusted content or script injection surfaces that would benefit from a restrictive CSP.", "Deploy a least-privilege CSP tailored to the application.", "A02:2025 Security Misconfiguration", "CWE-693")
    elif "unsafe-inline" in csp.lower() and "nonce-" not in csp.lower() and "sha256-" not in csp.lower():
        add("RF-WEB-003", "CSP allows unsafe-inline scripts", "low", "CONFIRMED_OBSERVED", "The CSP contains unsafe-inline without an obvious nonce/hash alternative.", "Determine which pages rely on inline scripts and whether script execution can be constrained further without breaking the application.", "Replace unsafe-inline with nonces or hashes where practical and remove unnecessary inline script execution.", "A02:2025 Security Misconfiguration", "CWE-693")
    if url.lower().startswith("https://") and "strict-transport-security" not in lower:
        add("RF-WEB-004", "HSTS is not offered", "low", "CONFIRMED_OBSERVED", "HTTPS response did not include Strict-Transport-Security.", "Confirm that the site should be HTTPS-only and assess whether subdomains are also covered.", "Add a correctly scoped Strict-Transport-Security policy after ensuring HTTPS is deployed consistently.", "A02:2025 Security Misconfiguration", "CWE-319")
    if "x-content-type-options" not in lower:
        add("RF-WEB-005", "X-Content-Type-Options is absent", "low", "CONFIRMED_OBSERVED", "No X-Content-Type-Options header was observed.", "Check whether user-controlled content or MIME-sniffing behavior could cause a security boundary issue.", "Set X-Content-Type-Options: nosniff.", "A02:2025 Security Misconfiguration", "CWE-693")
    if "referrer-policy" not in lower:
        add("RF-WEB-006", "Referrer-Policy is absent", "low", "CONFIRMED_OBSERVED", "No Referrer-Policy header was observed.", "Review whether sensitive paths or identifiers could appear in URLs and leak through the Referer header.", "Set a restrictive Referrer-Policy appropriate for the application.", "A02:2025 Security Misconfiguration", "CWE-200")
    if "permissions-policy" not in lower:
        add("RF-WEB-007", "Permissions-Policy is absent", "info", "CONFIRMED_OBSERVED", "No Permissions-Policy header was observed.", "Review browser features exposed to the application and third-party content.", "Set Permissions-Policy for capabilities the application does not require.", "A02:2025 Security Misconfiguration", "CWE-693")

    acao = lower.get("access-control-allow-origin", "").strip()
    acac = lower.get("access-control-allow-credentials", "").strip().lower()
    if acao == "*":
        severity = "medium" if acac == "true" else "low"
        add("RF-WEB-008", "CORS allows any origin", severity, "CONFIRMED_OBSERVED", "Access-Control-Allow-Origin is set to wildcard.", "Determine whether the endpoint returns sensitive data and whether credentialed cross-origin requests are actually supported by application logic.", "Allow only trusted origins and configure credential handling explicitly.", "A02:2025 Security Misconfiguration", "CWE-942", {"access_control_allow_origin": "*", "access_control_allow_credentials": acac or None})

    for cookie in cookies[:50]:
        name = cookie.split("=", 1)[0].strip() or "<unnamed>"
        lc = cookie.lower()
        missing = [flag for flag, present in (("Secure", "secure" in lc), ("HttpOnly", "httponly" in lc), ("SameSite", "samesite=" in lc)) if not present]
        if missing:
            add("RF-WEB-009", f"Cookie {name} missing security flags", "low", "CONFIRMED_OBSERVED", "The Set-Cookie header is missing one or more common security attributes.", "Identify whether the cookie is a session/authentication cookie and confirm the required flags for its use case.", "Apply Secure, HttpOnly, and an appropriate SameSite policy to sensitive cookies.", "A07:2025 Authentication Failures", "CWE-614", {"cookie": "<redacted>", "missing_flags": missing})

    server = lower.get("server", "")
    if server and re.search(r"\b\d+\.\d+(?:\.\d+)?\b", server):
        add("RF-WEB-010", "Server header discloses a version", "low", "CONFIRMED_OBSERVED", "The Server header contains a software version string.", "Check whether version disclosure materially helps fingerprinting or whether a standardized hardened response can hide unnecessary detail.", "Remove or minimize version information from response headers where practical.", "A02:2025 Security Misconfiguration", "CWE-200", {"server": server})

    if re.search(r"(?:Index of /|<title>\s*Index of /)", body, re.I):
        add("RF-WEB-011", "Directory listing exposed", "medium", "CONFIRMED_OBSERVED", "The response resembles a directory listing.", "Review the listed files and determine whether any contain source, backups, credentials, or internal documentation.", "Disable directory indexing or restrict the directory to intentionally public content.", "A02:2025 Security Misconfiguration", "CWE-548")

    error_patterns = (r"Traceback \(most recent call last\)", r"SQLSTATE\[", r"Exception in thread", r"javax\.servlet\.", r"org\.springframework\.", r"Fatal error:\s", r"Stack trace\s*:")
    if any(re.search(p, body, re.I) for p in error_patterns):
        add("RF-WEB-012", "Verbose error or stack trace disclosed", "medium", "CONFIRMED_OBSERVED", "The response body contains recognizable application error details or a stack trace.", "Repeat the request without sensitive context and verify whether the error page leaks file paths, framework versions, SQL details, or other internals.", "Return generic production error responses and log detailed diagnostics server-side.", "A02:2025 Security Misconfiguration", "CWE-209")

    sensitive_ext = re.compile(r"(?:^|/)(?:\.env|\.git(?:/|$)|id_rsa|docker-compose(?:\.[^/]+)?|backup|backup\.(?:zip|tar|gz)|config\.(?:bak|old)|\.sql(?:\.gz)?)(?:$|[?#])", re.I)
    for item in discovered_urls:
        if sensitive_ext.search(urlparse(item).path):
            add("RF-WEB-013", "Sensitive file or repository path discovered", "high", "CONFIRMED_OBSERVED", "A crawl-discovered same-origin URL resembles a sensitive configuration, backup, or repository path.", "Open the resource manually in your authorized test environment and verify whether sensitive content is actually accessible; do not alter or upload anything.", "Remove the sensitive artifact from the web root and add deployment controls to prevent recurrence.", "A01:2025 Broken Access Control / A02:2025 Security Misconfiguration", "CWE-552", {"discovered_url": item})
            break

    for item in discovered_urls:
        if urlparse(item).path.lower().endswith(".js.map"):
            add("RF-WEB-014", "JavaScript source map exposed", "low", "CONFIRMED_OBSERVED", "A crawl-discovered script references a JavaScript source map.", "Review the map for internal paths, source code, debug data, or secrets before deciding whether public exposure is acceptable.", "Remove production source maps or publish only sanitized maps where appropriate.", "A02:2025 Security Misconfiguration", "CWE-200", {"source_map": item})
            break

    if url.lower().startswith("https://"):
        http_resources = [u for u in discovered_urls if u.lower().startswith("http://")]
        if http_resources:
            add("RF-WEB-015", "Mixed-content references discovered", "medium", "CONFIRMED_OBSERVED", "An HTTPS page references same-origin HTTP resources.", "Determine whether each HTTP resource is loaded in a browser context and whether it can affect page integrity or confidentiality.", "Serve all security-sensitive resources over HTTPS and remove insecure references.", "A02:2025 Security Misconfiguration", "CWE-311", {"http_resources": http_resources[:20]})

    for form in forms:
        action = form.get("action") or url
        method = str(form.get("method") or "GET").upper()
        names = {str(i.get("name") or "").lower() for i in form.get("inputs", [])}
        types = {str(i.get("type") or "").lower() for i in form.get("inputs", [])}
        if "password" in types and action.lower().startswith("http://"):
            add("RF-WEB-016", "Password form submits over HTTP", "high", "CONFIRMED_OBSERVED", "A password input is present in a form whose action uses HTTP.", "Confirm the final submission path and whether credentials can traverse an unencrypted connection at any point.", "Submit credential forms only over HTTPS and enforce HTTPS consistently.", "A07:2025 Authentication Failures", "CWE-319")
        csrf_names = {n for n in names if any(token in n for token in ("csrf", "xsrf", "anti-forgery", "authenticity_token"))}
        if method in {"POST", "PUT", "PATCH", "DELETE"} and not csrf_names:
            add("RF-WEB-017", "State-changing form may lack CSRF protection", "medium", "NEEDS_VALIDATION", "A state-changing form was crawled without an obvious anti-CSRF token field.", "Use a controlled authenticated workflow to verify whether the server requires a per-request or per-session CSRF defense and whether SameSite cookies provide sufficient protection for the flow.", "Use framework-provided CSRF defenses for state-changing browser requests and require appropriate cookie protections.", "A01:2025 Broken Access Control", "CWE-352", {"method": method, "action": action, "input_names": sorted(names)}, "medium")

    params = set(_safe_query_names(url))
    query_values = [v for _, v in parse_qsl(urlparse(url).query, keep_blank_values=True)]
    for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if value and len(value) >= 2 and value in body:
            add("RF-WEB-018", "Reflected input candidate", "medium", "NEEDS_VALIDATION", "A current query parameter value is reflected in the response body.", "Determine the output context and whether the application applies correct context-sensitive encoding before considering exploitability.", "Apply context-appropriate output encoding and input handling for the affected sink.", "A05:2025 Injection", "CWE-79", {"parameter": key, "value_length": len(value)})
            break

    redirect_names = {"url", "uri", "next", "redirect", "redirect_url", "return", "returnto", "continue"}
    if status in {301, 302, 303, 307, 308} and params & redirect_names:
        add("RF-WEB-019", "Open redirect candidate", "medium", "NEEDS_VALIDATION", "A redirect response contains a destination-like query parameter.", "Verify whether the application restricts redirect destinations to trusted internal paths or approved origins.", "Validate redirect destinations against an allowlist or use server-side route identifiers instead of arbitrary URLs.", "A01:2025 Broken Access Control", "CWE-601", {"parameters": sorted(params & redirect_names)}, "medium")

    ssrf_names = {"url", "uri", "link", "callback", "webhook", "feed", "image", "dest", "destination", "proxy"}
    if params & ssrf_names:
        add("RF-WEB-020", "Server-side fetch / SSRF review candidate", "medium", "NEEDS_VALIDATION", "The endpoint exposes a parameter name commonly associated with server-side URL fetching.", "Review the server-side request flow and confirm whether destinations are constrained, validated, and protected against access to internal services.", "Use strict destination allowlists, URL parsing, network egress controls, and deny-by-default access to internal address space where applicable.", "A10 Server-Side Request Forgery", "CWE-918", {"parameters": sorted(params & ssrf_names)}, "low")

    # Methodology-oriented passive/candidate checks. These do not submit payloads or mutate state.
    sql_param_names = {"id", "query", "search", "q", "filter", "sort", "order", "where", "select", "report", "item", "user"}
    sql_error_markers = (r"sql syntax", r"sqlstate", r"mysql_fetch", r"postgresql.*error", r"ora-\d{4,}", r"sqlite.*error", r"odbc.*driver")
    if (params & sql_param_names) or any(re.search(p, body, re.I) for p in sql_error_markers):
        add("RF-WEB-024", "SQL injection review candidate", "medium", "NEEDS_VALIDATION", "The endpoint exposes parameter names or response markers commonly associated with SQL-backed input handling.", "Review the parameter-to-query data flow and manually validate whether input reaches a SQL interpreter without parameterization. ReconForge does not inject SQL payloads in this safe audit.", "Use parameterized queries or prepared statements and avoid concatenating untrusted input into SQL statements.", "A05:2025 Injection", "CWE-89", {"parameter_names": sorted(params & sql_param_names), "error_marker_observed": any(re.search(p, body, re.I) for p in sql_error_markers)}, "low")

    traversal_names = {"file", "filepath", "path", "filename", "folder", "dir", "directory", "template", "include", "download"}
    if params & traversal_names:
        add("RF-WEB-025", "Path traversal review candidate", "medium", "NEEDS_VALIDATION", "A parameter name suggests server-side file/path selection.", "Manually review path normalization, allowlisting and filesystem boundary enforcement for the affected parameter. No traversal payload is sent by this audit.", "Canonicalize and validate paths against an allowlisted base directory and reject escape sequences before filesystem access.", "A01:2025 Broken Access Control", "CWE-22", {"parameters": sorted(params & traversal_names)}, "low")

    command_names = {"cmd", "command", "exec", "execute", "shell", "command_line"}
    if params & command_names:
        add("RF-WEB-026", "OS command injection review candidate", "high", "NEEDS_VALIDATION", "A parameter name suggests that the application may construct or invoke an operating-system command.", "Review whether user-controlled data reaches a command interpreter or process API. Manually validate in an isolated authorized environment; do not execute injected commands from ReconForge.", "Avoid shell interpretation and use fixed executable/argument arrays with strict allowlists for command parameters.", "A05:2025 Injection", "CWE-78", {"parameters": sorted(params & command_names)}, "low")

    upload_forms = []
    for form in forms:
        for inp in form.get("inputs", []):
            if str(inp.get("type") or "").lower() == "file":
                upload_forms.append({"action": form.get("action") or url, "method": form.get("method") or "GET", "name": inp.get("name") or ""})
    if upload_forms:
        add("RF-WEB-027", "File upload security review surface", "medium", "NEEDS_VALIDATION", "The crawler discovered one or more file upload controls.", "Review extension/MIME validation, storage location, filename handling, authorization and execution isolation with a controlled test file. ReconForge does not upload files.", "Allowlist safe types, rename uploads, store outside executable web roots, enforce authorization and scan content as appropriate.", "A01:2025 Broken Access Control", "CWE-434", {"forms": upload_forms[:20]}, "high")

    object_path_candidates = [p for p in [url] if re.search(r"/(?:users?|accounts?|orders?|documents?|files?|projects?)/(?:[0-9]{1,}|[0-9a-f]{8,})(?:/|$)", url, re.I)]
    if object_path_candidates:
        add("RF-WEB-028", "Object-level authorization review candidate", "medium", "NEEDS_VALIDATION", "A resource path contains a user-controlled-looking object identifier.", "Compare the same resource under separate authorized identities and verify object- and function-level authorization decisions. No identity swapping is performed automatically.", "Enforce authorization server-side for every object and function, independent of client-supplied identifiers.", "A01:2025 Broken Access Control", "CWE-862", {"endpoint": url}, "medium")

    manifest_paths = [u for u in discovered_urls if re.search(r"/(?:package-lock\\.json|yarn\\.lock|pnpm-lock\\.yaml|composer\\.lock|requirements(?:\\.txt)?|pom\\.xml|gradle(?:\\.lockfile)?|go\\.sum)(?:$|[?#])", urlparse(u).path, re.I)]
    if manifest_paths:
        add("RF-WEB-029", "Dependency/build manifest exposed", "info", "CONFIRMED_OBSERVED", "A crawl-discovered URL resembles a dependency or build manifest.", "Review whether the manifest leaks internal dependency versions, private package names or build metadata and correlate versions with your approved inventory.", "Keep dependency/build manifests out of public web roots unless intentionally published.", "A03:2025 Software Supply Chain Failures", "CWE-200", {"manifest_paths": manifest_paths[:20]})

    secret_markers = [
        r"AKIA[0-9A-Z]{16}", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\\s*[:=]\\s*[\"'][^\"']{12,}[\"']",
    ]
    matched_secret = next((pat for pat in secret_markers if re.search(pat, body)), None)
    if matched_secret:
        add("RF-WEB-030", "Potential sensitive secret exposure", "high", "NEEDS_VALIDATION", "The response body contains a pattern resembling a credential or secret-bearing value.", "Verify whether the value is a real credential, test placeholder or public identifier. Do not use or rotate a discovered credential during automated scanning.", "Remove secrets from client-delivered content, rotate exposed credentials, and add secret-scanning controls to the SDLC.", "A01:2025 Broken Access Control", "CWE-200", {"pattern": matched_secret}, "medium")

    if re.search(r"/(?:swagger|openapi)(?:\.json|/|$)", url, re.I) or "openapi" in body.lower() or "swagger-ui" in body.lower():
        add("RF-WEB-021", "API documentation endpoint exposed", "info", "CONFIRMED_OBSERVED", "The crawler observed an OpenAPI/Swagger-related endpoint or marker.", "Review whether documentation exposes internal operations, administrative routes, schemas, or environment-specific details.", "Restrict documentation to intended audiences and avoid embedding secrets or sensitive implementation details.", "A02:2025 Security Misconfiguration", "CWE-200")
    if re.search(r"/(?:graphql)(?:/|$)", url, re.I) or "graphql" in body.lower():
        add("RF-WEB-022", "GraphQL surface discovered", "info", "CONFIRMED_OBSERVED", "A GraphQL-related endpoint or marker was observed.", "Manually review authentication, field-level authorization, introspection policy, query depth, batching, and rate limiting.", "Restrict introspection in production where appropriate and enforce authorization and resource limits at the resolver/API layer.", "A01:2025 Broken Access Control", "CWE-285")

    if "cache-control" in lower and re.search(r"\bpublic\b", lower["cache-control"], re.I) and any(f in lower for f in ("set-cookie", "authorization")):
        add("RF-WEB-023", "Potentially sensitive response marked public-cacheable", "medium", "NEEDS_VALIDATION", "A response carrying session-related headers also advertises public caching.", "Use a controlled authenticated session to confirm whether personalized or sensitive content can be served from a shared cache.", "Use private/no-store directives for responses containing user-specific sensitive information where required.", "A02:2025 Security Misconfiguration", "CWE-524")

    return findings


def _manual_review_queue(pages: list[dict]) -> list[dict]:
    paths = sorted({p.get("url") for p in pages if p.get("url")})
    forms = [f for p in pages for f in p.get("forms", [])]
    review = [
        {"area": "Authentication/session", "reason": "Automated crawl cannot safely prove login, MFA, reset-flow, session fixation, logout, or timeout weaknesses without an approved test account.", "targets": [p for p in paths if re.search(r"/(login|signin|auth|reset|password|account)(/|$)", urlparse(p).path, re.I)][:20], "guidance": "Review authentication state transitions, cookie scope/flags, logout invalidation, reset-token lifecycle, and MFA enforcement in a controlled account."},
        {"area": "Authorization / IDOR / BOLA", "reason": "Object-level access control requires comparing requests under separate authorized identities.", "targets": [p for p in paths if re.search(r"/(api|users?|accounts?|orders?|documents?|files?)(/|$)", urlparse(p).path, re.I)][:30], "guidance": "Repeat representative object requests with two approved roles/tenants and verify that server-side authorization follows the authenticated principal."},
        {"area": "Privilege / role boundaries", "reason": "Role enforcement cannot be inferred reliably from anonymous crawling.", "targets": [p for p in paths if re.search(r"/(admin|manage|staff|moderator|operator)(/|$)", urlparse(p).path, re.I)][:20], "guidance": "Check the same sensitive operations under each approved role and confirm unauthorized actions are rejected server-side."},
        {"area": "File upload / content handling", "reason": "The crawler inventories forms but does not submit files or modify server state.", "targets": [f.get("action") for f in forms if any(str(i.get("type") or "").lower() == "file" for i in f.get("inputs", []))][:20], "guidance": "Review file type validation, storage location, retrieval permissions, filename handling, and content-disposition behavior using controlled benign test files."},
        {"area": "Business logic / workflow", "reason": "Business logic flaws are application-specific and require manual workflow reasoning.", "targets": paths[:30], "guidance": "Trace sensitive multi-step workflows and confirm server-side invariants, replay resistance, quantity/price bounds, and authorization at every step."},
        {"area": "Rate limiting / abuse controls", "reason": "This audit avoids high-volume probing and therefore cannot prove rate-limit strength.", "targets": [p for p in paths if re.search(r"/(login|auth|api|reset|otp|verify)(/|$)", urlparse(p).path, re.I)][:30], "guidance": "Within the approved test budget, verify that authentication, reset, OTP, and sensitive API operations have appropriate per-user/per-IP throttling."},
    ]
    return review
