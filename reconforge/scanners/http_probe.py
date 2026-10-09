from __future__ import annotations

import asyncio
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

from ..evidence.normalize import extract_body_markers, extract_technologies, redact_http_headers
from ..utils import dedupe_ordered


class PassiveHTTPProbe:
    """Low-noise HTTP/TLS metadata collector used as first-class evidence."""

    USER_AGENT = "ReconForge/4.2 passive-recon"

    def __init__(self, ctx):
        self.ctx = ctx

    async def run(self):
        return await asyncio.to_thread(self._run_sync)

    @staticmethod
    def _same_host(a: str, b: str) -> bool:
        try:
            return (urlparse(a).hostname or "").lower().rstrip(".") == (urlparse(b).hostname or "").lower().rstrip(".")
        except Exception:
            return False

    @staticmethod
    def _findings(url: str, status: int | None, headers: dict[str, str], cookies: list[str], tls_verification_error: str | None = None):
        lower = {str(k).lower(): str(v) for k, v in headers.items()}
        findings = []
        csp = lower.get("content-security-policy", "")
        frame_ancestors = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I)
        xfo = lower.get("x-frame-options", "").strip()

        if not xfo and not frame_ancestors:
            findings.append({
                "name": "Missing clickjacking protection",
                "severity": "low",
                "endpoint": url,
                "direct_observation": True,
                "evidence_state": "CONFIRMED_OBSERVED",
                "details": {"x_frame_options": None, "frame_ancestors": None},
            })
        if url.lower().startswith("https://") and "strict-transport-security" not in lower:
            findings.append({
                "name": "HSTS is not offered",
                "severity": "low",
                "endpoint": url,
                "direct_observation": True,
                "evidence_state": "CONFIRMED_OBSERVED",
                "details": {"http_status": status},
            })
        if "content-security-policy" not in lower:
            findings.append({
                "name": "Content-Security-Policy is absent",
                "severity": "low",
                "endpoint": url,
                "direct_observation": True,
                "evidence_state": "CONFIRMED_OBSERVED",
            })
        if "x-content-type-options" not in lower:
            findings.append({
                "name": "X-Content-Type-Options is absent",
                "severity": "low",
                "endpoint": url,
                "direct_observation": True,
                "evidence_state": "CONFIRMED_OBSERVED",
            })

        acao = lower.get("access-control-allow-origin", "").strip()
        if acao == "*":
            findings.append({
                "name": "Access-Control-Allow-Origin permits any origin",
                "severity": "low",
                "endpoint": url,
                "direct_observation": True,
                "evidence_state": "CONFIRMED_OBSERVED",
                "details": {"access_control_allow_origin": "*", "access_control_allow_credentials": lower.get("access-control-allow-credentials")},
            })

        for cookie in cookies[:20]:
            cookie_name = cookie.split("=", 1)[0].strip() or "<unnamed>"
            low_cookie = cookie.lower()
            missing = [flag for flag, present in (
                ("Secure", "secure" in low_cookie),
                ("HttpOnly", "httponly" in low_cookie),
                ("SameSite", "samesite=" in low_cookie),
            ) if not present]
            if missing:
                findings.append({
                    "name": f"Cookie {cookie_name} missing security flags",
                    "severity": "low",
                    "endpoint": url,
                    "direct_observation": True,
                    "evidence_state": "CONFIRMED_OBSERVED",
                    "details": {"cookie": "<redacted>", "missing_flags": missing},
                })

        server = lower.get("server", "")
        if server and re.search(r"/(?:\d+\.\d+)|\b\d+\.\d+(?:\.\d+)?\b", server):
            findings.append({
                "name": "Server header discloses a version",
                "severity": "low",
                "endpoint": url,
                "direct_observation": True,
                "evidence_state": "CONFIRMED_OBSERVED",
                "details": {"server": server},
            })

        if tls_verification_error:
            findings.append({
                "name": "TLS certificate verification failed during HTTP probe",
                "severity": "medium",
                "endpoint": url,
                "direct_observation": True,
                "evidence_state": "CONFIRMED_OBSERVED",
                "details": {"error": tls_verification_error[:500]},
            })
        return findings

    def _fetch(self, url, include_findings=True):
        req = urllib.request.Request(url, headers={"User-Agent": self.USER_AGENT}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw_headers = r.headers
                headers = dict(raw_headers.items())
                cookies = raw_headers.get_all("Set-Cookie") or []
                body = r.read(65536).decode("utf-8", errors="replace")
                base = r.geturl()
                links = []
                for raw in re.findall(r'''(?:href|src|action)\s*=\s*[\"']([^\"']+)[\"']''', body, re.I):
                    absolute = urljoin(base, raw)
                    if self._same_host(absolute, base):
                        links.append(absolute)
                findings = self._findings(base, r.status, headers, cookies) if include_findings else []
                return {
                    "status": "completed",
                    "http_status": r.status,
                    "requested_url": url,
                    "final_url": base,
                    "redirected": base.rstrip("/") != url.rstrip("/"),
                    "server": headers.get("Server"),
                    "content_type": headers.get("Content-Type"),
                    "headers": redact_http_headers(headers),
                    "technologies": sorted(set(extract_technologies(" ".join(headers.values()) + " " + body))),
                    "body_markers": extract_body_markers(body),
                    "discovered_links": sorted(set(links))[:500],
                    "passive_findings": findings,
                }
        except urllib.error.HTTPError as e:
            raw_headers = e.headers
            headers = dict(raw_headers.items()) if raw_headers else {}
            cookies = raw_headers.get_all("Set-Cookie") if raw_headers else []
            findings = self._findings(url, e.code, headers, cookies or []) if include_findings else []
            return {
                "status": "completed",
                "http_status": e.code,
                "requested_url": url,
                "final_url": url,
                "redirected": False,
                "server": headers.get("Server"),
                "content_type": headers.get("Content-Type"),
                "headers": redact_http_headers(headers),
                "technologies": sorted(set(extract_technologies(" ".join(headers.values())))),
                "body_markers": [],
                "discovered_links": [],
                "passive_findings": findings,
            }
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if url.lower().startswith("https://") and isinstance(reason, ssl.SSLCertVerificationError):
                return self._fetch_unverified(url, str(reason), include_findings)
            return {"status": "error", "error": str(e), "passive_findings": []}
        except ssl.SSLCertVerificationError as e:
            return self._fetch_unverified(url, str(e), include_findings)
        except Exception as e:
            return {"status": "error", "error": str(e), "passive_findings": []}

    def _fetch_unverified(self, url: str, tls_error: str, include_findings: bool = True):
        req = urllib.request.Request(url, headers={"User-Agent": self.USER_AGENT + " tls-fallback"}, method="GET")
        context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, timeout=10, context=context) as r:
                raw_headers = r.headers
                headers = dict(raw_headers.items())
                cookies = raw_headers.get_all("Set-Cookie") or []
                body = r.read(65536).decode("utf-8", errors="replace")
                base = r.geturl()
                links = []
                for raw in re.findall(r'''(?:href|src|action)\s*=\s*[\"']([^\"']+)[\"']''', body, re.I):
                    absolute = urljoin(base, raw)
                    if self._same_host(absolute, base):
                        links.append(absolute)
                return {
                    "status": "completed-unverified-tls",
                    "http_status": r.status,
                    "requested_url": url,
                    "final_url": base,
                    "redirected": base.rstrip("/") != url.rstrip("/"),
                    "tls_verification_error": tls_error[:500],
                    "server": headers.get("Server"),
                    "content_type": headers.get("Content-Type"),
                    "headers": redact_http_headers(headers),
                    "technologies": sorted(set(extract_technologies(" ".join(headers.values()) + " " + body))),
                    "body_markers": extract_body_markers(body),
                    "discovered_links": sorted(set(links))[:500],
                    "passive_findings": self._findings(base, r.status, headers, cookies, tls_error) if include_findings else [],
                }
        except Exception as e:
            return {"status": "tls-error", "error": str(e), "tls_verification_error": tls_error[:500], "passive_findings": self._findings(url, None, {}, [], tls_error) if include_findings else []}

    def _run_sync(self):
        data = self._fetch(self.ctx.web_url)
        if self.ctx.passive_depth >= 2:
            extras = {}
            for suffix in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                item = self._fetch(self.ctx.web_url.rstrip("/") + suffix, include_findings=False)
                extras[suffix] = item
            data["passive_resources"] = extras
            data["discovered_links"] = dedupe_ordered(list(data.get("discovered_links", [])))[:500]
        return data
