"""Bounded HTTP client with manually validated redirects and body limits."""
import http.client
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin

from sentinel.scope import Scope, normalize_url
from sentinel.redaction import safe_headers, safe_url

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

@dataclass
class Response:
    url: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    error: str | None = None
    redirects: list[str] | None = None


def _header_size(headers) -> int:
    """Approximate the wire size of response headers."""
    return sum(len(str(name)) + len(str(value)) + 4 for name, value in headers.items())

class BoundedClient:
    max_header_bytes = 64 * 1024

    def __init__(self, scope: Scope):
        self.scope = scope
        self.count = 0
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, url: str, method: str = "GET") -> Response:
        start = time.monotonic()
        deadline = start + self.scope.timeout_seconds
        redirects = []
        current = url
        try:
            if not isinstance(method, str):
                raise ValueError("method must be a string")
            method = method.upper()
            if method not in {"GET", "HEAD"}:
                raise ValueError("only GET and HEAD are allowed")
            current = normalize_url(url)
            for hop in range(self.scope.max_redirects + 1):
                if self.count >= self.scope.max_requests: raise RuntimeError("request budget exhausted")
                if not self.scope.permits(current): raise ValueError("destination is outside scope or resolves to a prohibited address")
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise TimeoutError("request deadline exceeded")
                self.count += 1
                req = urllib.request.Request(current, method=method, headers={"User-Agent": "Sentinel/0.1 (authorized security research; bounded)"})
                try:
                    resp = self.opener.open(req, timeout=min(self.scope.timeout_seconds, remaining))
                except urllib.error.HTTPError as e:
                    resp = e
                status = getattr(resp, "status", getattr(resp, "code", None))
                if _header_size(resp.headers) > self.max_header_bytes:
                    resp.close()
                    return Response(safe_url(current), status, {}, b"", (time.monotonic()-start)*1000, "response headers exceeded size limit", redirects)
                headers = dict(resp.headers.items())
                if status in {301, 302, 303, 307, 308}:
                    loc = resp.headers.get("Location")
                    resp.close()
                    if not loc or hop >= self.scope.max_redirects: return Response(safe_url(current), status, safe_headers(headers), b"", (time.monotonic()-start)*1000, "redirect limit or missing Location", redirects)
                    nxt = normalize_url(urljoin(current, loc))
                    safe_nxt = safe_url(nxt)
                    if not self.scope.permits(nxt): return Response(safe_url(current), status, safe_headers(headers), b"", (time.monotonic()-start)*1000, "blocked out-of-scope redirect", redirects + [safe_nxt])
                    redirects.append(safe_nxt); current = nxt; continue
                content_length = resp.headers.get("Content-Length")
                if content_length:
                    try:
                        if int(content_length) > self.scope.max_response_bytes:
                            resp.close()
                            return Response(safe_url(current), status, safe_headers(headers), b"", (time.monotonic()-start)*1000, "response exceeded size limit", redirects)
                    except ValueError:
                        pass
                try:
                    body = b"" if method == "HEAD" else resp.read(self.scope.max_response_bytes + 1)
                finally:
                    resp.close()
                if time.monotonic() > deadline: return Response(safe_url(current), status, safe_headers(headers), b"", (time.monotonic()-start)*1000, "request deadline exceeded", redirects)
                if len(body) > self.scope.max_response_bytes: return Response(safe_url(current), status, safe_headers(headers), b"", (time.monotonic()-start)*1000, "response exceeded size limit", redirects)
                return Response(safe_url(current), status, safe_headers(headers), body, (time.monotonic()-start)*1000, None, redirects)
        except (OSError, urllib.error.URLError, TimeoutError, http.client.HTTPException, ValueError, RuntimeError) as e:
            return Response(safe_url(current), None, {}, b"", (time.monotonic()-start)*1000, str(e)[:200], redirects)
        return Response(safe_url(current), None, {}, b"", (time.monotonic()-start)*1000, "request failed", redirects)
