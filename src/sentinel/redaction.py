"""Small, conservative redaction helpers; never retain cookie values."""
import re
from urllib.parse import urlsplit, urlunsplit

SENSITIVE = re.compile(r"(?i)(authorization|cookie|set-cookie|api[_-]?key|password|token)\s*[:=]\s*(?:bearer\s+)?([^;\s,]+)")

def redact(text: str) -> str:
    return SENSITIVE.sub(r"\1: [REDACTED]", text)


def safe_url(value: str) -> str:
    """Preserve URL identity without retaining query-string values."""
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))

def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    allowed = {"content-type", "content-length", "server", "strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "location"}
    safe = {k.lower(): ("[REDACTED]" if k.lower() == "location" else redact(v)) for k, v in headers.items() if k.lower() in allowed}
    cookie = next((v for k, v in headers.items() if k.lower() == "set-cookie"), None)
    if cookie:
        parts = cookie.split(";")
        safe["set-cookie"] = "; ".join(["[COOKIE VALUE REDACTED]"] + [p.strip() for p in parts[1:]])
    return safe
