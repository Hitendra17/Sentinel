"""Fail-closed target and destination validation."""
import ipaddress
import json
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

FORBIDDEN = {"169.254.169.254", "metadata.google.internal"}


def normalize_url(value: str) -> str:
    p = urlsplit(value.strip())
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("URL must be an absolute HTTP(S) URL without userinfo")
    if p.fragment:
        p = p._replace(fragment="")
    host = p.hostname.lower().rstrip(".")
    port = p.port
    netloc = f"[{host}]" if ":" in host else host
    if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
        netloc += f":{port}"
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))


def origin(value: str) -> tuple[str, str, int]:
    p = urlsplit(normalize_url(value))
    return p.scheme, (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80)


@dataclass
class Scope:
    origins: list[str]
    allow_private: bool = False
    expected_https: bool = False
    max_requests: int = 12
    max_response_bytes: int = 1_000_000
    timeout_seconds: float = 5
    max_redirects: int = 3

    @classmethod
    def load(cls, path: str) -> "Scope":
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict) or not isinstance(raw.get("origins"), list) or not raw["origins"]:
            raise ValueError("scope must contain a non-empty origins array")
        origins = [normalize_url(x) for x in raw["origins"]]
        if any(urlsplit(x).path != "/" or urlsplit(x).query for x in origins):
            raise ValueError("scope entries must be origins (no path or query)")
        bounds = {"max_requests": (1, 100), "max_response_bytes": (1024, 10_000_000), "timeout_seconds": (0.1, 30), "max_redirects": (0, 5)}
        for key, (lo, hi) in bounds.items():
            val = raw.get(key, getattr(cls, key, None))
            if val is not None and not lo <= val <= hi:
                raise ValueError(f"{key} must be between {lo} and {hi}")
        return cls(origins=origins, **{k: raw[k] for k in bounds if k in raw}, allow_private=bool(raw.get("allow_private", False)), expected_https=bool(raw.get("expected_https", False)))

    def permits(self, url: str) -> bool:
        try:
            normalized = normalize_url(url)
            return any(origin(normalized) == origin(x) for x in self.origins) and self.safe_address(normalized)
        except (ValueError, OSError):
            return False

    def safe_address(self, url: str) -> bool:
        host = urlsplit(url).hostname or ""
        if host.lower() in FORBIDDEN:
            return False
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                addresses = [ipaddress.ip_address(x[4][0].split("%")[0]) for x in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]
            except OSError:
                return False
        for ip in addresses:
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if not self.allow_private and not ip.is_global:
                return False
        return bool(addresses)
