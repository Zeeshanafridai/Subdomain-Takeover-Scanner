from typing import Optional
"""
Core DNS + HTTP engine for subdomain takeover detection.
"""

import socket
import ssl
import urllib.request
import urllib.error
import time
import re
import json
from typing import Optional

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
C    = "\033[96m"
DIM  = "\033[90m"
BOLD = "\033[1m"
RST  = "\033[0m"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

# Public resolvers for DNS queries
DNS_RESOLVERS = [
    "1.1.1.1",   # Cloudflare
    "8.8.8.8",   # Google
    "9.9.9.9",   # Quad9
    "208.67.222.222",  # OpenDNS
]


def resolve_cname(hostname: str, timeout: int = 5) -> Optional[str]:
    """
    Resolve CNAME for a hostname.
    Returns the CNAME target or None.
    """
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "CNAME", hostname],
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout.strip()
        if output and not output.startswith(";"):
            return output.rstrip(".")
        return None
    except FileNotFoundError:
        # dig not available — use socket
        pass
    except Exception:
        pass

    # Fallback: try to detect via nxdomain
    try:
        answers = socket.getaddrinfo(hostname, None)
        if answers:
            return "resolves"
    except socket.gaierror:
        return None
    return None


def resolve_a(hostname: str, timeout: int = 5) -> list:
    """Resolve A records for hostname. Returns list of IPs."""
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list(set(r[4][0] for r in results))
        return ips
    except socket.gaierror:
        return []
    except Exception:
        return []


def resolve_ns(hostname: str, timeout: int = 5) -> list:
    """Resolve NS records via dig."""
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "NS", hostname],
            capture_output=True, text=True, timeout=timeout
        )
        lines = [l.strip().rstrip(".") for l in result.stdout.strip().splitlines()
                 if l.strip() and not l.startswith(";")]
        return lines
    except Exception:
        return []


def resolve_mx(hostname: str, timeout: int = 5) -> list:
    """Resolve MX records via dig."""
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "MX", hostname],
            capture_output=True, text=True, timeout=timeout
        )
        lines = [l.strip() for l in result.stdout.strip().splitlines()
                 if l.strip() and not l.startswith(";")]
        return lines
    except Exception:
        return []


def is_nxdomain(hostname: str) -> bool:
    """Check if hostname resolves to NXDOMAIN (non-existent)."""
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(hostname, None)
        return False
    except socket.gaierror as e:
        if "Name or service not known" in str(e) or "No address" in str(e):
            return True
        return False
    except Exception:
        return False


def http_get(url: str, timeout: int = 10,
              follow_redirects: bool = True,
              extra_headers: dict = None) -> dict:
    """HTTP GET with full response capture."""
    headers = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)

    try:
        req = urllib.request.Request(url, headers=headers)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None

        if follow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX)
            )
        else:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX),
                NoRedirect()
            )

        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(256 * 1024).decode("utf-8", errors="replace")
            return {
                "status":   resp.status,
                "headers":  {k.lower(): v for k, v in dict(resp.headers).items()},
                "body":     body,
                "url":      resp.url,
                "error":    None,
            }
    except urllib.error.HTTPError as e:
        try:
            body = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "status": e.code,
            "headers": {k.lower(): v for k, v in dict(e.headers).items()} if e.headers else {},
            "body":   body,
            "url":    url,
            "error":  str(e),
        }
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}


def get_domain_root(subdomain: str) -> str:
    """Extract root domain from subdomain. e.g. api.target.com → target.com"""
    parts = subdomain.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return subdomain
