"""
HTTP Verification Engine
--------------------------
After DNS analysis flags a subdomain as potentially vulnerable,
this module makes HTTP requests to confirm via response body fingerprinting.

Also detects:
  - Specific error pages that confirm unclaimed services
  - SSL certificate mismatches (cert belongs to different domain)
  - Response headers that reveal the backend service
  - Content that confirms the service is unclaimed
"""

import re
import ssl
import socket
from ..core import http_get, R, G, Y, C, DIM, BOLD, RST
from ..fingerprints import get_service_by_body, get_service_by_cname, SERVICES


def verify_via_http(hostname: str, service: dict = None,
                     timeout: int = 10, verbose: bool = True) -> dict:
    """
    Verify subdomain takeover by making HTTP/HTTPS requests
    and matching response against known fingerprints.
    """
    result = {
        "hostname":      hostname,
        "http_status":   None,
        "https_status":  None,
        "body_match":    False,
        "matched_service":None,
        "confirmed":     False,
        "confidence":    "low",
        "evidence":      [],
        "ssl_issue":     None,
        "response_snippet": "",
    }

    # Try HTTP and HTTPS
    for scheme in ("https", "http"):
        url  = f"{scheme}://{hostname}"
        resp = http_get(url, timeout=timeout, follow_redirects=True)

        if resp["status"] == 0:
            continue

        key = f"{scheme}_status"
        result[key] = resp["status"]
        body = resp["body"]

        # Match body against service fingerprints
        matched = service or get_service_by_body(body)

        if matched:
            # Verify the specific fingerprints for this service
            body_lower = body.lower()
            fingerprint_hits = []
            for pattern in matched.get("body", []):
                if re.search(pattern, body_lower):
                    fingerprint_hits.append(pattern)

            if fingerprint_hits:
                result["body_match"]      = True
                result["matched_service"] = matched["service"]
                result["confirmed"]       = True
                result["confidence"]      = "high"
                result["evidence"].extend([
                    f"Body matched: {p}" for p in fingerprint_hits
                ])
                result["response_snippet"] = body[:300]

                if verbose:
                    print(f"  {R}{BOLD}[HTTP CONFIRMED]{RST} {hostname}")
                    print(f"    Service  : {matched['service']}")
                    print(f"    URL      : {url}")
                    print(f"    Status   : {resp['status']}")
                    print(f"    Matched  : {fingerprint_hits[0][:60]}")
                    if matched.get("difficulty"):
                        print(f"    Difficulty: {matched['difficulty']}")
                break  # confirmed via one scheme — stop

        # Check for interesting status codes even without body match
        if resp["status"] in (404, 403) and not result["confirmed"]:
            result[key] = resp["status"]
            result["response_snippet"] = body[:200]

    # SSL certificate check
    ssl_info = check_ssl_cert(hostname)
    result["ssl_issue"] = ssl_info

    return result


def check_ssl_cert(hostname: str, timeout: int = 5) -> dict:
    """
    Check SSL certificate for the hostname.
    Mismatched or expired certs can indicate:
      - The original service is gone
      - A different tenant is using this cert
    """
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=timeout),
            server_hostname=hostname
        ) as ssock:
            cert = ssock.getpeercert()
            cn   = dict(x[0] for x in cert.get("subject", [{}])).get("commonName", "")
            sans = []
            for san_type, san_value in cert.get("subjectAltName", []):
                if san_type == "DNS":
                    sans.append(san_value)

            # Check if cert covers our hostname
            covers = (
                cn == hostname or
                hostname in sans or
                any(san.startswith("*.") and hostname.endswith(san[1:]) for san in sans)
            )

            return {
                "valid":   True,
                "cn":      cn,
                "sans":    sans[:5],
                "covers":  covers,
                "mismatch":not covers,
            }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": "cert_verification_failed", "detail": str(e)}
    except ssl.CertificateError as e:
        return {"valid": False, "error": "cert_mismatch", "detail": str(e),
                "mismatch": True}
    except Exception as e:
        return {"valid": None, "error": str(e)}


def check_response_headers(hostname: str) -> dict:
    """
    Analyze response headers for service indicators.
    Some services reveal themselves in headers even before body matching.
    """
    url  = f"https://{hostname}"
    resp = http_get(url, timeout=8)

    indicators = {}
    headers    = resp.get("headers", {})

    # Server header
    server = headers.get("server", "")
    if server:
        indicators["server"] = server

    # X-Powered-By
    xpb = headers.get("x-powered-by", "")
    if xpb:
        indicators["x_powered_by"] = xpb

    # Cloud/CDN indicators
    for hdr, key in [
        ("cf-ray",                "cloudflare"),
        ("x-amz-request-id",      "aws"),
        ("x-ms-request-id",       "azure"),
        ("x-goog-hash",           "gcp"),
        ("x-github-request-id",   "github"),
        ("x-heroku-queue-depth",  "heroku"),
        ("fly-request-id",        "fly_io"),
        ("x-vercel-id",           "vercel"),
        ("x-netlify-cache-tag",   "netlify"),
    ]:
        if hdr in headers:
            indicators[key] = True

    return indicators
