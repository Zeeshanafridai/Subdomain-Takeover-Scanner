"""
CNAME Chain Analyzer
----------------------
Walks the full CNAME chain for a subdomain.
Detects dangling CNAMEs where the final target:
  - Is NXDOMAIN (domain doesn't exist)
  - Points to an unclaimed cloud service
  - Has an expired NS record

Also detects:
  - NS delegation to non-existent domains
  - Wildcard DNS abuse
  - Subdomain enumeration via zone transfer (AXFR)
"""

import subprocess
import re
import time
from ..core import resolve_cname, resolve_a, resolve_ns, is_nxdomain, R, G, Y, C, DIM, BOLD, RST
from ..fingerprints import get_service_by_cname, SERVICES


def get_cname_chain(hostname: str, max_depth: int = 10) -> list:
    """
    Follow the full CNAME chain for a hostname.
    Returns list of (hostname, cname_target) tuples.
    """
    chain = []
    current = hostname
    seen = set()

    for _ in range(max_depth):
        if current in seen:
            break
        seen.add(current)

        cname = resolve_cname(current)
        if not cname or cname == "resolves":
            break

        chain.append({"from": current, "to": cname})
        current = cname

    return chain


def check_cname_dangling(hostname: str, verbose: bool = False) -> dict:
    """
    Full CNAME dangling check.
    Returns finding dict with vulnerability assessment.
    """
    result = {
        "hostname":   hostname,
        "cname_chain":  [],
        "final_cname":  None,
        "nxdomain":     False,
        "service":      None,
        "vulnerable":   False,
        "confidence":   "low",
        "takeover_type":None,
        "difficulty":   None,
        "instructions": None,
    }

    # Build CNAME chain
    chain = get_cname_chain(hostname)
    result["cname_chain"] = chain

    if not chain:
        return result

    final_cname = chain[-1]["to"]
    result["final_cname"] = final_cname

    # Check if final CNAME is NXDOMAIN
    nxdomain = is_nxdomain(final_cname)
    result["nxdomain"] = nxdomain

    # Match against known services
    service = get_service_by_cname(final_cname)

    if service:
        result["service"] = service["service"]
        result["difficulty"] = service.get("difficulty")
        result["instructions"] = service.get("instructions")

        if nxdomain or service.get("takeable"):
            result["vulnerable"]    = True
            result["confidence"]    = "high" if nxdomain else "medium"
            result["takeover_type"] = "cname_dangling"

    elif nxdomain:
        # CNAME points to NXDOMAIN but no known service — still interesting
        result["vulnerable"]    = True
        result["confidence"]    = "medium"
        result["takeover_type"] = "cname_nxdomain_unknown"
        result["service"]       = "Unknown (NXDOMAIN)"
        result["instructions"]  = f"Register the domain: {final_cname}"

    return result


def check_ns_takeover(hostname: str, verbose: bool = False) -> dict:
    """
    Check for NS-level takeover vulnerability.
    If a subdomain's NS records point to a domain that can be registered,
    registering that domain gives full DNS control.
    """
    result = {
        "hostname":     hostname,
        "ns_records":   [],
        "vulnerable":   False,
        "confidence":   "low",
        "takeover_type":None,
        "expired_ns":   [],
    }

    ns_records = resolve_ns(hostname)
    result["ns_records"] = ns_records

    for ns in ns_records:
        ns_root = ns.rstrip(".")
        # Check if NS domain itself is NXDOMAIN
        if is_nxdomain(ns_root):
            result["vulnerable"]    = True
            result["confidence"]    = "high"
            result["takeover_type"] = "ns_expired"
            result["expired_ns"].append(ns_root)
            if verbose:
                print(f"  {R}{BOLD}[NS TAKEOVER]{RST} {hostname} → NS={ns_root} (NXDOMAIN!)")

    return result


def check_wildcard_subdomain(root_domain: str) -> dict:
    """
    Check if root domain has wildcard DNS (*.domain.com → some IP).
    Wildcard DNS can make false positives appear for non-existent subdomains.
    """
    test_sub = f"z33nonexistent99999.{root_domain}"
    ips = resolve_a(test_sub)
    has_wildcard = len(ips) > 0

    return {
        "has_wildcard": has_wildcard,
        "wildcard_ips": ips,
        "test_subdomain": test_sub,
    }


def try_zone_transfer(domain: str, timeout: int = 5) -> list:
    """
    Attempt DNS zone transfer (AXFR) — reveals all subdomains if allowed.
    Most servers disable this but worth trying.
    """
    subdomains = []
    ns_records = resolve_ns(domain)

    for ns in ns_records[:3]:
        try:
            result = subprocess.run(
                ["dig", f"@{ns}", domain, "AXFR"],
                capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout

            if "Transfer failed" in output or "REFUSED" in output:
                continue

            # Parse subdomains from AXFR output
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    name = parts[0].rstrip(".")
                    rtype = parts[3]
                    if rtype in ("A", "CNAME", "MX") and name.endswith(domain):
                        subdomains.append(name)

        except Exception:
            continue

    return list(set(subdomains))
