"""
Subdomain Takeover Scanner — Main Orchestrator
"""

import json
import time
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from .core import resolve_a, resolve_cname, is_nxdomain, get_domain_root, R, G, Y, C, DIM, BOLD, RST
from .fingerprints import get_service_by_cname, get_service_by_body, SERVICES
from .checks.cname_check import check_cname_dangling, check_ns_takeover, check_wildcard_subdomain
from .checks.http_verify import verify_via_http, check_response_headers
from .checks.subdomain_enum import discover_all


def scan_subdomain(hostname: str, verbose: bool = True) -> dict:
    """
    Full takeover check for a single subdomain.
    1. CNAME chain analysis
    2. NS takeover check
    3. HTTP verification
    4. Confidence scoring
    """
    result = {
        "hostname":     hostname,
        "vulnerable":   False,
        "confirmed":    False,
        "takeover_type":None,
        "service":      None,
        "confidence":   "none",
        "difficulty":   None,
        "cname_chain":  [],
        "final_cname":  None,
        "nxdomain":     False,
        "http_verified":False,
        "instructions": None,
        "severity":     None,
        "evidence":     [],
        "checked_at":   datetime.datetime.utcnow().isoformat(),
    }

    # Step 1: CNAME analysis
    cname_result = check_cname_dangling(hostname, verbose=False)
    result["cname_chain"] = cname_result["cname_chain"]
    result["final_cname"] = cname_result["final_cname"]
    result["nxdomain"]    = cname_result["nxdomain"]

    if cname_result["vulnerable"]:
        result["vulnerable"]    = True
        result["service"]       = cname_result["service"]
        result["takeover_type"] = cname_result["takeover_type"]
        result["confidence"]    = cname_result["confidence"]
        result["difficulty"]    = cname_result["difficulty"]
        result["instructions"]  = cname_result["instructions"]
        result["evidence"].append(
            f"CNAME → {cname_result['final_cname']}"
            + (" (NXDOMAIN)" if cname_result["nxdomain"] else "")
        )

    # Step 2: NS takeover check
    ns_result = check_ns_takeover(hostname, verbose=False)
    if ns_result["vulnerable"]:
        result["vulnerable"]    = True
        result["takeover_type"] = "ns_takeover"
        result["confidence"]    = "high"
        result["difficulty"]    = "hard"
        result["evidence"].extend([
            f"NS record NXDOMAIN: {ns}" for ns in ns_result["expired_ns"]
        ])

    # Step 3: HTTP verification (only if CNAME looks suspicious)
    if result["vulnerable"] or cname_result.get("final_cname"):
        service_hint = None
        if cname_result.get("final_cname"):
            service_hint = get_service_by_cname(cname_result["final_cname"])

        http_result = verify_via_http(hostname, service=service_hint,
                                       verbose=False)

        if http_result["confirmed"]:
            result["http_verified"] = True
            result["confirmed"]     = True
            result["vulnerable"]    = True
            result["confidence"]    = "high"
            if http_result.get("matched_service"):
                result["service"] = http_result["matched_service"]
            result["evidence"].extend(http_result.get("evidence", []))
            if http_result.get("response_snippet"):
                result["response_snippet"] = http_result["response_snippet"]

        if http_result["http_status"]:
            result["http_status"] = http_result["http_status"]

    # Step 4: Severity scoring
    if result["confirmed"] and result["confidence"] == "high":
        result["severity"] = "Critical"
    elif result["vulnerable"] and result["confidence"] in ("high", "medium"):
        result["severity"] = "High"
    elif result["vulnerable"]:
        result["severity"] = "Medium"

    # Print finding
    if result["vulnerable"] and verbose:
        sev_color = R if result["severity"] in ("Critical", "High") else Y
        conf_tag  = f"[{result['confidence']}]"
        verb_tag  = f"{G}[CONFIRMED]{RST}" if result["confirmed"] else f"{Y}[POSSIBLE]{RST}"
        print(f"\n  {sev_color}{BOLD}[TAKEOVER]{RST} {verb_tag} {hostname}")
        print(f"    Service    : {result['service'] or 'Unknown'}")
        print(f"    Type       : {result['takeover_type']}")
        print(f"    Confidence : {result['confidence']} {conf_tag}")
        if result.get("final_cname"):
            print(f"    CNAME      : {result['final_cname']}")
        if result.get("nxdomain"):
            print(f"    NXDOMAIN   : {R}YES — target domain does not exist{RST}")
        if result.get("difficulty"):
            print(f"    Difficulty : {result['difficulty']}")
        if result.get("instructions"):
            print(f"    {G}[HOW TO TAKE OVER]{RST}")
            for line in result["instructions"].splitlines():
                print(f"      {line}")
        print()

    return result


def scan(target: str, subdomains: list = None,
          discover: bool = True, threads: int = 30,
          sources: list = None, brute: bool = True,
          wordlist: list = None, permute: bool = False,
          filter_live: bool = True, verbose: bool = True) -> dict:
    """
    Full subdomain takeover scan.

    Args:
        target:     Root domain (e.g. target.com) or single subdomain
        subdomains: Pre-supplied list of subdomains to check
        discover:   Auto-discover subdomains from passive sources
        threads:    Parallel scan threads
        sources:    Passive sources to use
        brute:      Brute force subdomains
        wordlist:   Custom wordlist for brute force
        permute:    Generate permutations of found subdomains
        filter_live:Only check subdomains that resolve (skip NXDOMAIN early)
        verbose:    Print progress

    Returns:
        Full results dict
    """
    results = {
        "target":        target,
        "start_time":    datetime.datetime.utcnow().isoformat(),
        "subdomains_checked": 0,
        "findings":      [],
        "confirmed":     [],
        "possible":      [],
        "wildcard":      None,
        "stats":         {},
    }

    if verbose:
        print(f"\n{R}{BOLD}{'═'*60}{RST}")
        print(f"{R}{BOLD}  SUBDOMAIN TAKEOVER SCANNER{RST}")
        print(f"{R}{BOLD}{'═'*60}{RST}")
        print(f"  {C}Target{RST}   : {target}")
        print(f"  {C}Threads{RST}  : {threads}")
        print()

    # Determine root domain
    root = get_domain_root(target) if "." in target else target

    # Check for wildcard DNS (avoid false positives)
    if verbose:
        print(f"{Y}[STEP 1] Wildcard DNS Check{RST}")
    wildcard = check_wildcard_subdomain(root)
    results["wildcard"] = wildcard
    if wildcard["has_wildcard"]:
        if verbose:
            print(f"  {Y}[!] Wildcard DNS detected: *.{root} → {wildcard['wildcard_ips']}")
            print(f"  {Y}    False positives likely — results will be filtered carefully{RST}\n")
    else:
        if verbose:
            print(f"  {G}[+]{RST} No wildcard DNS — clean environment\n")

    # Subdomain discovery
    if subdomains:
        all_subs = subdomains
        if verbose:
            print(f"  {G}[+]{RST} Using {len(all_subs)} provided subdomains\n")
    elif discover:
        if verbose:
            print(f"{Y}[STEP 2] Subdomain Discovery{RST}")
        all_subs = discover_all(
            root, wordlist=wordlist, sources=sources,
            brute=brute, permute=permute, threads=threads,
            verbose=verbose
        )
    else:
        all_subs = [target]

    # Filter out wildcard matches
    if wildcard["has_wildcard"]:
        wildcard_ips = set(wildcard["wildcard_ips"])
        filtered = []
        for sub in all_subs:
            ips = resolve_a(sub)
            if not ips or not set(ips).issubset(wildcard_ips):
                filtered.append(sub)
        if verbose and len(filtered) < len(all_subs):
            removed = len(all_subs) - len(filtered)
            print(f"  {DIM}[*] Filtered {removed} wildcard matches{RST}")
        all_subs = filtered

    results["subdomains_checked"] = len(all_subs)

    if verbose:
        print(f"{Y}[STEP 3] Takeover Scanning ({len(all_subs)} subdomains){RST}\n")

    # Scan each subdomain in parallel
    findings   = []
    checked    = 0
    found_count= 0
    lock       = threading.Lock()

    def scan_one(sub):
        nonlocal checked, found_count
        try:
            result = scan_subdomain(sub, verbose=verbose)
            with lock:
                checked += 1
                if result["vulnerable"]:
                    found_count += 1
                if verbose and not result["vulnerable"]:
                    pct = (checked / len(all_subs)) * 100
                    print(f"  {DIM}[{pct:5.1f}%] {checked}/{len(all_subs)} "
                          f"checked | {found_count} found{RST}", end="\r")
            return result
        except Exception:
            return {"hostname": sub, "vulnerable": False}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_one, sub): sub for sub in all_subs}
        for future in as_completed(futures):
            result = future.result()
            findings.append(result)

    if verbose:
        print(f"\r{' '*70}\r", end="")

    # Sort findings
    results["findings"]  = findings
    results["confirmed"] = [f for f in findings if f.get("confirmed")]
    results["possible"]  = [f for f in findings if f.get("vulnerable") and not f.get("confirmed")]

    stats = {"total": len(findings), "vulnerable": len([f for f in findings if f.get("vulnerable")]),
             "confirmed": len(results["confirmed"]), "possible": len(results["possible"])}
    results["stats"] = stats

    if verbose:
        _print_summary(results)

    return results


def _print_summary(results: dict):
    confirmed = results["confirmed"]
    possible  = results["possible"]
    stats     = results["stats"]

    print(f"\n{R}{BOLD}{'═'*60}{RST}")
    print(f"{R}{BOLD}  SCAN COMPLETE{RST}")
    print(f"{R}{BOLD}{'═'*60}{RST}\n")
    print(f"  Subdomains checked : {stats['total']}")
    print(f"  Vulnerable         : {stats['vulnerable']}")
    print(f"  Confirmed          : {R}{BOLD}{stats['confirmed']}{RST}")
    print(f"  Possible           : {Y}{stats['possible']}{RST}")

    if confirmed:
        print(f"\n  {R}{BOLD}CONFIRMED TAKEOVERS:{RST}")
        for f in confirmed:
            print(f"    {G}→{RST} {f['hostname']}")
            print(f"       Service: {f.get('service','Unknown')} | "
                  f"Difficulty: {f.get('difficulty','?')}")

    if possible:
        print(f"\n  {Y}POSSIBLE TAKEOVERS (verify manually):{RST}")
        for f in possible:
            print(f"    → {f['hostname']} ({f.get('service','?')})")
    print()
