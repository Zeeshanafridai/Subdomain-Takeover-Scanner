#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       SUBDOMAIN TAKEOVER SCANNER  —  by 0xZ33                ║
║     github.com/Zeeshanafridai/subdomain-takeover-scanner     ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from takeover.scanner import scan, scan_subdomain
from takeover.core import R, G, Y, C, DIM, BOLD, RST
from takeover.report.generator import generate as gen_report

BANNER = f"""
{R}
  ████████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗   ██╗███████╗██████╗
  ╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗
     ██║   ███████║█████╔╝ █████╗  ██║   ██║██║   ██║█████╗  ██████╔╝
     ██║   ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
     ██║   ██║  ██║██║  ██╗███████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝
{RST}{DIM}  Subdomain Takeover Scanner — CNAME/NS Dangling, 50+ Services, CT Logs, HTTP Verify{RST}
"""


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="subdomain-takeover",
        description="Subdomain Takeover Scanner"
    )

    # Target
    target_grp = parser.add_mutually_exclusive_group(required=True)
    target_grp.add_argument("-d", "--domain",
                             help="Root domain to scan (e.g. target.com)")
    target_grp.add_argument("-s", "--subdomain",
                             help="Single subdomain to check")
    target_grp.add_argument("-l", "--list",
                             help="File with subdomains (one per line)")

    # Discovery options
    parser.add_argument("--no-discover",   action="store_true",
                        help="Skip passive subdomain discovery")
    parser.add_argument("--no-brute",      action="store_true",
                        help="Skip brute force subdomain enumeration")
    parser.add_argument("--permute",       action="store_true",
                        help="Generate subdomain permutations")
    parser.add_argument("--wordlist",      help="Custom brute force wordlist")
    parser.add_argument("--sources",       nargs="+",
                        choices=["crtsh","wayback","alienvault","rapiddns","hackertarget"],
                        help="Passive sources to use (default: all)")

    # Scan options
    parser.add_argument("--threads",       type=int, default=30,
                        help="Parallel scan threads (default: 30)")

    # Output
    parser.add_argument("--report",        action="store_true")
    parser.add_argument("--report-prefix", default="takeover_report")
    parser.add_argument("-o", "--output",  help="Save raw JSON results")
    parser.add_argument("--only-vulnerable", action="store_true",
                        help="Output only vulnerable subdomains")
    parser.add_argument("-q", "--quiet",   action="store_true")

    args = parser.parse_args()

    # Load wordlist
    wordlist = None
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [l.strip() for l in f if l.strip()]

    # Load subdomain list
    subdomains = None
    if args.list:
        with open(args.list) as f:
            subdomains = [l.strip() for l in f if l.strip()]

    if args.subdomain:
        # Single subdomain check
        result = scan_subdomain(args.subdomain, verbose=not args.quiet)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2, default=str)
        return

    # Full domain scan
    results = scan(
        target     = args.domain or args.list,
        subdomains = subdomains,
        discover   = not args.no_discover,
        threads    = args.threads,
        sources    = args.sources,
        brute      = not args.no_brute,
        wordlist   = wordlist,
        permute    = args.permute,
        verbose    = not args.quiet,
    )

    if args.report:
        paths = gen_report(results, args.report_prefix)
        print(f"\n{C}[*] Reports:{RST}")
        print(f"    JSON     : {paths['json']}")
        print(f"    Markdown : {paths['markdown']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{G}[+] Results: {args.output}{RST}")

    if args.only_vulnerable:
        vulns = [f["hostname"] for f in results.get("findings", [])
                 if f.get("vulnerable")]
        for v in vulns:
            print(v)


if __name__ == "__main__":
    main()
