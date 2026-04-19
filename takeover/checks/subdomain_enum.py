"""
Subdomain Discovery Engine
----------------------------
Finds subdomains via multiple passive and active sources:

Passive (no direct target interaction):
  - Certificate Transparency logs (crt.sh)
  - Wayback Machine / Web Archive
  - DNS Dumpster
  - AlienVault OTX
  - RapidDNS
  - SecurityTrails (if API key provided)
  - Common wordlist brute force

Active (direct DNS queries):
  - Common subdomain wordlist brute force
  - DNS zone transfer attempt (AXFR)
  - Permutation/alteration of known subdomains
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import resolve_a, is_nxdomain, R, G, Y, C, DIM, BOLD, RST

DEFAULT_UA = "Mozilla/5.0 (compatible; SubdomainScanner/1.0)"

# Common subdomains for brute force
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
    "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
    "ww42", "mx", "email", "mail3", "mobile", "static", "docs",
    "beta", "api", "demo", "staging", "admin", "login", "app",
    "dashboard", "assets", "img", "cdn", "media", "download",
    "upload", "files", "data", "db", "mysql", "redis", "mongo",
    "jenkins", "ci", "git", "gitlab", "github", "jira", "confluence",
    "wiki", "intranet", "internal", "corp", "office", "vpn2",
    "prod", "production", "preprod", "uat", "qa", "sandbox",
    "old", "new", "v1", "v2", "v3", "api2", "api-v1", "api-v2",
    "microservice", "service", "services", "gateway", "proxy",
    "analytics", "tracking", "metrics", "monitor", "logs",
    "auth", "sso", "oauth", "login2", "account", "accounts",
    "user", "users", "profile", "profiles", "member", "members",
    "help", "helpdesk", "support2", "kb", "knowledge",
    "status", "health", "ping", "heartbeat",
    "billing", "pay", "payment", "checkout", "invoice",
    "aws", "gcp", "azure", "cloud", "k8s", "kubernetes",
    "docker", "container", "registry",
    "mx1", "mx2", "smtp2", "imap", "pop", "relay",
    "preview", "draft", "testing", "devel",
    "customer", "partner", "vendor", "b2b",
    "es", "de", "fr", "uk", "us", "jp", "cn",
    "backup", "archive", "mirror", "failover",
    "search", "query", "index",
    "socket", "ws", "websocket", "stream", "streaming",
    "graphql", "grpc", "rpc",
    "android", "ios", "mobile-api",
    "3rd", "third", "external", "ext",
    "manage", "mgmt", "management", "control",
    "panel", "cpanel", "whm", "plesk",
    "stats", "report", "reporting",
    "smtp-relay", "outbound", "inbound",
    "noreply", "no-reply", "bounce", "mailer",
]


def _fetch_json(url: str, timeout: int = 15) -> dict:
    """Fetch JSON from URL."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": DEFAULT_UA, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}


def _fetch_text(url: str, timeout: int = 15) -> str:
    """Fetch text from URL."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": DEFAULT_UA, "Accept": "text/plain,*/*"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception:
        return ""


def from_crtsh(domain: str, verbose: bool = True) -> list:
    """
    Fetch subdomains from Certificate Transparency logs via crt.sh.
    Most comprehensive passive source.
    """
    subdomains = set()

    try:
        url  = f"https://crt.sh/?q=%.{domain}&output=json"
        data = _fetch_json(url)

        if isinstance(data, list):
            for entry in data:
                name = entry.get("name_value", "") or entry.get("common_name", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub.lower())

    except Exception:
        pass

    if verbose and subdomains:
        print(f"  {G}[crt.sh]{RST}    {len(subdomains)} subdomains")

    return list(subdomains)


def from_wayback(domain: str, verbose: bool = True) -> list:
    """Fetch subdomains from Wayback Machine CDX API."""
    subdomains = set()

    try:
        url  = (f"http://web.archive.org/cdx/search/cdx?"
                f"url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=5000")
        text = _fetch_text(url)

        for line in text.splitlines():
            m = re.search(r'https?://([^/]+)', line)
            if m:
                host = m.group(1).lower().split(":")[0]
                if host.endswith(f".{domain}"):
                    subdomains.add(host)

    except Exception:
        pass

    if verbose and subdomains:
        print(f"  {G}[Wayback]{RST}   {len(subdomains)} subdomains")

    return list(subdomains)


def from_alienvault(domain: str, verbose: bool = True) -> list:
    """Fetch subdomains from AlienVault OTX."""
    subdomains = set()

    try:
        url  = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        data = _fetch_json(url)

        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").lower()
            if hostname.endswith(f".{domain}") or hostname == domain:
                subdomains.add(hostname)

    except Exception:
        pass

    if verbose and subdomains:
        print(f"  {G}[AlienVault]{RST} {len(subdomains)} subdomains")

    return list(subdomains)


def from_rapiddns(domain: str, verbose: bool = True) -> list:
    """Fetch subdomains from RapidDNS."""
    subdomains = set()

    try:
        url  = f"https://rapiddns.io/subdomain/{domain}?full=1"
        text = _fetch_text(url)

        for m in re.finditer(r'<td>([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</td>', text):
            subdomains.add(m.group(1).lower())

    except Exception:
        pass

    if verbose and subdomains:
        print(f"  {G}[RapidDNS]{RST}  {len(subdomains)} subdomains")

    return list(subdomains)


def from_hackertarget(domain: str, verbose: bool = True) -> list:
    """Fetch subdomains from HackerTarget."""
    subdomains = set()

    try:
        url  = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        text = _fetch_text(url)

        if "API count exceeded" in text or "error" in text.lower()[:50]:
            return []

        for line in text.splitlines():
            if "," in line:
                host = line.split(",")[0].strip().lower()
                if host.endswith(f".{domain}") or host == domain:
                    subdomains.add(host)

    except Exception:
        pass

    if verbose and subdomains:
        print(f"  {G}[HackerTarget]{RST} {len(subdomains)} subdomains")

    return list(subdomains)


def brute_force(domain: str, wordlist: list = None,
                threads: int = 50, verbose: bool = True) -> list:
    """
    Brute force subdomains via DNS resolution.
    Returns only those that resolve.
    """
    candidates = wordlist or COMMON_SUBDOMAINS
    found      = []
    checked    = 0
    total      = len(candidates)
    lock       = threading.Lock()

    def check(word):
        nonlocal checked
        hostname = f"{word}.{domain}"
        ips = resolve_a(hostname)
        with lock:
            checked += 1
            if checked % 100 == 0 and verbose:
                pct = (checked / total) * 100
                print(f"  {DIM}[{pct:5.1f}%] brute force... {len(found)} found{RST}",
                      end="\r")
        if ips:
            return hostname
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check, w): w for w in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    if verbose:
        print(f"\r{' '*60}\r", end="")
        if found:
            print(f"  {G}[Brute]{RST}     {len(found)} subdomains resolved")

    return found


def generate_permutations(known_subdomains: list, domain: str) -> list:
    """
    Generate permutations of known subdomains.
    E.g. api.target.com → api2, api-v2, api-old, api-dev, etc.
    """
    prefixes  = ["dev", "staging", "test", "old", "new", "v2", "v3",
                  "beta", "prod", "internal", "api", "2", "3", "-v2", "-old"]
    suffixes  = ["-dev", "-test", "-staging", "-old", "-new", "-v2",
                  "-beta", "-prod", "2", "3"]

    perms = set()
    for sub in known_subdomains:
        base = sub.replace(f".{domain}", "").split(".")[0]
        for p in prefixes:
            perms.add(f"{p}-{base}.{domain}")
            perms.add(f"{base}-{p}.{domain}")
            perms.add(f"{p}{base}.{domain}")
        for s in suffixes:
            perms.add(f"{base}{s}.{domain}")

    # Filter to only those that resolve
    found = []
    for perm in list(perms)[:500]:
        ips = resolve_a(perm)
        if ips:
            found.append(perm)

    return found


def discover_all(domain: str, wordlist: list = None,
                  sources: list = None, threads: int = 50,
                  brute: bool = True, permute: bool = False,
                  verbose: bool = True) -> list:
    """
    Full subdomain discovery from all sources.
    Returns deduplicated list of subdomains.
    """
    all_subs = set()
    active_sources = sources or ["crtsh", "wayback", "alienvault",
                                   "rapiddns", "hackertarget"]

    if verbose:
        print(f"\n  {C}[SUBDOMAIN DISCOVERY]{RST} Target: {domain}")
        print(f"  {DIM}Sources: {', '.join(active_sources)}"
              f"{'+ brute' if brute else ''}{RST}\n")

    # Passive sources
    source_fns = {
        "crtsh":       from_crtsh,
        "wayback":     from_wayback,
        "alienvault":  from_alienvault,
        "rapiddns":    from_rapiddns,
        "hackertarget":from_hackertarget,
    }

    for src in active_sources:
        fn = source_fns.get(src)
        if fn:
            try:
                subs = fn(domain, verbose=verbose)
                all_subs.update(subs)
            except Exception as e:
                if verbose:
                    print(f"  {DIM}[{src}] Error: {e}{RST}")
            time.sleep(0.5)  # Rate limit

    # Brute force
    if brute:
        if verbose:
            print(f"  {C}[*]{RST} Brute forcing {len(wordlist or COMMON_SUBDOMAINS)} subdomains...")
        brute_found = brute_force(domain, wordlist, threads, verbose)
        all_subs.update(brute_found)

    # Permutations
    if permute and all_subs:
        if verbose:
            print(f"  {C}[*]{RST} Generating permutations...")
        perm_found = generate_permutations(list(all_subs), domain)
        all_subs.update(perm_found)

    # Deduplicate and sort
    result = sorted(set(s.lower().strip() for s in all_subs))

    if verbose:
        print(f"\n  {G}[+]{RST} Total unique subdomains discovered: {len(result)}\n")

    return result
