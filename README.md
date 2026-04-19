# Subdomain Takeover Scanner

> Finds dangling CNAMEs, expired NS delegations, and unclaimed cloud services. 50+ service fingerprints. Passive enumeration via CT logs, Wayback, AlienVault. HTTP body verification. Zero false positives from wildcard filtering.

---

## Coverage

| Check | Details |
|-------|---------|
| **CNAME Dangling** | Full chain walking — finds dangling CNAMEs pointing to unclaimed services |
| **NS Takeover** | Detects NS records pointing to expired/unregistered domains |
| **HTTP Verification** | Confirms via response body fingerprinting (not just DNS) |
| **Wildcard Filtering** | Detects wildcard DNS and removes false positives automatically |
| **50+ Services** | GitHub Pages, Heroku, AWS S3/EB/CF, Azure, GCP, Netlify, Vercel, Shopify, Zendesk, HubSpot, Surge, and more |
| **CT Log Mining** | crt.sh — most comprehensive passive source |
| **Wayback Machine** | Historical subdomain discovery |
| **AlienVault OTX** | Passive DNS data |
| **Brute Force** | 250+ common subdomain wordlist |
| **Permutations** | Generates -dev/-staging/-old variants of known subdomains |
| **Zone Transfer** | AXFR attempt on all discovered NS servers |

---

## Installation

```bash
git clone https://github.com/yourhandle/subdomain-takeover
cd subdomain-takeover
python3 subdomain_takeover.py --help
```

Zero dependencies. Pure Python 3.6+. `dig` recommended for better DNS resolution.

---

## Usage

### Full domain scan (discovery + takeover check)
```bash
python3 subdomain_takeover.py -d target.com
```

### Single subdomain check
```bash
python3 subdomain_takeover.py -s staging.target.com
```

### From subdomain list (e.g. from subfinder/amass)
```bash
python3 subdomain_takeover.py -l subdomains.txt
```

### Passive only (no brute force)
```bash
python3 subdomain_takeover.py -d target.com --no-brute
```

### Specific passive sources
```bash
python3 subdomain_takeover.py -d target.com \
  --sources crtsh wayback alienvault
```

### With permutation generation
```bash
python3 subdomain_takeover.py -d target.com --permute
```

### Custom wordlist
```bash
python3 subdomain_takeover.py -d target.com \
  --wordlist /path/to/subdomains.txt
```

### Fast parallel scan
```bash
python3 subdomain_takeover.py -d target.com --threads 50
```

### Output only vulnerable subdomains (pipe-friendly)
```bash
python3 subdomain_takeover.py -d target.com --only-vulnerable
```

### Full workflow with report
```bash
python3 subdomain_takeover.py -d target.com \
  --permute \
  --threads 50 \
  --report \
  -o results.json
```

---

## How Detection Works

### Step 1: Wildcard Check
Tests `z33nonexistent99999.target.com` — if it resolves, wildcard DNS is present.
All subsequent results are filtered against wildcard IPs to eliminate false positives.

### Step 2: Subdomain Discovery
Queries crt.sh, Wayback Machine, AlienVault OTX, RapidDNS, HackerTarget.
Brute forces 250+ common names. Optionally generates permutations.

### Step 3: CNAME Chain Walking
For each subdomain, follows the full CNAME chain:
```
staging.target.com → target-staging.herokuapp.com (NXDOMAIN!) → VULNERABLE
```

### Step 4: NS Delegation Check
Checks if NS records point to domains that can be registered:
```
api.target.com NS → ns1.expiredns.com (NXDOMAIN) → register expiredns.com → full DNS control
```

### Step 5: HTTP Verification
Makes actual HTTP requests to confirm via body fingerprinting:
```
"There isn't a GitHub Pages site here" → GitHub Pages confirmed
"No Such App" → Heroku confirmed
"NoSuchBucket" → AWS S3 confirmed
```

---

## Supported Services (50+)

**Cloud:** AWS S3, AWS Elastic Beanstalk, AWS CloudFront, Azure App Service, Azure Blob, Azure TrafficManager, GCP Storage, Google Firebase, Cloudflare Pages

**Platforms:** GitHub Pages, Heroku, Netlify, Vercel, Surge.sh, Webflow, Tilda, Strikingly, GitBook, ReadMe.io, Format, Cargo

**Support/Docs:** Zendesk, Freshdesk, HubSpot, Intercom, Help Scout, UserVoice, Statuspage.io, Pingdom

**CMS/Blog:** Tumblr, Ghost, WordPress (WP Engine, Pantheon), Squarespace, Wix, Unbounce, LaunchRock

**CDN/Infra:** Fastly, Akamai

**NS Takeover:** Any NS record pointing to unregistered domain

---

## Bug Bounty Workflow

```
1. Run discovery + scan:
   python3 subdomain_takeover.py -d target.com --permute --report

2. For each confirmed finding:
   a. Document the CNAME chain (screenshot dig output)
   b. Make HTTP request showing the "unclaimed" error page
   c. Note the service and difficulty

3. PoC for Critical findings (GitHub Pages example):
   - Create github.com/youraccount/subdomain-name
   - Enable GitHub Pages
   - Visit the subdomain — it should load your content

4. Report to H1/Bugcrowd with:
   - subdomain name
   - CNAME → NXDOMAIN chain
   - HTTP response showing unclaimed page
   - Service instructions for reproduction

CVSS: Subdomain takeover is typically 8.1-9.0 (High/Critical)
```

---

## GitHub Info

**Description:**
```
Subdomain takeover scanner — CNAME/NS dangling detection, 50+ service fingerprints, CT log mining, HTTP verification, wildcard filtering
```

**Topics:**
```
subdomain-takeover, dangling-cname, dns-security, bug-bounty,
reconnaissance, subdomain-enumeration, python, offensive-security, appsec
```

---

## License
MIT — For authorized testing only.
