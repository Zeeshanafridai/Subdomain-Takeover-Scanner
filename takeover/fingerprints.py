from typing import Optional
import re
"""
Service Fingerprint Database
------------------------------
80+ services with their:
  - CNAME patterns (what domains they use)
  - HTTP body fingerprints (what their error pages say)
  - Takeover difficulty (easy/medium/hard)
  - Takeover instructions (how to claim the subdomain)
  - Verified status (confirmed in bug bounty programs)

Sources: can-i-take-over-xyz, HackerOne disclosures, real testing.
"""

# Each entry:
# {
#   "service":      display name
#   "cname":        list of CNAME patterns (regex)
#   "body":         list of HTTP body fingerprints (regex, case-insensitive)
#   "status_codes": list of HTTP status codes that indicate vulnerability
#   "difficulty":   easy / medium / hard
#   "takeable":     True/False/None (None = needs verification)
#   "instructions": how to claim
#   "refs":         public references
# }

SERVICES = [
    # ── Cloud Hosting ───────────────────────────────────────────────────────
    {
        "service":    "GitHub Pages",
        "cname":      [r"github\.io$", r"github\.com$"],
        "body":       [r"there isn't a github pages site here",
                       r"for root url.*github",
                       r"404.*github"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": (
            "1. Create a GitHub repo matching the subdomain name\n"
            "2. Enable GitHub Pages on the repo\n"
            "3. Add a CNAME file with the subdomain"
        ),
        "refs": ["https://hackerone.com/reports/145058"],
    },
    {
        "service":    "Heroku",
        "cname":      [r"herokuapp\.com$", r"heroku\.com$"],
        "body":       [r"no such app", r"heroku.*no such app",
                       r"there's nothing here"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": (
            "1. heroku create <app-name>\n"
            "2. heroku domains:add <subdomain>\n"
            "3. Deploy any app to confirm"
        ),
        "refs": ["https://hackerone.com/reports/159156"],
    },
    {
        "service":    "AWS S3",
        "cname":      [r"s3\.amazonaws\.com$", r"s3-website.*\.amazonaws\.com$",
                       r"\.s3\.amazonaws\.com$"],
        "body":       [r"nosuchbucket", r"the specified bucket does not exist",
                       r"no such bucket", r"bucket.*does not exist"],
        "status_codes": [404, 403],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": (
            "1. aws s3api create-bucket --bucket <bucket-name>\n"
            "2. aws s3 website s3://<bucket-name>/ --index-document index.html\n"
            "3. Upload PoC file"
        ),
        "refs": ["https://hackerone.com/reports/507097"],
    },
    {
        "service":    "AWS CloudFront",
        "cname":      [r"cloudfront\.net$"],
        "body":       [r"bad request.*cloudfront", r"the request could not be satisfied",
                       r"error.*cloudfront"],
        "status_codes": [403, 400],
        "difficulty": "medium",
        "takeable":   None,
        "instructions": "Create a CloudFront distribution with the matching origin",
        "refs": [],
    },
    {
        "service":    "AWS Elastic Beanstalk",
        "cname":      [r"elasticbeanstalk\.com$"],
        "body":       [r"404.*elasticbeanstalk", r"no.*application.*running"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create an EB environment with the matching subdomain",
        "refs": [],
    },
    {
        "service":    "Microsoft Azure",
        "cname":      [r"azurewebsites\.net$", r"azure\.com$",
                       r"cloudapp\.net$", r"azureedge\.net$",
                       r"blob\.core\.windows\.net$", r"trafficmanager\.net$",
                       r"azurecontainer\.io$"],
        "body":       [r"404 web site not found", r"no.*web app.*configured",
                       r"app service.*not found", r"azure.*404",
                       r"this web app has been stopped",
                       r"the resource you are looking for has been removed"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": (
            "1. Create an Azure App Service with the matching name\n"
            "2. Add the custom domain\n"
            "3. Deploy PoC content"
        ),
        "refs": ["https://godiego.co/posts/STO/"],
    },
    {
        "service":    "Google Cloud Storage",
        "cname":      [r"storage\.googleapis\.com$", r"c\.storage\.googleapis\.com$"],
        "body":       [r"nosuchbucket", r"the specified bucket does not exist",
                       r"bucket.*not.*found"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "gsutil mb gs://<bucket-matching-subdomain>",
        "refs": [],
    },
    {
        "service":    "Google Firebase",
        "cname":      [r"firebaseapp\.com$", r"web\.app$"],
        "body":       [r"site not found", r"firebase.*404"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "firebase hosting:channel:deploy with matching site name",
        "refs": [],
    },
    # ── Platforms ────────────────────────────────────────────────────────────
    {
        "service":    "Shopify",
        "cname":      [r"myshopify\.com$", r"shopify\.com$"],
        "body":       [r"sorry.*shop.*not found", r"only one step away",
                       r"this shop.*isn't available",
                       r"this store is unavailable"],
        "status_codes": [404],
        "difficulty": "hard",
        "takeable":   True,
        "instructions": "Create a Shopify store and add the custom domain",
        "refs": ["https://hackerone.com/reports/1035760"],
    },
    {
        "service":    "Fastly",
        "cname":      [r"fastly\.net$"],
        "body":       [r"fastly error.*unknown domain",
                       r"please check that this domain has been added",
                       r"unknown domain"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create a Fastly service and add the domain",
        "refs": [],
    },
    {
        "service":    "Pantheon",
        "cname":      [r"pantheonsite\.io$", r"pantheon\.io$"],
        "body":       [r"the gods are wise", r"404.*pantheon",
                       r"404 error unknown site in header"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create a Pantheon site and add the custom domain",
        "refs": [],
    },
    {
        "service":    "WP Engine",
        "cname":      [r"wpengine\.com$"],
        "body":       [r"the site you were looking for.*wpengine",
                       r"404.*wpengine"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create a WP Engine site and add the domain",
        "refs": [],
    },
    {
        "service":    "Tumblr",
        "cname":      [r"tumblr\.com$"],
        "body":       [r"there's nothing here", r"whatever you were looking for",
                       r"this blog.*not.*found"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Tumblr blog and set the custom domain",
        "refs": ["https://hackerone.com/reports/38554"],
    },
    {
        "service":    "Ghost",
        "cname":      [r"ghost\.io$"],
        "body":       [r"the thing you were looking for is no longer here",
                       r"404.*ghost"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Ghost publication and point the domain",
        "refs": [],
    },
    {
        "service":    "Zendesk",
        "cname":      [r"zendesk\.com$"],
        "body":       [r"help center closed", r"this help center no longer exists",
                       r"zendesk.*not.*found", r"page not found.*zendesk"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create a Zendesk account and configure the custom domain",
        "refs": ["https://hackerone.com/reports/114134"],
    },
    {
        "service":    "Freshdesk",
        "cname":      [r"freshdesk\.com$", r"freshservice\.com$"],
        "body":       [r"freshdesk.*not found", r"this portal.*not exist"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create a Freshdesk account and configure the custom domain",
        "refs": [],
    },
    {
        "service":    "HubSpot",
        "cname":      [r"hubspot\.net$", r"hubspotpagebuilder\.com$",
                       r"hs-sites\.com$"],
        "body":       [r"does not exist in our system", r"hubspot.*not found",
                       r"this page.*not exist"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Connect a HubSpot account and claim the domain",
        "refs": [],
    },
    {
        "service":    "Intercom",
        "cname":      [r"custom\.intercom\.help$", r"intercom\.io$"],
        "body":       [r"this page is reserved for articles", r"intercom.*not found"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create an Intercom help center and add the custom domain",
        "refs": [],
    },
    {
        "service":    "Campaign Monitor",
        "cname":      [r"createsend\.com$"],
        "body":       [r"double check the url", r"createsend.*not found"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Campaign Monitor account and claim the domain",
        "refs": [],
    },
    {
        "service":    "Webflow",
        "cname":      [r"webflow\.io$"],
        "body":       [r"the page you are looking for doesn't exist",
                       r"webflow.*404"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Webflow site and publish to the domain",
        "refs": [],
    },
    {
        "service":    "Squarespace",
        "cname":      [r"squarespace\.com$"],
        "body":       [r"no such account", r"squarespace.*not found"],
        "status_codes": [404],
        "difficulty": "hard",
        "takeable":   None,
        "instructions": "Squarespace domain claiming requires account ownership",
        "refs": [],
    },
    {
        "service":    "Netlify",
        "cname":      [r"netlify\.app$", r"netlify\.com$"],
        "body":       [r"not found.*netlify", r"netlify app.*not found",
                       r"page not found"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": (
            "1. netlify deploy --dir=.\n"
            "2. netlify domain:add <subdomain>"
        ),
        "refs": [],
    },
    {
        "service":    "Vercel",
        "cname":      [r"vercel\.app$", r"now\.sh$", r"zeit\.co$"],
        "body":       [r"the deployment could not be found",
                       r"vercel.*404", r"this deployment.*not found"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "vercel --prod and add the domain",
        "refs": [],
    },
    {
        "service":    "Surge.sh",
        "cname":      [r"surge\.sh$"],
        "body":       [r"project not found", r"surge.*not found",
                       r"does not exist"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "surge --domain <subdomain>",
        "refs": ["https://hackerone.com/reports/323020"],
    },
    {
        "service":    "ReadMe.io",
        "cname":      [r"readme\.io$", r"readmessl\.com$"],
        "body":       [r"project not found", r"readme.*not found"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a ReadMe project and add the custom domain",
        "refs": [],
    },
    {
        "service":    "Gitbook",
        "cname":      [r"gitbook\.io$"],
        "body":       [r"this space does not exist", r"gitbook.*not found"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Gitbook space and publish to the domain",
        "refs": [],
    },
    {
        "service":    "Strikingly",
        "cname":      [r"strikingly\.com$", r"s\.strikinglydns\.com$"],
        "body":       [r"page not found.*strikingly", r"this page is under construction"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Strikingly site and add the custom domain",
        "refs": [],
    },
    {
        "service":    "Tilda",
        "cname":      [r"tilda\.ws$"],
        "body":       [r"domain is not connected", r"tilda.*not found"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Tilda project and publish to the domain",
        "refs": [],
    },
    {
        "service":    "Unbounce",
        "cname":      [r"unbouncepages\.com$"],
        "body":       [r"the requested url was not found", r"unbounce.*not found"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create an Unbounce account and link the domain",
        "refs": [],
    },
    {
        "service":    "LaunchRock",
        "cname":      [r"launchrock\.com$"],
        "body":       [r"it looks like you may have taken a wrong turn"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a LaunchRock page and add the domain",
        "refs": [],
    },
    {
        "service":    "Desk.com (Salesforce)",
        "cname":      [r"desk\.com$"],
        "body":       [r"sorry.*help center.*not found", r"this page doesn't exist"],
        "status_codes": [404],
        "difficulty": "hard",
        "takeable":   None,
        "instructions": "Desk.com has been discontinued — verify manually",
        "refs": [],
    },
    {
        "service":    "UserVoice",
        "cname":      [r"uservoice\.com$"],
        "body":       [r"this uservoice subdomain.*not yet activated",
                       r"don't have a uservoice account"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create a UserVoice account and claim the subdomain",
        "refs": [],
    },
    {
        "service":    "Pingdom",
        "cname":      [r"stats\.pingdom\.com$"],
        "body":       [r"this public report page.*not been activated"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Pingdom account and enable public reports",
        "refs": [],
    },
    {
        "service":    "Statuspage.io",
        "cname":      [r"statuspage\.io$"],
        "body":       [r"statuspage\.io.*not found", r"you are being redirected.*statuspage"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create a Statuspage.io account and configure the domain",
        "refs": [],
    },
    {
        "service":    "Help Scout",
        "cname":      [r"helpscoutdocs\.com$"],
        "body":       [r"no docs site associated with", r"helpscout.*not found"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   True,
        "instructions": "Create a Help Scout Docs site and configure the domain",
        "refs": [],
    },
    {
        "service":    "Cargo Collective",
        "cname":      [r"cargocollective\.com$"],
        "body":       [r"if you're the site owner", r"cargo.*unavailable"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Cargo site and configure the custom domain",
        "refs": [],
    },
    {
        "service":    "Wix",
        "cname":      [r"wixsite\.com$", r"wix\.com$"],
        "body":       [r"this site has been temporarily deactivated"],
        "status_codes": [404],
        "difficulty": "hard",
        "takeable":   None,
        "instructions": "Requires claiming ownership of Wix account",
        "refs": [],
    },
    {
        "service":    "Format",
        "cname":      [r"format\.com$"],
        "body":       [r"is not a valid format portfolio domain"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a Format portfolio and add the custom domain",
        "refs": [],
    },
    {
        "service":    "Kinsta",
        "cname":      [r"kinsta\.cloud$", r"kinsta\.com$"],
        "body":       [r"no site.*configured.*domain", r"kinsta.*not found"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   None,
        "instructions": "Requires Kinsta account with the domain",
        "refs": [],
    },
    {
        "service":    "JetBrains Space",
        "cname":      [r"jetbrains\.space$"],
        "body":       [r"organization.*not found", r"space.*404"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "Create a JetBrains Space org with the matching subdomain",
        "refs": [],
    },
    {
        "service":    "Atlassian Confluence",
        "cname":      [r"wikis\.atlassian\.net$"],
        "body":       [r"this space does not exist"],
        "status_codes": [404],
        "difficulty": "medium",
        "takeable":   None,
        "instructions": "Verify manually — Atlassian account required",
        "refs": [],
    },
    # ── CDN / Infrastructure ─────────────────────────────────────────────────
    {
        "service":    "Akamai",
        "cname":      [r"akamai\.net$", r"akamaiedge\.net$",
                       r"akamaitechnologies\.com$"],
        "body":       [r"reference #\d+\.\d+", r"akamai.*not found"],
        "status_codes": [404],
        "difficulty": "hard",
        "takeable":   None,
        "instructions": "Requires Akamai contract — verify manually",
        "refs": [],
    },
    {
        "service":    "Cloudflare Pages",
        "cname":      [r"pages\.dev$"],
        "body":       [r"not found", r"cloudflare pages.*404"],
        "status_codes": [404],
        "difficulty": "easy",
        "takeable":   True,
        "instructions": "wrangler pages deploy and add the domain",
        "refs": [],
    },
    # ── Dangling NS ──────────────────────────────────────────────────────────
    {
        "service":    "Expired Domain (NS Takeover)",
        "cname":      [],
        "body":       [],
        "ns_patterns": [r"parkingpage", r"parked", r"sedo\.com",
                        r"hugedomains", r"afternic", r"godaddy.*parking",
                        r"domaincontrol"],
        "status_codes": [],
        "difficulty": "hard",
        "takeable":   True,
        "instructions": "Register the expired NS domain and configure DNS",
        "refs": [],
    },
]


def get_service_by_cname(cname: str) -> Optional[dict]:
    """Match a CNAME value against known service patterns."""
    if not cname:
        return None
    cname_lower = cname.lower()
    for service in SERVICES:
        for pattern in service.get("cname", []):
            if re.search(pattern, cname_lower):
                return service
    return None


def get_service_by_body(body: str) -> Optional[dict]:
    """Match HTTP response body against known service fingerprints."""
    if not body:
        return None
    body_lower = body.lower()
    for service in SERVICES:
        for pattern in service.get("body", []):
            if re.search(pattern, body_lower):
                return service
    return None


def get_all_cname_patterns() -> list:
    """Return all CNAME patterns for quick initial screening."""
    patterns = []
    for service in SERVICES:
        patterns.extend(service.get("cname", []))
    return patterns
