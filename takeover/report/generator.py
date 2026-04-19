"""Report generator for subdomain takeover findings."""
import json, datetime

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

def generate(results: dict, prefix: str = "takeover_report") -> dict:
    now   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    jpath = f"{prefix}_{now}.json"
    mpath = f"{prefix}_{now}.md"

    with open(jpath, "w") as f:
        json.dump(results, f, indent=2, default=str)

    confirmed = results.get("confirmed", [])
    possible  = results.get("possible", [])
    lines     = []

    lines.append("# Subdomain Takeover Report\n")
    lines.append(f"**Target:** `{results.get('target', '')}`  ")
    lines.append(f"**Date:** {results.get('start_time', '')}  ")
    lines.append(f"**Confirmed:** {len(confirmed)} | **Possible:** {len(possible)}  \n")
    lines.append("---\n")

    if confirmed:
        lines.append("## Confirmed Takeovers\n")
        for f in confirmed:
            lines.append(f"### {f['hostname']}\n")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Severity** | {f.get('severity','High')} |")
            lines.append(f"| **Service** | {f.get('service','Unknown')} |")
            lines.append(f"| **CNAME** | `{f.get('final_cname','')}` |")
            lines.append(f"| **NXDOMAIN** | {f.get('nxdomain', False)} |")
            lines.append(f"| **Difficulty** | {f.get('difficulty','?')} |\n")
            if f.get("instructions"):
                lines.append(f"**How to take over:**\n```\n{f['instructions']}\n```\n")
            if f.get("evidence"):
                lines.append(f"**Evidence:** {' | '.join(f['evidence'][:3])}\n")
            lines.append("---\n")

    if possible:
        lines.append("## Possible Takeovers (Manual Verification Needed)\n")
        for f in possible:
            lines.append(f"- **{f['hostname']}** — {f.get('service','?')} "
                         f"(CNAME: `{f.get('final_cname','?')}`)")
        lines.append("")

    lines.append("## Remediation\n")
    lines.append("- Remove DNS records (CNAME/A) for subdomains that no longer serve content")
    lines.append("- Implement a DNS audit process — check for dangling CNAMEs regularly")
    lines.append("- Before decommissioning cloud services, remove all associated DNS records first")
    lines.append("- Monitor Certificate Transparency logs for unexpected subdomains")
    lines.append("- Add subdomain takeover detection to your CI/CD pipeline\n")

    with open(mpath, "w") as f:
        f.write("\n".join(lines))

    return {"json": jpath, "markdown": mpath}
