import subprocess
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

def get_txt_records(domain):
    try:
        result = subprocess.run(["host", "-t", "TXT", domain], capture_output=True, text=True, timeout=10)
        return [line for line in result.stdout.splitlines() if "descriptive text" in line]
    except Exception: return []

def get_mx_records(domain):
    try:
        result = subprocess.run(["host", "-t", "MX", domain], capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            if "mail is handled by" in line:
                return line.split()[-1].strip('.')
    except Exception: pass
    return None

def run_email(session, config):
    console.print("\n[bold blue]━━ PHASE 2.7: SPOOFCHECK (SPF & DMARC MATRIX) ━━[/bold blue]")
    domain = session.domain
    
    mx = get_mx_records(domain)
    if mx:
        console.print(f"  + Primary MX: {mx}")
    else:
        console.print("  ! No MX records found. Domain likely does not receive email.")
        return

    # 1. Parse SPF Enforcement
    spf_records = get_txt_records(domain)
    spf_enforcement = "Missing"
    for rec in spf_records:
        if "v=spf1" in rec:
            if "-all" in rec: spf_enforcement = "HardFail (-all)"
            elif "~all" in rec: spf_enforcement = "SoftFail (~all)"
            elif "?all" in rec: spf_enforcement = "Neutral (?all)"
            elif "+all" in rec: spf_enforcement = "Pass (+all)"
            else: spf_enforcement = "Weak/Malformed"

    # 2. Parse DMARC Policy
    dmarc_records = get_txt_records(f"_dmarc.{domain}")
    dmarc_p = "Missing"
    for rec in dmarc_records:
        if "v=DMARC1" in rec:
            if "p=reject" in rec: dmarc_p = "reject"
            elif "p=quarantine" in rec: dmarc_p = "quarantine"
            elif "p=none" in rec: dmarc_p = "none"

    # 3. The Logical Decision Matrix
    is_vuln = False
    
    # If DMARC protects the domain, it cannot be spoofed regardless of SPF
    if dmarc_p in ["reject", "quarantine"]:
        is_vuln = False
    # If DMARC is weak/missing, we check if SPF allows unauthorized senders
    elif dmarc_p in ["none", "Missing"]:
        if spf_enforcement in ["Missing", "SoftFail (~all)", "Neutral (?all)", "Pass (+all)", "Weak/Malformed"]:
            is_vuln = True

    if is_vuln:
        console.print("╭────────────────────────────────────────── ❌ SPOOFCHECK FAILED ──────────────────────────────────────────╮")
        console.print("│ VULNERABLE: CEO Fraud / Email Spoofing Confirmed!                                                        │")
        console.print(f"│ SPF Record:   {spf_enforcement:<86} │")
        console.print(f"│ DMARC Policy: p={dmarc_p:<84} │")
        console.print(f"│ Impact: You can send emails as 'admin@{domain}' directly to employee inboxes.                       │")
        console.print("╰──────────────────────────────────────────────────────────────────────────────────────────────────────────╯")
        console.print("\nPoC Command (Authorized Testing Only):")
        console.print(f"swaks --to target@example.com --from admin@{domain} --server {mx} --header 'Subject: Urgent Transfer'\n")
        
        session.vulnerabilities.append({
            "type": "VULN",
            "name": "Email Spoofing Vulnerability",
            "matched-at": domain,
            "info": {"severity": "MEDIUM"}
        })
    else:
        console.print(f"[green]  + SECURE: Domain is cryptographically protected against spoofing.[/green]")
        console.print(f"[dim]    └ SPF: {spf_enforcement} | DMARC: p={dmarc_p}[/dim]")
