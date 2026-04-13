import dns.resolver
import dns.query
import dns.zone
import dns.exception
import re
import logging
from rich.console import Console
from rich.panel import Panel

console = Console()
log = logging.getLogger("rich")

TXT_PATTERNS = {
    "Internal_IP_Leak": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})",
    "Google_Verification_Token": r"google-site-verification=[\w-]+",
    "AWS_Validation": r"aws:?_?validation:?_?[\w-]+",
    "Stripe_Verification": r"stripe-verification=[\w-]+"
}

def run_dns_forensics(session, config):
    console.print("[bold blue]━━ PHASE 1.2: INFRASTRUCTURE FORENSICS ━━[/bold blue]")
    domain = session.domain
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        ns_records = resolver.resolve(domain, 'NS')
        ns_list = [str(ns.target).rstrip('.') for ns in ns_records]
        console.print(f"[cyan]  + Discovered {len(ns_list)} Authoritative Name Servers.[/cyan]")
    except Exception:
        log.error("Could not resolve Name Servers. Aborting DNS Forensics.")
        return

    # --- 1. NS TAKEOVER CHECK ---
    for ns in ns_list:
        try:
            resolver.resolve(ns, 'A')
        except dns.resolver.NXDOMAIN:
            console.print(Panel(
                f"[bold red]CRITICAL ANOMALY: NS TAKEOVER POSSIBLE[/bold red]\nName Server: {ns}",
                title="❌ NS HIJACK DETECTED", border_style="red"
            ))
            session.vulnerabilities.append({"name": "NS Takeover", "severity": "CRITICAL", "url": ns, "info": "Dangling NS record."})
        except Exception: pass

    # --- 2. WEAPONIZED AXFR (ZONE TRANSFER) ---
    zone_transfer_success = False
    for ns in ns_list:
        try:
            ns_ip = resolver.resolve(ns, 'A')[0].to_text()
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5.0))
            if z:
                zone_transfer_success = True
                extracted_subs = []
                # PARSE THE ZONE DATA AND INJECT INTO SESSION
                for name, node in z.nodes.items():
                    sub = str(name)
                    if sub != "@" and sub != "*":
                        full_sub = f"{sub}.{domain}"
                        if full_sub not in session.get_subdomains():
                            session.add_subdomain(full_sub)
                            extracted_subs.append(full_sub)
                
                console.print(Panel(
                    f"[bold red]CRITICAL ANOMALY: AXFR ZONE TRANSFER PERMITTED[/bold red]\n"
                    f"Name Server: {ns} ({ns_ip})\n"
                    f"Intelligence Gathered: Extracted [bold white]{len(extracted_subs)}[/bold white] internal/external records.\n"
                    f"Action: Data injected directly into ARBITER memory pipeline.",
                    title="❌ AXFR SUCCESS & DATA EXTRACTION", border_style="red"
                ))
                session.vulnerabilities.append({"name": "DNS Zone Transfer (AXFR)", "severity": "CRITICAL", "url": ns, "info": f"Extracted {len(extracted_subs)} records."})
                break
        except Exception: continue
            
    if not zone_transfer_success:
        console.print("[green]  + AXFR queries rejected (Secure).[/green]")

    # --- 3. TXT RECORD MINING ---
    try:
        txt_records = resolver.resolve(domain, 'TXT')
        for txt in txt_records:
            record_text = txt.to_text()
            for key, pattern in TXT_PATTERNS.items():
                matches = re.findall(pattern, record_text)
                for match in matches:
                    console.print(f"[yellow]  ! {key.replace('_', ' ')} Discovered: {match}[/yellow]")
    except Exception: pass
