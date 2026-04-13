import logging
import socket
import requests
from rich.console import Console

log = logging.getLogger("rich")
console = Console()

def run_horizontal(session, config):
    console.print("\n[bold blue]━━ PHASE 1.1: HORIZONTAL RECON (ORIGIN & ASN MAPPING) ━━[/bold blue]")
    domain = session.domain
    ip = None
    
    # --- DNS FALLBACK ROUTER ---
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"INFO     Resolved {domain} to IP: {ip}")
    except socket.gaierror:
        try:
            ip = socket.gethostbyname(f"www.{domain}")
            console.print(f"INFO     Apex void detected. Resolved origin via www.{domain} to IP: {ip}")
        except socket.gaierror:
            console.print(f"[red]  ! DNS Resolution completely failed for {domain}[/red]")
            return

    try:
        resp = requests.get(f"https://api.hackertarget.com/asnlookup/?q={ip}", timeout=10)
        
        if resp.status_code == 200:
            data = resp.text.split(',')
            if len(data) > 3:
                asn = data[1].strip()
                org = data[3].strip().replace('"', '')
                
                cdns = ["Cloudflare", "Fastly", "Akamai", "Amazon", "Incapsula", "Sucuri"]
                is_cdn = any(cdn.lower() in org.lower() for cdn in cdns)
                
                if is_cdn:
                    console.print(f"[yellow]  ! WAF/CDN DETECTED ({org}). BGP/CIDR expansion aborted.[/yellow]")
                else:
                    console.print(f"[green]  + True Origin Confirmed: {org} (ASN: {asn})[/green]")
                    session.cidrs.append(asn)
        else:
            console.print("[dim]  ! ASN API unavailable. Skipping horizontal expansion.[/dim]")
            
    except Exception as e:
        log.error(f"Horizontal Recon failed: {e}")
