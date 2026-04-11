import logging
import socket
import requests
from rich.console import Console

log = logging.getLogger("rich")
console = Console()

def run_horizontal(session, config):
    console.print("\n[bold blue]━━ PHASE 1.1: HORIZONTAL RECON (ORIGIN & ASN MAPPING) ━━[/bold blue]")
    domain = session.domain
    
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"INFO     Resolved {domain} to IP: {ip}")
        
        # Switched to HackerTarget ASN (Much more stable than BGPView)
        resp = requests.get(f"https://api.hackertarget.com/asnlookup/?q={ip}", timeout=10)
        
        if resp.status_code == 200:
            data = resp.text.split(',')
            if len(data) > 3:
                asn = data[1].strip()
                org = data[3].strip().replace('"', '')
                
                # 1. The CDN Shield (Heuristic Identification)
                cdns = ["Cloudflare", "Fastly", "Akamai", "Amazon", "Incapsula", "Sucuri"]
                is_cdn = any(cdn.lower() in org.lower() for cdn in cdns)
                
                if is_cdn:
                    console.print(f"[yellow]  ! WAF/CDN DETECTED ({org}). BGP/CIDR expansion aborted to prevent shared-infrastructure scanning.[/yellow]")
                else:
                    console.print(f"[green]  + True Origin Confirmed: {org} (ASN: {asn})[/green]")
                    console.print(f"INFO     Extracting IPv4 CIDR blocks for {asn}...")
                    # Future integration: Query CIDRs for the true origin ASN here
                    session.cidrs.append(asn)
        else:
            console.print("[dim]  ! ASN API unavailable. Skipping horizontal expansion.[/dim]")
            
    except socket.gaierror:
        console.print(f"[red]  ! DNS Resolution failed for {domain}[/red]")
    except Exception as e:
        log.error(f"Horizontal Recon failed: {e}")
