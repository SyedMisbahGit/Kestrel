from core.ui import print_briefing
import asyncio
import aiodns
import logging
import socket
from rich.console import Console

log = logging.getLogger("rich")
console = Console()

async def query_cymru_bgp(ip):
    try:
        resolver = aiodns.DNSResolver(timeout=3.0, tries=2)
        reversed_ip = '.'.join(reversed(ip.split('.')))
        query_target = f"{reversed_ip}.origin.asn.cymru.com"
        
        res = await resolver.query(query_target, 'TXT')
        if res:
            data = res[0].text.split('|')
            if len(data) >= 3:
                asn = data[0].strip()
                cidr = data[1].strip()
                return asn, cidr
    except Exception:
        pass
    return None, None

def run_horizontal(session, config):
    console.print("\n[bold blue]━━ PHASE 1.1: HORIZONTAL RECON (NATIVE BGP ROUTING) ━━[/bold blue]")
    print_briefing(
        title="BGP ASN Unmasking",
        happening="Querying Team Cymru's global BGP routing tables via native UDP DNS to extract the target's Autonomous System Number and CIDR ranges.",
        fallback="If the target is completely shielded by Cloudflare/Fastly, DNS will fail. Kestrel will gracefully skip expansion to prevent scanning CDN edge nodes.",
        command="whois -h whois.radb.net <IP_ADDRESS>"
    )
    domain = session.domain
    ip = None
    
    # Mathematical Apex vs Subdomain detection
    is_subdomain = len(domain.split('.')) > 2
    
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"INFO     Resolved {domain} to IP: {ip}")
    except socket.gaierror:
        if not is_subdomain:
            try:
                ip = socket.gethostbyname(f"www.{domain}")
                console.print(f"INFO     Apex void detected. Resolved origin via www.{domain} to IP: {ip}")
            except socket.gaierror:
                console.print(f"[red]  ! DNS Resolution completely failed for {domain}[/red]")
                return
        else:
            console.print(f"[red]  ! DNS Resolution failed for subdomain: {domain}[/red]")
            return

    asn, cidr = asyncio.run(query_cymru_bgp(ip))
    
    if asn and cidr:
        console.print(f"[green]  + Origin ASN Confirmed: AS{asn} ({cidr})[/green]")
        session.cidrs.append(asn)
    else:
        console.print("[dim]  ! BGP routing table query failed. Skipping horizontal expansion.[/dim]")
