import asyncio
import aiohttp
import ssl
import socket
import json
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

def extract_ssl_organization(domain):
    """Natively connects to the target to rip the Organization (O=) field from the SSL cert."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                for subject in cert.get('subject', []):
                    for key, value in subject:
                        if key == 'organizationName':
                            return value
    except Exception:
        pass
    return None

async def pivot_ct_logs(client, org_name, session_state):
    """Queries Certificate Transparency logs for the exact corporate entity."""
    url = f"https://crt.sh/?q={org_name}&output=json"
    subsidiaries = set()
    
    try:
        async with client.get(url, timeout=15, ssl=False) as r:
            if r.status == 200:
                data = await r.json()
                for entry in data:
                    name = entry.get("name_value", "").split('\n')[0].lower()
                    if '*' not in name and name != session_state.domain:
                        # Extract root domain to avoid flooding the state graph with 10k subdomains
                        root = ".".join(name.split('.')[-2:])
                        subsidiaries.add(root)
    except Exception:
        pass
    return subsidiaries

def run_umbrella(session, config):
    console.print("\n[bold blue]━━ PHASE 1.2: CORPORATE UMBRELLA (SSL ORG PIVOTING) ━━[/bold blue]")
    domain = session.domain
    
    console.print(f"INFO     Extracting X.509 Cryptographic Identity for {domain}...")
    org_name = extract_ssl_organization(domain)
    
    # Filter out generic hosting certs (e.g., Let's Encrypt, Cloudflare)
    ignore_orgs = ["Cloudflare, Inc.", "Amazon.com, Inc.", "Let's Encrypt", "Google Trust Services"]
    
    if not org_name or any(ignore in org_name for ignore in ignore_orgs):
        console.print("[dim]  * No proprietary Corporate Identity found in SSL (likely Let's Encrypt/CDN). Skipping Umbrella pivot.[/dim]")
        return
        
    console.print(f"[green]  + Corporate Identity Confirmed: '{org_name}'[/green]")
    console.print(f"INFO     Executing Global CT Log Pivot for corporate acquisitions...")
    
    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    async def deploy():
        async with aiohttp.ClientSession(connector=connector) as client:
            return await pivot_ct_logs(client, org_name, session)
            
    subsidiaries = asyncio.run(deploy())
    
    if subsidiaries:
        console.print(f"[bold magenta]  [*] UMBRELLA DETECTED: Found {len(subsidiaries)} cross-brand subsidiary root domains.[/bold magenta]")
        for sub in subsidiaries:
            console.print(f"      └ {sub}")
            # Note: We print these for intelligence. We don't automatically scan them to prevent scope-creep.
    else:
        console.print("  + No external subsidiaries discovered via SSL pivoting.")
