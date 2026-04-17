from core.cdn import is_cdn_ip
import asyncio
import aiohttp
import codecs
import mmh3
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

async def fetch_and_hash_favicon(client, domain):
    """Downloads the target's favicon and computes the Shodan-compatible MurmurHash3."""
    url = f"https://{domain}/favicon.ico"
    try:
        async with client.get(url, timeout=8, ssl=False) as r:
            if r.status == 200:
                body = await r.read()
                # Shodan specific Favicon hashing algorithm
                favicon_base64 = codecs.encode(body, "base64")
                return mmh3.hash(favicon_base64)
    except Exception:
        pass
    return None

async def query_shodan_origin(client, fav_hash, api_key):
    """Queries Shodan across the entire IPv4 space for the Favicon hash, ignoring CDNs."""
    # We explicitly exclude Cloudflare, Fastly, and Akamai ASNs to find the true origin
    query = f"http.favicon.hash:{fav_hash} -org:Cloudflare -org:Fastly -org:Akamai"
    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
    
    origins = set()
    try:
        async with client.get(url, timeout=10) as r:
            if r.status == 200:
                data = await r.json()
                for match in data.get('matches', []):
                    ip = match.get('ip_str')
                    if is_cdn_ip(ip): continue
                    org = match.get('org', 'Unknown ASN')
                    origins.add((ip, org))
    except Exception:
        pass
    return origins

def run_unmask(session, config):
    console.print("\n[bold blue]━━ PHASE 1.6: ORIGIN UNMASKING (FAVICON PIVOT) ━━[/bold blue]")
    
    api_key = config.get("keys", {}).get("shodan", "")
    if not api_key:
        console.print("[dim]  * Shodan API Key not found in config/settings.yaml. Skipping Origin Unmasking.[/dim]")
        return

    domain = session.domain
    
    async def deploy():
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as client:
            console.print("INFO     Extracting and hashing primary visual asset (Favicon)...")
            fav_hash = await fetch_and_hash_favicon(client, domain)
            
            if not fav_hash:
                console.print("[dim]  ! Favicon unreadable or non-existent. Cannot calculate origin signature.[/dim]")
                return set()
                
            console.print(f"[green]  + Asset Signature Generated (MurmurHash3): {fav_hash}[/green]")
            console.print("INFO     Pivoting visual signature across global IPv4 space (Bypassing CDNs)...")
            
            return await query_shodan_origin(client, fav_hash, api_key)

    origins = asyncio.run(deploy())
    
    if origins:
        console.print(f"[bold red]  ! [CRITICAL] CDN SHIELD BYPASSED. TRUE ORIGINS EXPOSED:[/bold red]")
        for ip, org in origins:
            console.print(f"      └ IP: {ip} | Host: {org}")
            # Inject the naked IP back into the state graph so the Port Scanner / Fuzzer can hit it directly
            session.add_subdomain(ip)
    else:
        console.print("  + Perimeter secure. No origin IP leakage detected via visual assets.")
