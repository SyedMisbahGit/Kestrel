from core.cdn import is_cdn_ip
import asyncio
import aiohttp
import codecs
import mmh3
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

try:
    from pyjarm.api import scan as jarm_scan
except ImportError:
    jarm_scan = None

async def fetch_and_hash_favicon(client, domain):
    """Downloads the target's favicon and computes the Shodan-compatible MurmurHash3."""
    url = f"https://{domain}/favicon.ico"
    try:
        async with client.get(url, timeout=8, ssl=False) as r:
            if r.status == 200:
                body = await r.read()
                favicon_base64 = codecs.encode(body, "base64")
                return mmh3.hash(favicon_base64)
    except Exception:
        pass
    return None

async def fetch_jarm_hash(domain):
    """Executes the JARM active TLS fingerprinting protocol."""
    if not jarm_scan: return None
    try:
        # pyjarm is synchronous, so we run it in a thread executor
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, jarm_scan, domain, 443)
        return result[0] if result else None
    except Exception:
        return None

async def query_shodan_advanced(client, domain, fav_hash, jarm_hash, api_key):
    """Queries Shodan across the IPv4 space utilizing both visual and cryptographic signatures."""
    origins = set()
    domain_keyword = domain.split('.')[0]
    
    queries = []
    if fav_hash:
        queries.append(f"http.favicon.hash:{fav_hash} -org:Cloudflare -org:Fastly -org:Akamai")
    
    if jarm_hash:
        # JARM paired with the HTML keyword prevents returning millions of shared CDN edge nodes
        queries.append(f"ssl.jarm:{jarm_hash} http.html:\"{domain_keyword}\" -org:Cloudflare -org:Fastly -org:Akamai")

    for query in queries:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
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
    console.print("\n[bold blue]━━ PHASE 1.6: ORIGIN UNMASKING (JARM & FAVICON PIVOT) ━━[/bold blue]")
    
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
            if fav_hash:
                console.print(f"[green]  + Asset Signature Generated (MurmurHash3): {fav_hash}[/green]")
            else:
                console.print("[dim]  ! Favicon unreadable or non-existent.[/dim]")

            console.print("INFO     Executing Active JARM TLS Fingerprinting...")
            if jarm_scan:
                jarm_hash = await fetch_jarm_hash(domain)
                if jarm_hash:
                    console.print(f"[green]  + Cryptographic Soul Extracted (JARM): {jarm_hash}[/green]")
                else:
                    console.print("[dim]  ! JARM fingerprinting failed.[/dim]")
            else:
                jarm_hash = None
                console.print("[dim]  ! pyjarm library not installed. Skipping TLS fingerprinting.[/dim]")

            if not fav_hash and not jarm_hash:
                console.print("[yellow]WARNING  Both unmasking signatures failed. Bypassing phase.[/yellow]")
                return set()

            console.print("INFO     Pivoting cryptographic signatures across global IPv4 space (Bypassing CDNs)...")
            return await query_shodan_advanced(client, domain, fav_hash, jarm_hash, api_key)

    origins = asyncio.run(deploy())
    
    if origins:
        console.print(f"[bold red]  ! [CRITICAL] CDN SHIELD BYPASSED. TRUE ORIGINS EXPOSED:[/bold red]")
        for ip, org in origins:
            console.print(f"      └ IP: {ip} | Host: {org}")
            # Inject the naked IP back into the state graph so Port Scanners & Fuzzers can hit it directly
            session.add_subdomain(ip)
    else:
        console.print("  + Perimeter secure. No origin IP leakage detected via TLS or visual assets.")
