import asyncio
import aiohttp
import logging
import re
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- NATIVE OSINT SCRAPERS ---

async def fetch_crtsh(client, domain):
    try:
        async with client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15) as r:
            if r.status == 200:
                data = await r.json()
                subs = {row['name_value'].lower() for row in data if domain in row['name_value']}
                # Clean wildcard prefixes
                return {s.replace('*.', '') for s in subs}
    except Exception: pass
    return set()

async def fetch_hackertarget(client, domain):
    try:
        async with client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15) as r:
            if r.status == 200:
                text = await r.text()
                return {line.split(',')[0].lower() for line in text.splitlines() if domain in line}
    except Exception: pass
    return set()

async def fetch_alienvault(client, domain):
    try:
        async with client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=15) as r:
            if r.status == 200:
                data = await r.json()
                return {x['hostname'].lower() for x in data.get('passive_dns', []) if domain in x['hostname']}
    except Exception: pass
    return set()

async def fetch_urlscan(client, domain):
    try:
        async with client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000", timeout=15) as r:
            if r.status == 200:
                data = await r.json()
                return {x['page']['domain'].lower() for x in data.get('results', []) if 'page' in x and domain in x.get('page', {}).get('domain', '')}
    except Exception: pass
    return set()

async def fetch_wayback(client, domain):
    try:
        async with client.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit=5000", timeout=15) as r:
            if r.status == 200:
                data = await r.json()
                urls = [x[2] for x in data[1:]]
                subs = set()
                regex = re.compile(r'https?://([a-zA-Z0-9.-]+)')
                for url in urls:
                    match = regex.search(url)
                    if match and match.group(1).endswith(domain):
                        subs.add(match.group(1).lower())
                return subs
    except Exception: pass
    return set()

async def deploy_omniscient_engine(domain):
    results = {}
    async with aiohttp.ClientSession() as client:
        tasks = {
            "crt.sh": fetch_crtsh(client, domain),
            "HackerTarget": fetch_hackertarget(client, domain),
            "AlienVault OTX": fetch_alienvault(client, domain),
            "URLScan.io": fetch_urlscan(client, domain),
            "Wayback Machine": fetch_wayback(client, domain)
        }
        
        # Await all API calls concurrently
        completed = await asyncio.gather(*tasks.values(), return_exceptions=True)
        
        for name, res in zip(tasks.keys(), completed):
            if isinstance(res, set):
                results[name] = res
            else:
                results[name] = set()
                
    return results

def run_recon(session, config):
    console.print("\n[bold blue]━━ PHASE 1: NATIVE OSINT INTELLIGENCE ENGINE ━━[/bold blue]")
    domain = session.domain
    
    console.print("INFO     Deploying concurrent API scrapers (Zero Third-Party Dependencies)...")
    
    results = asyncio.run(deploy_omniscient_engine(domain))
    
    total_found = set()
    for source, subs in results.items():
        if subs:
            total_found.update(subs)
            console.print(f"[green]  + {source} returned {len(subs)} assets.[/green]")
        else:
            console.print(f"[dim]  ! {source} query returned 0 assets or timed out.[/dim]")

    if total_found:
        session.add_subdomain(list(total_found))
        
    console.print(f"INFO     Total Unique Subdomains Discovered: {len(total_found)}")
