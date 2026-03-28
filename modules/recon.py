import subprocess
import requests
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

def fetch_wayback(domain):
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit=5000", timeout=15)
        if r.status_code == 200:
            urls = [x[2] for x in r.json()[1:]]
            subs = set()
            regex = re.compile(r'https?://([a-zA-Z0-9.-]+)')
            for url in urls:
                match = regex.search(url)
                if match and match.group(1).endswith(domain):
                    subs.add(match.group(1))
            return subs
    except Exception:
        pass
    return set()

def fetch_alienvault(domain):
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=15)
        if r.status_code == 200:
            return {x['hostname'] for x in r.json().get('passive_dns', []) if domain in x['hostname']}
    except Exception:
        pass
    return set()

def fetch_urlscan(domain):
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000", timeout=15)
        if r.status_code == 200:
            return {x['page']['domain'] for x in r.json().get('results', []) if 'page' in x and domain in x['page'].get('domain', '')}
    except Exception:
        pass
    return set()

def run_recon(session, config):
    console.print("[bold blue]━━ PHASE 1: PASSIVE RECON & THE ARCHIVIST ━━[/bold blue]")
    domain = session.domain
    
    # 1. Subfinder
    console.print("INFO     Running Subfinder...")
    cmd = ["subfinder", "-d", domain, "-silent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        subs = set(result.stdout.splitlines())
        session.subdomains.extend(list(subs))
        console.print(f"INFO     Subfinder found {len(subs)} subdomains")
    except Exception as e:
        log.error(f"Subfinder failed: {e}")

    # 2. The Archivist (Multi-threaded Historical Recon)
    console.print("INFO     Deploying The Archivist (Wayback, AlienVault, URLScan)...")
    historical_subs = set()
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(fetch_wayback, domain): "Wayback Machine",
            executor.submit(fetch_alienvault, domain): "AlienVault OTX",
            executor.submit(fetch_urlscan, domain): "URLScan.io"
        }
        
        for future in futures:
            source = futures[future]
            try:
                res = future.result()
                historical_subs.update(res)
                console.print(f"[green]  + {source} returned {len(res)} historical assets.[/green]")
            except Exception:
                console.print(f"[red]  ! {source} query failed or timed out.[/red]")

    if historical_subs:
        session.subdomains.extend(list(historical_subs))
        
    total_unique = len(set(session.subdomains))
    console.print(f"INFO     Total Unique Subdomains Found: {total_unique}")
