import asyncio
import aiohttp
import ssl
import socket
import json
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- 1. NATIVE LOCAL EXTRACTION (SSL/TLS SAN CARVING) ---
def extract_native_sans(domain):
    """Connects directly to the target to rip subdomains natively from their SSL certs."""
    sans = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                for field in cert.get('subjectAltName', []):
                    if field[0] == 'DNS':
                        clean_name = field[1].replace('*.', '').lower()
                        if clean_name.endswith(domain):
                            sans.add(clean_name)
    except Exception:
        pass
    return sans

# --- 2. THE API CIRCUIT BREAKER ARRAY ---
async def fetch_api(client, name, url, parser_func, timeout=5):
    """Executes a strict HTTP request. If it hangs, the circuit breaks."""
    try:
        async with client.get(url, timeout=timeout, ssl=False) as r:
            if r.status == 200:
                data = await r.text()
                results = parser_func(data)
                console.print(f"[green]  + {name} returned {len(results)} assets.[/green]")
                return results
            else:
                console.print(f"[dim]  ! {name} returned HTTP {r.status}[/dim]")
    except asyncio.TimeoutError:
        console.print(f"[yellow]  ! {name} Circuit Broken (Timeout).[/yellow]")
    except Exception:
        console.print(f"[dim]  ! {name} connection failed.[/dim]")
    return set()

# --- PARSERS ---
def parse_certspotter(data):
    try:
        return {name for entry in json.loads(data) for name in entry.get("dns_names", [])}
    except: return set()

def parse_anubis(data):
    try: return set(json.loads(data))
    except: return set()

def parse_hackertarget(data):
    return {line.split(',')[0] for line in data.splitlines() if line}

def parse_crtsh(data):
    try: return {entry.get("name_value", "").split('\n')[0] for entry in json.loads(data)}
    except: return set()

async def deploy_osint(domain):
    connector = aiohttp.TCPConnector(limit=50, ssl=False)
    discovered_subs = set()

    # 1. Fire Native Local Extraction immediately
    native_sans = extract_native_sans(domain)
    if native_sans:
        console.print(f"[bold magenta]  [*] NATIVE SAN EXTRACTION: Ripped {len(native_sans)} domains directly from SSL crypto.[/bold magenta]")
        discovered_subs.update(native_sans)

    # 2. Fire Async API Circuit Breakers
    apis = [
        ("CertSpotter", f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", parse_certspotter),
        ("Anubis", f"https://jldc.me/anubis/subdomains/{domain}", parse_anubis),
        ("HackerTarget", f"https://api.hackertarget.com/hostsearch/?q={domain}", parse_hackertarget),
        ("CRT.sh", f"https://crt.sh/?q=%25.{domain}&output=json", parse_crtsh)
    ]

    async with aiohttp.ClientSession(connector=connector) as client:
        tasks = [fetch_api(client, name, url, parser) for name, url, parser in apis]
        results = await asyncio.gather(*tasks)
        for res in results:
            discovered_subs.update(res)

    # Clean up results
    final_subs = {sub.lower().strip() for sub in discovered_subs if sub.endswith(domain) and '*' not in sub}
    return final_subs

def run_osint(session, config):
    console.print("\n[bold blue]━━ PHASE 1: HYBRID INTELLIGENCE ENGINE (NATIVE + API) ━━[/bold blue]")
    console.print("INFO     Deploying Native SSL Carving & API Circuit Breakers...")
    
    subdomains = asyncio.run(deploy_osint(session.domain))
    
    if subdomains:
        for sub in subdomains:
            session.add_subdomain(sub)
        console.print(f"INFO     Total Unique Subdomains Discovered: {len(subdomains)}")
    else:
        console.print("[red]WARNING  Total failure of all Intelligence nodes. Target may be air-gapped.[/red]")
