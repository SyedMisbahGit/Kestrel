import asyncio
import aiohttp
import logging
import re
import random
import mmh3
import base64
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"]

# --- SHODAN FAVICON HASHES ---
FAVICON_HASHES = {
    116323821: "Spring Boot",
    81586312: "Jenkins",
    1398055326: "Apache Tomcat",
    -1536000212: "React",
    1480026135: "Next.js",
    -31682854: "Vue.js",
    548082013: "WordPress",
    1139158307: "Laravel",
    -1416434454: "GitLab"
}

TECH_SIGS = {
    "Cloudflare": {"headers": {"server": "cloudflare"}},
    "Nginx": {"headers": {"server": "nginx"}},
    "Apache": {"headers": {"server": "apache"}},
    "PHP": {"headers": {"x-powered-by": "php"}, "body": [".php"]}
}

TITLE_REGEX = re.compile(r'<title[^>]*>([^<]+)</title>', re.IGNORECASE | re.DOTALL)

def get_favicon_hash(data):
    """Calculates the MurmurHash3 value of a favicon exactly as Shodan does."""
    b64 = base64.encodebytes(data).decode()
    return mmh3.hash(b64.encode())

async def fetch_url_and_tech(client, url, headers):
    status, text, server, resp_headers = None, None, "Unknown", {}
    detected_tech = set()
    
    # 1. Fetch Main Page
    async with client.get(url, headers=headers, timeout=8, ssl=False, allow_redirects=True) as response:
        status = response.status
        text = await response.text()
        server = response.headers.get("Server", "Unknown")
        resp_headers = response.headers

    # 2. Fetch and Hash Favicon (Bypass WAF Stripping)
    favicon_url = f"{url.rstrip('/')}/favicon.ico"
    try:
        async with client.get(favicon_url, headers=headers, timeout=5, ssl=False) as fav_resp:
            if fav_resp.status == 200:
                data = await fav_resp.read()
                fav_hash = get_favicon_hash(data)
                if fav_hash in FAVICON_HASHES:
                    detected_tech.add(FAVICON_HASHES[fav_hash])
    except Exception:
        pass

    # 3. Standard Heuristics
    if server != "Unknown": detected_tech.add(server)
    for tech, sig in TECH_SIGS.items():
        for h_key, h_val in sig.get("headers", {}).items():
            if h_val.lower() in resp_headers.get(h_key, "").lower(): detected_tech.add(tech)
        for b_val in sig.get("body", []):
            if b_val in text: detected_tech.add(tech)

    return status, text, server, detected_tech

async def probe_target(client, sem, url, session_state):
    async with sem:
        clean_url = url.replace('https://', '').replace('http://', '')
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        final_url, status, text, detected_tech = None, None, None, set()

        # Protocol Fallback Engine
        try:
            final_url = f"https://{clean_url}"
            status, text, server, detected_tech = await fetch_url_and_tech(client, final_url, headers)
        except Exception:
            try:
                final_url = f"http://{clean_url}"
                status, text, server, detected_tech = await fetch_url_and_tech(client, final_url, headers)
            except Exception:
                return

        title_match = TITLE_REGEX.search(text)
        title = title_match.group(1).strip() if title_match else "No Title"

        tech_list = list(detected_tech) or ["Undetected"]
        tech_str = ", ".join(tech_list[:3]) + ("..." if len(tech_list) > 3 else "")
        status_color = "green" if status in [200, 301, 302] else "yellow" if status in [401, 403] else "red"
        
        console.print(f"[{status_color}]  + {final_url} [/{status_color}][dim] [{status}] | Tech: {tech_str}[/dim]")
        session_state.add_live_host(url=final_url, status=status, title=title, server=server, tech=tech_list)

async def deploy_prober(session_state, targets):
    CHUNK_SIZE = 500  
    sem = asyncio.Semaphore(30)
    connector = aiohttp.TCPConnector(limit=0, ssl=False, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as client:
        for i in range(0, len(targets), CHUNK_SIZE):
            chunk = targets[i:i + CHUNK_SIZE]
            tasks = [probe_target(client, sem, target, session_state) for target in chunk]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.1)

def run_probing(session, config):
    console.print("\n[bold blue]━━ PHASE 2: NATIVE ACTIVE PROBING (FAVICON HASHING) ━━[/bold blue]")
    targets = session.get_subdomains()
    if not targets: return
    console.print(f"INFO     Probing {len(targets)} targets (Protocol Fallback & Favicon Hashing)...")
    asyncio.run(deploy_prober(session, targets))
    console.print(f"INFO     Active Live Hosts Profiled: {len(session.get_live_hosts())}")
