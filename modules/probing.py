import asyncio
import aiohttp
import logging
import re
import random
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

TECH_SIGS = {
    "Cloudflare": {"headers": {"server": "cloudflare"}},
    "Amazon S3": {"headers": {"server": "AmazonS3"}},
    "Nginx": {"headers": {"server": "nginx"}},
    "Apache": {"headers": {"server": "apache"}},
    "Next.js": {"body": ["_next/static", "__NEXT_DATA__"]},
    "React": {"body": ["data-reactroot", "react-dom"]},
    "Vue.js": {"body": ["data-v-", "__vue__"]},
    "WordPress": {"body": ["wp-content", "wp-includes"]},
    "Bootstrap": {"body": ["bootstrap.min.css", "twitter-bootstrap"]},
    "jQuery": {"body": ["jquery.min.js"]}
}

TITLE_REGEX = re.compile(r'<title[^>]*>([^<]+)</title>', re.IGNORECASE | re.DOTALL)

async def probe_target(client, sem, url, session_state):
    async with sem:
        if not url.startswith("http"): url = f"https://{url}"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        try:
            async with client.get(url, headers=headers, timeout=10, ssl=False, allow_redirects=True) as response:
                status = response.status
                text = await response.text()
                
                title_match = TITLE_REGEX.search(text)
                title = title_match.group(1).strip() if title_match else "No Title"
                server = response.headers.get("Server", "Unknown")
                
                detected_tech = set()
                if server != "Unknown": detected_tech.add(server)
                
                for tech, sig in TECH_SIGS.items():
                    for h_key, h_val in sig.get("headers", {}).items():
                        if h_val.lower() in response.headers.get(h_key, "").lower(): detected_tech.add(tech)
                    for b_val in sig.get("body", []):
                        if b_val in text: detected_tech.add(tech)

                tech_list = list(detected_tech) or ["Undetected"]
                tech_str = ", ".join(tech_list[:3]) + ("..." if len(tech_list) > 3 else "")

                status_color = "green" if status in [200, 301, 302] else "yellow" if status in [401, 403] else "red"
                console.print(f"[{status_color}]  + {url} [/{status_color}][dim] [{status}] | Tech: {tech_str}[/dim]")

                session_state.add_live_host(
                    url=url, status=status, title=title, server=server, tech=tech_list
                )
        except Exception:
            pass 

async def deploy_prober(session_state, targets):
    CHUNK_SIZE = 500  # Backpressure chunking limit
    sem = asyncio.Semaphore(20) # Stealth Governor
    
    connector = aiohttp.TCPConnector(limit=0, ssl=False, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as client:
        # Process in memory-safe batches
        for i in range(0, len(targets), CHUNK_SIZE):
            chunk = targets[i:i + CHUNK_SIZE]
            tasks = [probe_target(client, sem, target, session_state) for target in chunk]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.1) # Clear TCP sockets before next chunk

def run_probing(session, config):
    console.print("\n[bold blue]━━ PHASE 2: NATIVE ACTIVE PROBING (BACKPRESSURE ACTIVE) ━━[/bold blue]")
    targets = session.get_subdomains()
    if not targets:
        log.warning("No targets available for active probing.")
        return
    console.print(f"INFO     Probing {len(targets)} targets (Stealth Governor & Chunking)...")
    asyncio.run(deploy_prober(session, targets))
    console.print(f"INFO     Active Live Hosts Profiled: {len(session.get_live_hosts())}")
