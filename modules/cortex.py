import re
import logging
import asyncio
import aiohttp
from urllib.parse import urljoin
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# Regex to catch API paths (e.g., /api/v2/users) and hidden URLs inside JS
ENDPOINT_REGEX = re.compile(r'(?:"|\')(((?:[a-zA-Z]{1,10}://|/)[^"\'\s]+|([a-zA-Z0-9_\-]+/)+[a-zA-Z0-9_\-]+))(?:"|\')')

async def extract_js_endpoints(session, js_url):
    endpoints = set()
    try:
        async with session.get(js_url, timeout=5, ssl=False) as response:
            if response.status == 200:
                content = await response.text()
                matches = ENDPOINT_REGEX.findall(content)
                for match in matches:
                    path = match[0]
                    # Filter out standard junk, CSS, and HTML strings
                    if not path.endswith(('.js', '.css', '.html', '.png', '.svg', '.woff2')):
                        if path.startswith('/') or 'api' in path.lower():
                            endpoints.add(path)
    except Exception:
        pass
    return js_url, endpoints

async def run_async_cortex(js_urls):
    extracted_data = {}
    connector = aiohttp.TCPConnector(limit_per_host=10, limit=50, verify_ssl=False)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [extract_js_endpoints(session, url) for url in js_urls]
        results = await asyncio.gather(*tasks)
        
        for url, endpoints in results:
            if endpoints:
                extracted_data[url] = endpoints
                
    return extracted_data

def run_cortex(session, config):
    console.print("[bold blue]━━ PHASE 3: CORTEX (NEURAL JS EXTRACTION) ━━[/bold blue]")
    
    # 1. Gather all JS files found by the Spider
    js_targets = []
    if hasattr(session, 'crawled_urls') and session.crawled_urls:
        js_targets = [url for url in session.crawled_urls if url.lower().endswith('.js')]
        
    if not js_targets:
        log.warning("No JavaScript bundles found. Skipping Cortex.")
        return

    console.print(f"INFO     Analyzing {len(js_targets)} JavaScript bundles for hidden APIs...")
    
    loop = asyncio.get_event_loop()
    extracted_data = loop.run_until_complete(run_async_cortex(js_targets))
    
    total_endpoints = 0
    for js_file, endpoints in extracted_data.items():
        console.print(f"[cyan]  + Bundle: {js_file.split('/')[-1]}[/cyan] -> Found {len(endpoints)} routes")
        total_endpoints += len(endpoints)
        
        # Pipe these newly found API endpoints back into the target pool for Nuclei
        for ep in endpoints:
            full_route = urljoin(js_file, ep)
            session.crawled_urls.append(full_route)

    if total_endpoints > 0:
        console.print(f"INFO     Cortex extracted and injected {total_endpoints} hidden API endpoints.")
    else:
        console.print("[dim]  + No actionable endpoints found in JS bundles.[/dim]")
