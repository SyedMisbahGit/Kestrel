import asyncio
import aiohttp
import logging
import re
from urllib.parse import urljoin
from rich.console import Console

log = logging.getLogger("rich")
console = Console()

JS_REGEX = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
HREF_REGEX = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

async def crawl_target(session_client, url, state_session):
    try:
        async with session_client.get(url, timeout=10, ssl=False) as response:
            if response.status == 200:
                html = await response.text()
                
                js_files = JS_REGEX.findall(html)
                for js in js_files:
                    state_session.add_crawled_url(urljoin(url, js))

                links = HREF_REGEX.findall(html)
                for link in links:
                    if link.startswith('/') or url in link:
                        state_session.add_crawled_url(urljoin(url, link))
    except Exception:
        pass 

async def deploy_spider(state_session, targets):
    # OOM Protection: Chunking
    CHUNK_SIZE = 500 
    connector = aiohttp.TCPConnector(limit=50) # Connection pool limit
    
    async with aiohttp.ClientSession(connector=connector) as client:
        # Process targets in strict memory-safe batches
        for i in range(0, len(targets), CHUNK_SIZE):
            chunk = targets[i:i + CHUNK_SIZE]
            tasks = [crawl_target(client, target['url'] if isinstance(target, dict) else target, state_session) for target in chunk]
            
            # Await the chunk to finish before loading the next batch into RAM
            await asyncio.gather(*tasks)
            
            # Optional: Add a tiny sleep to let the OS clear TCP sockets
            await asyncio.sleep(0.1)

def run_spider(session, config):
    console.print("[bold blue]━━ PHASE 2.2: THE SPIDER (ASYNC BACKPRESSURE ACTIVE) ━━[/bold blue]")
    
    live_hosts = session.get_live_hosts()
    if not live_hosts:
        console.print("WARNING  No live hosts to crawl. Skipping.")
        return

    console.print(f"INFO     Deploying Async Spider to {len(live_hosts)} targets (Chunk Size: 500)...")
    asyncio.run(deploy_spider(session, live_hosts))
    
    total_crawled = len(session.get_crawled_urls())
    console.print(f"  + Spider Complete. Mapped and injected {total_crawled} endpoints/bundles for analysis.")
