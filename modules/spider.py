import asyncio
import aiohttp
import logging
import re
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- THE SKELETON ENGINE ---
# Regex patterns to detect dynamic variables in URLs
UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
HASH_REGEX = re.compile(r'\b[0-9a-f]{32,64}\b', re.I)
INT_REGEX = re.compile(r'\b\d+\b')
LINK_REGEX = re.compile(r'(?:href|src)=["\']([^"\'#]+)["\']', re.I)

# Assets we do not want to crawl to save bandwidth
IGNORE_EXTS = ('.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.woff', '.woff2', '.mp4', '.css', '.ico', '.zip', '.tar', '.gz')

def get_skeleton(url):
    """Strips dynamic data to reveal the underlying URL structure."""
    parsed = urlparse(url)
    path = parsed.path
    path = UUID_REGEX.sub('{uuid}', path)
    path = HASH_REGEX.sub('{hash}', path)
    path = INT_REGEX.sub('{int}', path)
    return f"{parsed.netloc}{path}"

async def crawl_target(client, sem, url, session_state, global_skeletons):
    async with sem:
        try:
            async with client.get(url, timeout=5, ssl=False) as r:
                if r.status != 200: return
                text = await r.text()
                
                links = LINK_REGEX.findall(text)
                for link in links:
                    full_url = urljoin(url, link)
                    parsed_full = urlparse(full_url)
                    
                    # 1. Scope Boundary: Only map our target infrastructure
                    if not parsed_full.netloc.endswith(session_state.domain): continue
                    if not full_url.startswith(('http://', 'https://')): continue
                    if parsed_full.path.lower().endswith(IGNORE_EXTS): continue
                    
                    # 2. THE SPIDER TRAP DEFENSE
                    skeleton = get_skeleton(full_url)
                    if global_skeletons[skeleton] >= 3:
                        continue # Structural Trap Detected. Drop the URL silently.
                        
                    global_skeletons[skeleton] += 1
                    session_state.add_crawled_url(full_url)
                    
        except Exception:
            pass

async def deploy_spider(session_state, targets):
    CHUNK_SIZE = 500
    sem = asyncio.Semaphore(50)
    global_skeletons = defaultdict(int) # Tracks the structural frequency
    
    connector = aiohttp.TCPConnector(limit=0, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as client:
        for i in range(0, len(targets), CHUNK_SIZE):
            chunk = targets[i:i+CHUNK_SIZE]
            
            # Extract URL string whether it's a dict or a raw string
            clean_targets = [t['url'] if isinstance(t, dict) else t for t in chunk]
            
            tasks = [crawl_target(client, sem, t, session_state, global_skeletons) for t in clean_targets]
            await asyncio.gather(*tasks)

def run_spider(session, config):
    console.print("\n[bold blue]━━ PHASE 2.2: THE SPIDER (STRUCTURE-HASHING & ANTI-TRAP) ━━[/bold blue]")
    targets = session.get_live_hosts()
    
    if not targets:
        console.print("WARNING  No live hosts to crawl. Skipping.")
        return
        
    console.print(f"INFO     Deploying Async Spider to {len(targets)} targets (URL Skeleton Depth-Limiter Active)...")
    
    initial_count = len(session.get_crawled_urls())
    asyncio.run(deploy_spider(session, targets))
    new_count = len(session.get_crawled_urls())
    
    console.print(f"  + Spider Complete. Safely mapped {new_count - initial_count} endpoints without looping.")
