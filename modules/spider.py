import asyncio
import aiohttp
import logging
import re
import json
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- THE SKELETON ENGINE ---
UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
HASH_REGEX = re.compile(r'\b[0-9a-f]{32,64}\b', re.I)
INT_REGEX = re.compile(r'\b\d+\b')
LINK_REGEX = re.compile(r'(?:href|src)=["\']([^"\'#]+)["\']', re.I)

# Assets we do not want to crawl or fuzz
IGNORE_EXTS = ('.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.woff', '.woff2', '.mp4', '.css', '.ico', '.zip', '.tar', '.gz')

def get_skeleton(url):
    parsed = urlparse(url)
    path = parsed.path
    path = UUID_REGEX.sub('{uuid}', path)
    path = HASH_REGEX.sub('{hash}', path)
    path = INT_REGEX.sub('{int}', path)
    return f"{parsed.netloc}{path}"

# --- THE GHOST ARCHIVE (ZOMBIE API MINING) ---
async def mine_wayback(client, domain):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    endpoints = set()
    try:
        async with client.get(url, timeout=15, ssl=False) as r:
            if r.status == 200:
                data = await r.json()
                # Skip the first row (headers)
                for row in data[1:]:
                    if len(row) > 0: endpoints.add(row[0])
    except Exception: pass
    return endpoints

async def mine_alienvault(client, domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1"
    endpoints = set()
    try:
        async with client.get(url, timeout=15, ssl=False) as r:
            if r.status == 200:
                data = await r.json()
                for item in data.get('url_list', []):
                    endpoints.add(item.get('url'))
    except Exception: pass
    return endpoints

async def deploy_ghost_archive(session_state, domain):
    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as client:
        results = await asyncio.gather(
            mine_wayback(client, domain),
            mine_alienvault(client, domain)
        )
    
    historical_urls = results[0].union(results[1])
    valid_urls = set()
    
    for url in historical_urls:
        if not url.startswith(('http://', 'https://')): continue
        parsed = urlparse(url)
        if not parsed.netloc.endswith(domain): continue
        if parsed.path.lower().endswith(IGNORE_EXTS): continue
        valid_urls.add(url)
        
    return valid_urls

# --- THE LIVE CRAWLER ---
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
                    
                    if not parsed_full.netloc.endswith(session_state.domain): continue
                    if not full_url.startswith(('http://', 'https://')): continue
                    if parsed_full.path.lower().endswith(IGNORE_EXTS): continue
                    
                    skeleton = get_skeleton(full_url)
                    if global_skeletons[skeleton] >= 3:
                        continue 
                        
                    global_skeletons[skeleton] += 1
                    session_state.add_crawled_url(full_url)
                    
        except Exception:
            pass

async def deploy_spider(session_state, targets):
    CHUNK_SIZE = 500
    sem = asyncio.Semaphore(50)
    global_skeletons = defaultdict(int) 
    
    connector = aiohttp.TCPConnector(limit=0, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as client:
        for i in range(0, len(targets), CHUNK_SIZE):
            chunk = targets[i:i+CHUNK_SIZE]
            clean_targets = [t['url'] if isinstance(t, dict) else t for t in chunk]
            tasks = [crawl_target(client, sem, t, session_state, global_skeletons) for t in clean_targets]
            await asyncio.gather(*tasks)

def run_spider(session, config):
    console.print("\n[bold blue]━━ PHASE 2.2: THE SPIDER (GHOST ARCHIVE & ANTI-TRAP) ━━[/bold blue]")
    domain = session.domain
    targets = session.get_live_hosts()
    
    # 1. Historical Mining
    console.print(f"INFO     Mining Historical Archives (Wayback/AlienVault) for Zombie APIs...")
    historical_urls = asyncio.run(deploy_ghost_archive(session, domain))
    
    global_skeletons = defaultdict(int)
    injected_historical = 0
    for url in historical_urls:
        skeleton = get_skeleton(url)
        if global_skeletons[skeleton] < 3:
            global_skeletons[skeleton] += 1
            session.add_crawled_url(url)
            injected_historical += 1
            
    console.print(f"  + Ghost Archive Complete. Resurrected {injected_historical} historical endpoints.")
    
    # 2. Live Crawling
    if not targets:
        console.print("WARNING  No live hosts to crawl. Skipping live spider.")
        return
        
    console.print(f"INFO     Deploying Live Async Spider to {len(targets)} targets (URL Skeleton Depth-Limiter Active)...")
    
    initial_count = len(session.get_crawled_urls())
    asyncio.run(deploy_spider(session, targets))
    new_count = len(session.get_crawled_urls())
    
    console.print(f"  + Live Spider Complete. Safely mapped {new_count - initial_count} active endpoints.")
