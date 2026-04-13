from core.ui import print_briefing
import asyncio
import aiohttp
import logging
import re
import json
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from rich.console import Console
from playwright.async_api import async_playwright
from core.mesh import mesh

console = Console()
log = logging.getLogger("rich")

UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
HASH_REGEX = re.compile(r'\b[0-9a-f]{32,64}\b', re.I)
INT_REGEX = re.compile(r'\b\d+\b')
LINK_REGEX = re.compile(r'(?:href|src)=["\']([^"\'#]+)["\']', re.I)
IGNORE_EXTS = ('.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.woff', '.woff2', '.mp4', '.css', '.ico', '.zip', '.tar', '.gz')

def get_skeleton(url):
    parsed = urlparse(url)
    path = parsed.path
    return f"{parsed.netloc}{INT_REGEX.sub('{int}', HASH_REGEX.sub('{hash}', UUID_REGEX.sub('{uuid}', path)))}"

async def mine_historical(client, url, extract_key):
    endpoints = set()
    try:
        proxy_url, proxy_auth = await mesh.get_node()
        async with client.get(url, timeout=15, ssl=False, proxy=proxy_url, proxy_auth=proxy_auth) as r:
            if r.status == 200:
                data = await r.json()
                for item in data if isinstance(data, list) else data.get(extract_key, []):
                    if isinstance(item, list) and len(item) > 0: endpoints.add(item[0])
                    elif isinstance(item, dict): endpoints.add(item.get('url'))
    except Exception: pass
    return endpoints

async def deploy_ghost_archive(session_state, domain):
    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as client:
        wayback = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        alien = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1"
        results = await asyncio.gather(mine_historical(client, wayback, None), mine_historical(client, alien, 'url_list'))
        
    return {url for url in results[0].union(results[1]) if url.startswith(('http://', 'https://')) and urlparse(url).netloc.endswith(domain) and not urlparse(url).path.lower().endswith(IGNORE_EXTS)}

async def intercept_js_traffic(url, browser, session_state, global_skeletons, domain):
    try:
        # INJECT AUTH HEADERS
        context = await browser.new_context(ignore_https_errors=True, extra_http_headers=getattr(session_state, 'auth_headers', {}))
        
        # INJECT AUTH COOKIES
        cookies_dict = getattr(session_state, 'auth_cookies', {})
        if cookies_dict:
            pw_cookies = [{"name": k, "value": v, "domain": f".{domain}", "path": "/"} for k, v in cookies_dict.items()]
            await context.add_cookies(pw_cookies)

        page = await context.new_page()
        
        async def log_request(request):
            req_url = request.url
            parsed = urlparse(req_url)
            if parsed.netloc.endswith(domain) and not parsed.path.lower().endswith(IGNORE_EXTS):
                skeleton = get_skeleton(req_url)
                if global_skeletons[skeleton] < 3:
                    global_skeletons[skeleton] += 1
                    session_state.add_crawled_url(req_url)

        page.on("request", log_request)
        
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(4000) 
        except Exception: pass

        try:
            links = await page.eval_on_selector_all("a[href]", "elements => elements.map(e => e.href)")
            for link in links:
                if urlparse(link).netloc.endswith(domain) and not urlparse(link).path.lower().endswith(IGNORE_EXTS):
                    skeleton = get_skeleton(link)
                    if global_skeletons[skeleton] < 3:
                        global_skeletons[skeleton] += 1
                        session_state.add_crawled_url(link)
        except Exception: pass
        await context.close()
    except Exception: pass 

async def deploy_phantom_dom(session_state, targets, global_skeletons):
    domain = session_state.domain
    sem = asyncio.Semaphore(5) 
    async def bounded_intercept(url, browser):
        async with sem: await intercept_js_traffic(url, browser, session_state, global_skeletons, domain)

    try:
        async with async_playwright() as p:
            # Playwright does not natively support rotating async proxies per-request easily, so we use the default IP for DOM rendering to maintain JS stability
            browser = await p.chromium.launch(headless=True)
            await asyncio.gather(*[bounded_intercept(t, browser) for t in targets])
            await browser.close()
    except Exception as e: console.print(f"[yellow]WARNING Phantom DOM failed: {e}[/yellow]")

async def crawl_target(client, sem, url, session_state, global_skeletons):
    async with sem:
        try:
            proxy_url, proxy_auth = await mesh.get_node()
            async with client.get(url, timeout=7, ssl=False, proxy=proxy_url, proxy_auth=proxy_auth) as r:
                if r.status != 200: return
                for link in LINK_REGEX.findall(await r.text()):
                    full_url = urljoin(url, link)
                    if urlparse(full_url).netloc.endswith(session_state.domain) and full_url.startswith(('http://', 'https://')) and not urlparse(full_url).path.lower().endswith(IGNORE_EXTS):
                        skeleton = get_skeleton(full_url)
                        if global_skeletons[skeleton] < 3:
                            global_skeletons[skeleton] += 1
                            session_state.add_crawled_url(full_url)
        except Exception: pass

async def deploy_spider(session_state, targets, global_skeletons):
    sem = asyncio.Semaphore(50)
    connector = aiohttp.TCPConnector(limit=0, ssl=False)
    headers = getattr(session_state, 'auth_headers', {})
    cookies = getattr(session_state, 'auth_cookies', {})
    
    async with aiohttp.ClientSession(connector=connector, headers=headers, cookies=cookies) as client:
        for i in range(0, len(targets), 500):
            await asyncio.gather(*[crawl_target(client, sem, t, session_state, global_skeletons) for t in targets[i:i+500]])

def run_spider(session, config):
    console.print("\n[bold blue]━━ PHASE 2.2: THE SPIDER (GHOST ARCHIVE & PHANTOM DOM) ━━[/bold blue]")
    targets = [t['url'] if isinstance(t, dict) else t for t in session.get_live_hosts()]
    global_skeletons = defaultdict(int) 
    
    console.print(f"INFO     Mining Historical Archives for Zombie APIs...")
    historical_urls = asyncio.run(deploy_ghost_archive(session, session.domain))
    for url in historical_urls:
        skeleton = get_skeleton(url)
        if global_skeletons[skeleton] < 3:
            global_skeletons[skeleton] += 1
            session.add_crawled_url(url)
            
    if not targets: return
        
    initial_count = len(session.get_crawled_urls())
    print_briefing(
        title="Phantom DOM Injection",
        happening="Spawning local headless Chromium. Injecting user-provided authentication cookies/headers to bypass login walls and intercept authenticated XHR backend traffic.",
        fallback="If the WAF blocks headless execution (e.g. Cloudflare Turnstile), Kestrel safely catches the timeout and falls back to static aiohttp spidering.",
        command="playwright show-trace trace.zip (If tracing enabled)"
    )
    console.print(f"INFO     Deploying Phantom DOM (Auth/JS Interceptor) to {len(targets)} active hosts...")
    asyncio.run(deploy_phantom_dom(session, targets, global_skeletons))
    
    current_count = len(session.get_crawled_urls())
    console.print(f"INFO     Deploying Distributed Async Spider (Static HTML Mapping)...")
    asyncio.run(deploy_spider(session, targets, global_skeletons))
    
    console.print(f"  + Spider Complete. {len(session.get_crawled_urls()) - initial_count} endpoints securely mapped.")
