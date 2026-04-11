import asyncio
import aiohttp
import logging
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

PAYLOADS = {
    "SQLi": ["'", "1' OR '1'='1", "';--", "1\" OR \"1\"=\"1", "admin'--"],
    "XSS": ["<script>alert(1)</script>", "\"><img src=x onerror=prompt(1)>"],
    "LFI": ["../../../../../../../../etc/passwd", "../../../../windows/win.ini"]
}
CHRONOS_PAYLOADS = {
    "Time-Blind SQLi": ["1' OR SLEEP(6)--", "1); pg_sleep(6)--", "1'; WAITFOR DELAY '0:0:6'--"]
}

DETECTIONS = {
    "SQLi": re.compile(r'(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL query failed|SQLite/JDBCDriver|SequelizeDatabaseError)', re.I),
    "XSS": re.compile(r'(<script>alert\(1\)</script>|"><img src=x onerror=prompt\(1\)>)', re.I),
    "LFI": re.compile(r'(root:x:0:0:|\[extensions\]|boot loader)', re.I)
}

COMMON_PARAMS = ["id", "page", "username", "email", "password", "file", "q"]
SWAGGER_PATHS = ["/swagger.json", "/api/swagger.json", "/openapi.json", "/v2/api-docs", "/api-docs"]

async def hunt_swagger(client, base_url, session_state):
    parsed_base = urlparse(base_url)
    root_url = f"{parsed_base.scheme}://{parsed_base.netloc}"
    for path in SWAGGER_PATHS:
        target_url = urljoin(root_url, path)
        try:
            async with client.get(target_url, timeout=5, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'paths' in data:
                        console.print(f"[bold magenta]  [*] SEMANTIC BREACH: API Blueprint at {target_url}[/bold magenta]")
                        for api_path in data.get('paths', {}).keys():
                            session_state.add_crawled_url(urljoin(root_url, data.get('basePath', '') + api_path))
                        return True
        except Exception: pass
    return False

async def measure_baseline(client, url):
    """Auto-Calibrates the network latency to detect WAF Tarpits."""
    try:
        start = time.perf_counter()
        async with client.get(url, timeout=8, ssl=False) as r:
            await r.read()
        return time.perf_counter() - start
    except Exception:
        return 9.0 # Assume heavy tarpit on failure

async def fuzz_endpoint(client, url, session_state):
    vulnerabilities_found = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query) or {p: ["1"] for p in COMMON_PARAMS}

    # 1. Establish Baseline Latency
    baseline = await measure_baseline(client, url)
    is_tarpitted = baseline > 4.0

    for param, values in query_params.items():
        # Polyglot Fuzzing
        for vuln_type, payloads in PAYLOADS.items():
            for payload in payloads:
                fuzzed_params = query_params.copy()
                fuzzed_params[param] = [payload]
                target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
                json_payload = {p: payload if p == param else "test" for p in query_params.keys()}

                try:
                    async with client.get(target_url, timeout=5, ssl=False) as r_get:
                        if DETECTIONS[vuln_type].search(await r_get.text()):
                            console.print(f"[red]  ! [HIGH] {vuln_type} via GET on {url}[/red]")
                            vulnerabilities_found.append({"type": "VULN", "name": f"GET {vuln_type}", "matched-at": url, "info": {"severity": "HIGH"}})
                            break 
                    async with client.post(url, json=json_payload, headers={"Content-Type": "application/json"}, timeout=5, ssl=False) as r_post:
                        if DETECTIONS[vuln_type].search(await r_post.text()):
                            console.print(f"[red]  ! [HIGH] {vuln_type} via POST on {url}[/red]")
                            vulnerabilities_found.append({"type": "VULN", "name": f"POST {vuln_type}", "matched-at": url, "info": {"severity": "HIGH"}})
                            break
                except Exception: pass

        # Chronos Temporal Fuzzing (Protected by Auto-Calibration)
        if is_tarpitted:
            continue # Skip temporal fuzzing to prevent WAF false positives

        for vuln_type, payloads in CHRONOS_PAYLOADS.items():
            for payload in payloads:
                fuzzed_params = query_params.copy()
                fuzzed_params[param] = [payload]
                target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
                chronos_timeout = aiohttp.ClientTimeout(total=12) 
                
                # Dynamic Threshold: Must be 5 seconds slower than the normal baseline
                threshold = baseline + 5.0 

                try:
                    start_time = time.perf_counter()
                    async with client.get(target_url, timeout=chronos_timeout, ssl=False) as r_get:
                        await r_get.read()
                    if (time.perf_counter() - start_time) >= threshold:
                        console.print(f"[red]  ! [CRITICAL] {vuln_type} via GET on {url}[/red]")
                        vulnerabilities_found.append({"type": "VULN", "name": f"Chronos {vuln_type}", "matched-at": url, "info": {"severity": "CRITICAL"}})
                        break
                except asyncio.TimeoutError: pass
                except Exception: pass
                    
    return vulnerabilities_found

async def deploy_fuzzer(session_state, api_targets, root_hosts):
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as client:
        if root_hosts:
            await asyncio.gather(*[hunt_swagger(client, h, session_state) for h in root_hosts])
        for i in range(0, len(api_targets), 100):
            chunk = api_targets[i:i + 100]
            results = await asyncio.gather(*[fuzz_endpoint(client, t, session_state) for t in chunk])
            for vuln_list in results:
                if vuln_list: session_state.vulnerabilities.extend(vuln_list)

def run_fuzzer(session, config):
    console.print("\n[bold blue]━━ PHASE 5: NATIVE API FUZZER (AUTO-CALIBRATED) ━━[/bold blue]")
    root_hosts = {h['url'] if isinstance(h, dict) else h for h in session.get_live_hosts()}
    api_targets = {u['url'] if isinstance(u, dict) else u for u in session.get_crawled_urls()}
    api_targets = [t for t in api_targets if not re.search(r'\.(css|js|png|jpg|svg|woff2|ico)$', t, re.I)]
    
    if not root_hosts and not api_targets: return
    asyncio.run(deploy_fuzzer(session, list(api_targets), list(root_hosts)))
