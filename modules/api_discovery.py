import asyncio
import aiohttp
import json
import logging
import re
from urllib.parse import urljoin, urlencode, urlunparse, urlparse
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# Target schema definitions
SCHEMA_PATHS = [
    "swagger.json", "api/swagger.json", "v1/swagger.json", "v2/swagger.json",
    "openapi.json", "api/openapi.json", "v1/openapi.json",
    "api-docs", "api/v1/api-docs", "api/v2/api-docs", "v1/api-docs"
]

GRAPHQL_PATHS = [
    "graphql", "api/graphql", "v1/graphql", "graphql/console", "graphiql"
]

async def parse_openapi(base_url, schema_json, session_state):
    """Deconstructs OpenAPI specifications into fuzzer-ready query endpoints."""
    endpoints_added = 0
    try:
        paths = schema_json.get("paths", {})
        if not paths: return 0
        
        for path, methods in paths.items():
            # Standardize dynamic path parameters (e.g., /user/{id} -> /user/1)
            fuzzed_path = re.sub(r'\{[a-zA-Z0-9_\-]+\}', '1', path)
            
            for method, data in methods.items():
                if method.lower() not in ["get", "post", "put", "delete"]: continue
                
                query_params = {}
                parameters = data.get("parameters", [])
                
                # Global path parameters fallback
                if not parameters and "parameters" in paths[path]:
                    parameters = paths[path]["parameters"]
                    
                for param in parameters:
                    p_name = param.get("name")
                    p_in = param.get("in", "query")
                    
                    if p_in == "query" and p_name:
                        query_params[p_name] = "test"
                
                # Construct query string if parameters exist
                constructed_url = urljoin(base_url, fuzzed_path.lstrip("/"))
                if query_params:
                    parsed_url = urlparse(constructed_url)
                    constructed_url = urlunparse(parsed_url._replace(query=urlencode(query_params)))
                
                # Drop straight into Kestrel's memory/DB execution cache
                session_state.add_crawled_url(constructed_url)
                endpoints_added += 1
                
        return endpoints_added
    except Exception as e:
        log.debug(f"OpenAPI parsing error: {e}")
        return 0

async def probe_endpoint(client, host_url, path, is_graphql, session_state):
    """Probes and processes individual spec endpoints."""
    target_url = urljoin(host_url, path)
    try:
        async with client.get(target_url, timeout=4, ssl=False) as r:
            if r.status_code == 200:
                if is_graphql:
                    console.print(f"  + [FOUND] GraphQL Endpoint: {target_url}")
                    session_state.add_crawled_url(f"{target_url}?query={{__schema{{types{{name}}}}}}")
                    return 1
                else:
                    try:
                        content = await r.json()
                        if "openapi" in content or "swagger" in content:
                            count = await parse_openapi(host_url, content, session_state)
                            if count > 0:
                                console.print(f"  + [FOUND] OpenAPI Specification: {target_url} [green]({count} routes parsed)[/green]")
                                return count
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return 0

async def execute_discovery(session_state, active_hosts):
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    headers = getattr(session_state, 'auth_headers', {})
    cookies = getattr(session_state, 'auth_cookies', {})
    
    async with aiohttp.ClientSession(connector=connector, headers=headers, cookies=cookies) as client:
        tasks = []
        for host in active_hosts:
            url = host.get('url', '') if isinstance(host, dict) else host
            if not url: continue
            
            # Queue OpenAPI definitions
            for path in SCHEMA_PATHS:
                tasks.append(probe_endpoint(client, url, path, False, session_state))
            # Queue GraphQL endpoints
            for path in GRAPHQL_PATHS:
                tasks.append(probe_endpoint(client, url, path, True, session_state))
                
        results = await asyncio.gather(*tasks)
        return sum(results)

def run_api_discovery(session, config):
    console.print("\n[bold blue]━━ PHASE 2.1: API SCHEMA PARSING & SPEC DISCOVERY ━━[/bold blue]")
    
    # Extract live profiled hosts from Phase 2.0 Probing
    live_hosts = session.get_live_hosts()
    if not live_hosts:
        console.print("WARNING  No active live web hosts available for schema hunting. Skipping Phase.")
        return
        
    console.print(f"INFO     Hunting for API Blueprints across {len(live_hosts)} verified targets...")
    total_discovered = asyncio.run(execute_discovery(session, live_hosts))
    
    if total_discovered > 0:
        console.print(f"  + Ingested {total_discovered} newly mapped endpoints into the pipeline cache.")
    else:
        console.print("  * No public OpenAPI documents or GraphQL endpoints discovered via static probing.")
