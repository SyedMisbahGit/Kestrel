import asyncio
import aiohttp
import logging
import re
import json
import esprima
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- PROJECT GHOST: TIER 1 SECRET SIGNATURES ---
SECRETS_REGEX = {
    "AWS Access Key": re.compile(r'(AKIA[0-9A-Z]{16})'),
    "Stripe Standard Key": re.compile(r'(sk_live_[0-9a-zA-Z]{24})'),
    "Google API Key": re.compile(r'(AIza[0-9A-Za-z-_]{35})'),
    "Slack Token": re.compile(r'(xox[baprs]-[0-9a-zA-Z]{10,48})'),
    "RSA Private Key": re.compile(r'(-----BEGIN RSA PRIVATE KEY-----)')
}

# --- THE AST TAINT TRACKER ---
class TaintTracker:
    def __init__(self):
        self.variables = {}
        self.endpoints = set()

    def walk(self, node):
        if not node or not hasattr(node, "type"): return

        # 1. Track Variable Assignments (e.g., const base = "/api/v1")
        if node.type == "VariableDeclarator":
            if node.id.type == "Identifier" and node.init:
                if node.init.type == "Literal" and isinstance(node.init.value, str):
                    self.variables[node.id.name] = node.init.value

        # 2. Track Concatenations (e.g., fetch(base + "/users"))
        if node.type == "BinaryExpression" and node.operator == "+":
            left = self._resolve_node(node.left)
            right = self._resolve_node(node.right)
            if left and right and isinstance(left, str) and isinstance(right, str):
                combined = left + right
                if "/" in combined and len(combined) > 4: 
                    self.endpoints.add(combined)

        # 3. Track Raw Literals
        if node.type == "Literal" and isinstance(node.value, str):
            if node.value.startswith(('/', 'http', 'api/')) and len(node.value) > 4:
                self.endpoints.add(node.value)

        # Recursion
        for key, val in vars(node).items():
            if isinstance(val, list):
                for item in val: self.walk(item)
            elif hasattr(val, "type"):
                self.walk(val)

    def _resolve_node(self, node):
        if not node or not hasattr(node, "type"): return ""
        if node.type == "Literal": return node.value
        if node.type == "Identifier": return self.variables.get(node.name, "")
        return ""

async def hunt_source_map(client, js_url, session_state):
    """PROJECT GHOST: Hunts for and reconstructs unminified source trees."""
    map_url = f"{js_url}.map"
    vulnerabilities = []
    
    try:
        async with client.get(map_url, timeout=8, ssl=False) as response:
            if response.status == 200:
                text = await response.text()
                try:
                    map_data = json.loads(text)
                    sources = map_data.get("sources", [])
                    contents = map_data.get("sourcesContent", [])
                    
                    if sources and contents:
                        console.print(f"[bold magenta]  [*] PROJECT GHOST: Extracted Unminified Source Tree from {js_url}[/bold magenta]")
                        console.print(f"      └ Recovered {len(sources)} original developer files (.ts, .jsx, .vue)")
                        
                        for filename, content in zip(sources, contents):
                            if not content: continue
                            for sec_name, regex in SECRETS_REGEX.items():
                                if regex.search(content):
                                    console.print(f"[bold red]  ! [CRITICAL] {sec_name} found in unminified {filename}[/bold red]")
                                    vulnerabilities.append({
                                        "type": "VULN", "name": f"Source Map Leak: {sec_name}", 
                                        "matched-at": map_url, "info": {"severity": "CRITICAL"}
                                    })
                except json.JSONDecodeError: pass
    except Exception: pass
    return vulnerabilities

async def extract_js_ast(client, js_url, session_state):
    """AST Neural Extraction: Bypasses Minification via Taint Tracking."""
    try:
        async with client.get(js_url, timeout=8, ssl=False) as response:
            if response.status == 200:
                text = await response.text()
                base_url = "/".join(js_url.split('/')[:3])
                
                try:
                    # Parse code into an Abstract Syntax Tree
                    tree = esprima.parseScript(text, {"tolerant": True})
                    tracker = TaintTracker()
                    tracker.walk(tree)
                    
                    for endpoint in tracker.endpoints:
                        if not endpoint.startswith('http'):
                            endpoint = base_url + ("/" if not endpoint.startswith('/') else "") + endpoint
                        session_state.add_crawled_url(endpoint)
                except Exception:
                    # Fallback if Esprima fails on overly complex ES6+ syntax
                    pass
    except Exception: pass

async def deploy_cortex(session_state, js_targets):
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as client:
        ghost_tasks = [hunt_source_map(client, url, session_state) for url in js_targets]
        results = await asyncio.gather(*ghost_tasks)
        for vuln_list in results:
            if vuln_list: session_state.vulnerabilities.extend(vuln_list)
                
        console.print("INFO     Executing AST Taint Tracking across JS clusters...")
        ast_tasks = [extract_js_ast(client, url, session_state) for url in js_targets]
        await asyncio.gather(*ast_tasks)

def run_cortex(session, config):
    console.print("\n[bold blue]━━ PHASE 3: CORTEX (PROJECT GHOST & AST EXTRACTION) ━━[/bold blue]")
    urls = [u['url'] if isinstance(u, dict) else u for u in session.get_crawled_urls()]
    js_targets = list(set([u for u in urls if u.endswith('.js')]))
    
    if not js_targets:
        console.print("WARNING  No JavaScript bundles found. Skipping Cortex.")
        return
        
    console.print(f"INFO     Deploying Neural Extraction against {len(js_targets)} JS bundles...")
    asyncio.run(deploy_cortex(session, js_targets))
    console.print("  + AST Taint Analysis Complete. Extracted Shadow APIs injected into state graph.")
