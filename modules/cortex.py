import logging
import asyncio
import aiohttp
from rich.console import Console
try:
    from pyjsparser import parse
except ImportError:
    parse = None

log = logging.getLogger("rich")
console = Console()

class ASTTaintAnalyzer:
    def __init__(self):
        self.variables = {}
        self.endpoints = set()

    def traverse(self, node):
        if not isinstance(node, dict): return
        
        # 1. State Tracking: Variable Declarations
        if node.get('type') == 'VariableDeclarator':
            id_node = node.get('id')
            init_node = node.get('init')
            if id_node and init_node and id_node.get('type') == 'Identifier':
                var_name = id_node.get('name')
                if init_node.get('type') == 'Literal':
                    self.variables[var_name] = init_node.get('value')
        
        # 2. Sink Detection: Finding the API Calls (fetch, axios, http)
        if node.get('type') == 'CallExpression':
            callee = node.get('callee')
            if self._is_api_sink(callee):
                args = node.get('arguments', [])
                if args:
                    # Weaponized Taint Resolution
                    endpoint = self._resolve_argument(args[0])
                    if endpoint and isinstance(endpoint, str) and (endpoint.startswith('/') or endpoint.startswith('http')):
                        self.endpoints.add(endpoint)

        # 3. Recursive Graph Traversal
        for key, value in node.items():
            if isinstance(value, dict):
                self.traverse(value)
            elif isinstance(value, list):
                for item in value:
                    self.traverse(item)

    def _is_api_sink(self, callee):
        """Heuristic identification of network execution sinks."""
        if not callee: return False
        if callee.get('type') == 'Identifier' and callee.get('name') in ['fetch', 'request']:
            return True
        if callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            if obj.get('name') in ['axios', '$http', 'http'] and prop.get('name') in ['get', 'post', 'put', 'delete', 'request']:
                return True
        return False

    def _resolve_argument(self, arg):
        """Recursively trace variables and concatenations backward through the AST."""
        if not arg: return ""
        # Base case: Literal String
        if arg.get('type') == 'Literal':
            return str(arg.get('value'))
        # Taint Resolution: Variable Lookup
        if arg.get('type') == 'Identifier':
            return str(self.variables.get(arg.get('name'), ''))
        # Concatenation: Binary Expression (e.g., base_url + "/users")
        if arg.get('type') == 'BinaryExpression' and arg.get('operator') == '+':
            left = self._resolve_argument(arg.get('left'))
            right = self._resolve_argument(arg.get('right'))
            return str(left) + str(right)
        return ""

async def analyze_js_file(session_client, url, session):
    try:
        async with session_client.get(url, timeout=10) as response:
            if response.status == 200:
                js_code = await response.text()
                if parse:
                    try:
                        # Compile JS into logical tree
                        ast_tree = parse(js_code)
                        analyzer = ASTTaintAnalyzer()
                        analyzer.traverse(ast_tree)
                        
                        # Inject extracted Shadow APIs back into the Omni-Adapter
                        for ep in analyzer.endpoints:
                            full_url = f"https://{url.split('/')[2]}{ep}" if ep.startswith('/') else ep
                            session.add_crawled_url(full_url)
                    except Exception:
                        pass # Ignore highly obfuscated syntax errors
    except Exception:
        pass

async def run_cortex_async(session, js_urls):
    async with aiohttp.ClientSession() as client:
        tasks = [analyze_js_file(client, url, session) for url in js_urls]
        await asyncio.gather(*tasks)

def run_cortex(session, config):
    console.print("\n[bold blue]━━ PHASE 3: CORTEX (AST NEURAL EXTRACTION) ━━[/bold blue]")
    if not parse:
        log.warning("pyjsparser not installed. Run: pip install pyjsparser")
        return

    # Extract clean strings safely from the Omni-Adapter database
    js_urls = []
    for u in session.get_crawled_urls():
        if isinstance(u, dict) and u.get('url', '').endswith('.js'):
            js_urls.append(u['url'])
        elif isinstance(u, str) and u.endswith('.js'):
            js_urls.append(u)
    
    if not js_urls:
        log.warning("No JavaScript bundles found. Skipping Cortex.")
        return

    console.print(f"INFO     Compiling {len(js_urls)} JS bundles into Abstract Syntax Trees...")
    asyncio.run(run_cortex_async(session, js_urls))
    console.print("  + AST Taint Analysis Complete. Extracted Shadow APIs injected into state graph.")
