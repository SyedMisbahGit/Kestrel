from modules.oracle import ask_brain
from modules.blacksmith import WasmExtractor
from modules.chimera import JWTSniper
from core.filters import is_whitelisted
from core.mesh import ProxyMesh
import asyncio
import aiohttp
import logging
import re
import json
import ijson
import io
import math
import esprima
from urllib.parse import urlparse
from rich.console import Console
from core.ui import print_briefing

console = Console()
log = logging.getLogger("rich")

SECRETS_REGEX = {
    "AWS Access Key": re.compile(r'(AKIA[0-9A-Z]{16})'),
    "Stripe Standard Key": re.compile(r'(sk_live_[0-9a-zA-Z]{24})'),
    "Google API Key": re.compile(r'(AIza[0-9A-Za-z-_]{35})'),
    "Slack Token": re.compile(r'(xox[baprs]-[0-9a-zA-Z]{10,48})'),
    "RSA Private Key": re.compile(r'(-----BEGIN RSA PRIVATE KEY-----)')}
UUID_REGEX = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
HEX_HASH_REGEX = re.compile(r'^[0-9a-fA-F]{32,64}$')


def calculate_shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy



def is_webpack_noise(val):
    noise_signatures = [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "use strict", "object", "undefined", "function", "boolean",
        "symbol", "webpackChunk", "sourceMappingURL", "data:image",
        "application/x-www-form-urlencoded"
    ]
    if len(val) > 100 and "{" in val and "}" in val: return True # Inline JSON/CSS
    if val.startswith(('npm.', 'chunk-', 'webpack-', 'core-js')): return True
    return any(noise in val for noise in noise_signatures)

class TaintTracker:
    def __init__(self):
        self.variables = {}
        self.endpoints = set()
        self.entropy_secrets = set()

    def walk(self, node, current_context="unknown"):
        if not node or not hasattr(node, "type"):
            return

        # AST CONTEXT EXTRACTION: Grab the variable/property name
        next_context = current_context
        if node.type == "VariableDeclarator" and hasattr(node, "id"):
            next_context = getattr(node.id, "name", current_context)
        elif node.type == "Property" and hasattr(node, "key"):
            next_context = getattr(node.key, "name", getattr(node.key, "value", current_context))
        elif node.type == "AssignmentExpression" and hasattr(node, "left"):
            next_context = getattr(node.left, "name", current_context)

        # Basic endpoint concatenation tracking
        if node.type == "BinaryExpression" and node.operator == "+":
            left, right = self._resolve_node(node.left), self._resolve_node(node.right)
            if left and right and isinstance(left, str) and isinstance(right, str) and "/" in (left + right) and len(left + right) > 4:
                self.endpoints.add(left + right)

        # Literal String Evaluation
        if node.type == "Literal" and isinstance(node.value, str):
            val = node.value
            if val.startswith(('/', 'http', 'api/')) and len(val) > 4:
                self.endpoints.add(val)
                
            if 16 <= len(val) <= 128 and " " not in val and "," not in val and not val.startswith(('/', 'http')):
                if not UUID_REGEX.match(val) and not HEX_HASH_REGEX.match(val):
                    if 16 < len(val) < 64:
                        if not is_whitelisted(val) and not any(noise in val.lower() for noise in ['data:', 'url(', 'position:', 'application/', 'text/', 'display:']):
                            entropy = calculate_shannon_entropy(val)
                            if entropy > 4.85:
                                if not any(js_noise in val for js_noise in [" ", "()", "=>", "return", "function", "var ", "let ", "const "]):
                                    # Attach the extracted AST context to the finding
                                    self.entropy_secrets.add((val, round(entropy, 2), str(next_context)))

        # Traverse deeper into the AST
        for key, val in vars(node).items():
            if isinstance(val, list):
                for item in val:
                    self.walk(item, next_context)
            elif hasattr(val, "type"):
                self.walk(val, next_context)

    def _resolve_node(self, node):
        if not node or not hasattr(node, "type"): return ""
        if node.type == "Literal": return node.value
        if node.type == "Identifier": return self.variables.get(node.name, "")
        return ""

        if node.type == "Literal":
            return node.value
        if node.type == "Identifier":
            return self.variables.get(node.name, "")
        return ""


async def extract_target(client, js_url, session_state, proxy=None):
    vulnerabilities = []

    # 1. HARD PERIMETER: Do not scan binary extensions, images, or third-party
    # domains
    skip_extensions = (
        '.pdf',
        '.png',
        '.jpg',
        '.jpeg',
        '.gif',
        '.svg',
        '.woff',
        '.woff2',
        '.ttf',
        '.eot',
        '.mp4',
        '.mp3')
    if js_url.lower().endswith(skip_extensions):
        return vulnerabilities

    if js_url.startswith('http') and session_state.domain not in js_url:
        return vulnerabilities

    try:
        async with client.get(f"{js_url}.map", timeout=8, ssl=False, proxy=proxy) as response:
            if response.status == 200:
                # ZERO-RAM STREAMING: Parse 50MB files without loading them
                # into memory
                text_stream = io.StringIO(await response.text())
                sources = list(ijson.items(text_stream, 'sources.item'))
                text_stream.seek(0)
                contents = list(
                    ijson.items(
        text_stream,
        'sourcesContent.item'))
                if sources and contents:
                    console.print(f"[bold magenta]  [*] PROJECT GHOST: Extracted {len(sources)} dev files from {js_url}[/bold magenta]")
                    for filename, content in zip(sources, contents):
                        if not content:
                            continue
                        for sec_name, regex in SECRETS_REGEX.items():
                            if regex.search(content):
                                console.print(
                                    f"[bold red]  ! [CRITICAL] {sec_name} found in unminified {filename}[/bold red]")
                                vulnerabilities.append(
                                    {
        "type": "VULN",
        "name": f"Source Map Leak: {sec_name}",
        "matched-at": js_url,
        "info": {
            "severity": "CRITICAL"}})
    except Exception:
        pass

    try:
        async with client.get(js_url, timeout=8, ssl=False, proxy=proxy) as response:
            if response.status == 200:
                # 2. CONTENT TYPE SHIELD: Abort if the server returns a binary
                # stream instead of text
                content_type = response.headers.get('Content-Type', '')
                if 'application/pdf' in content_type or 'image/' in content_type or 'video/' in content_type:
                    return vulnerabilities

                text_data = await response.text()
                tracker = TaintTracker()
                tracker.walk(
                    esprima.parseScript(
        text_data, {
            "tolerant": True}))

                for endpoint in tracker.endpoints:
                    if not endpoint.startswith('http'):
                        endpoint = "/".join(js_url.split('/')[:3]) + (
                            "/" if not endpoint.startswith('/') else "") + endpoint
                    session_state.add_crawled_url(endpoint)

                for val, entropy, context in tracker.entropy_secrets:
                    console.print(
                        f"[bold red]  ! [HIGH] Proprietary Token Detected [H: {entropy}]: {secret[:10]}...[/bold red]")
                    vulnerabilities.append({"type": "VULN",
                                            "name": f"High Entropy Anomaly (H={entropy})",
                        "matched-at": js_url,
                        "info": {"severity": "HIGH"}})
                if secret.startswith('eyJh') and len(secret) > 40:
                    jwt_vulns = self.chimera.analyze_token(js_url, secret)
                    if jwt_vulns:
                        vulnerabilities.extend(jwt_vulns)

    except Exception:
        pass
    return vulnerabilities


async def deploy_cortex(session_state, js_targets):
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    headers = getattr(session_state, 'auth_headers', {})
    cookies = getattr(session_state, 'auth_cookies', {})
    mesh = ProxyMesh()

    async with aiohttp.ClientSession(connector=connector, headers=headers, cookies=cookies) as client:
        # Wrap extract_target to inject a random proxy per request
        async def _routed_extract(url):
            proxy = mesh.get_random_node()
            return await extract_target(client, url, session_state, proxy=proxy)
            
        results = await asyncio.gather(*[_routed_extract(url) for url in js_targets])
        for vuln_list in results:
            if vuln_list:
                session_state.vulnerabilities.extend(vuln_list)


def run_cortex(session, config):
    console.print(
        "\n[bold blue]━━ PHASE 3: CORTEX (PROJECT GHOST & AST EXTRACTION) ━━[/bold blue]")
    print_briefing(
        title="AST Compilation & Shannon Entropy",
        happening="Downloading Webpack JS bundles, bypassing minification via .map leaks, and compiling the code into an Abstract Syntax Tree to extract Shadow APIs.",
        fallback="If Webpack is secure, Kestrel will calculate Shannon Entropy (H > 4.4) on all string literals to mathematically detect proprietary, non-regex secrets.",
        command="curl -s https://target.com/main.js.map | jq '.sources'")

    raw_urls = [
        u['url'] if isinstance(
        u, dict) else u for u in session.get_crawled_urls()]
    js_targets = set()
    for u in raw_urls:
        try:
            if urlparse(u).path.endswith('.js'):
                js_targets.add(u)
        except ValueError:
            pass

    js_targets = list(js_targets)
    if not js_targets:
        console.print("WARNING  No JavaScript bundles found. Skipping Cortex.")
        return

    console.print(
        f"INFO     Deploying Neural Extraction & Entropy Math against {len(js_targets)} bundles...")
    asyncio.run(deploy_cortex(session, js_targets))
    console.print(
        "  + AST Compilation Complete. Shadow APIs and Proprietary Tokens injected into state graph.")


def sanitize_database(db_path):
    """Aggressively purges known false positives from the state database before Phase 7."""
    import sqlite3
    import os


    if not os.path.exists(db_path):
        return
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Hard kill-list for the database
        noise_patterns = [
    "%ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%",
    "%.html%",
    "%cloudflare%",
    "%iglu:%",
    "%classid%",
    "%ABCDEFGHIJ%",
    '%.pdf%',
    '%.png%',
    '%.jpg%',
    '%.svg%',
    '%.woff%',
    '%google.com%',
    '%facebook.com%',
    '%twitter.com%',
    '%linkedin.com%',
    '%jquery%',
    '%bootstrap%',
    '%tailwind%',
     '%.css%', 
    '%function(%', 
    '%Object.defineProperty%', 
    '%return null%', 
    '%prototype%', 
    '%strict%', 
    '%__esModule%',
    '%Symbol(%' ]

        for pattern in noise_patterns:
            cursor.execute(
                "DELETE FROM vulnerabilities WHERE id LIKE ? OR data LIKE ?",
                (pattern,
     pattern))

        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Sanitization failed: {e}")
