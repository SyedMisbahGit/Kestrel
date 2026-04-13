import asyncio
import aiohttp
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

class ProxyMesh:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ProxyMesh, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.nodes = []
        self.index = 0
        self.lock = asyncio.Lock()
        self._initialized = True

    def arm_mesh(self, filepath="config/proxies.txt"):
        """Loads and parses the exit nodes into memory."""
        try:
            with open(filepath, 'r') as f:
                raw_nodes = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            for node in raw_nodes:
                if '@' in node:
                    # Handle Authenticated Proxies (user:pass@ip:port)
                    creds, address = node.split('@')
                    user, pwd = creds.split(':')
                    self.nodes.append({
                        "url": f"http://{address}",
                        "auth": aiohttp.BasicAuth(user, pwd)
                    })
                else:
                    # Handle Open Proxies (ip:port)
                    self.nodes.append({
                        "url": f"http://{node}",
                        "auth": None
                    })
                    
            if self.nodes:
                console.print(f"[bold green]  + PROXY MESH ONLINE: {len(self.nodes)} Geographic Exit Nodes Armed.[/bold green]")
            else:
                console.print("[dim]  * Proxy list empty. Mesh operating in Transparent Mode (Direct IP).[/dim]")
        except FileNotFoundError:
            console.print("[dim]  * config/proxies.txt not found. Mesh operating in Transparent Mode.[/dim]")

    async def get_node(self):
        """Asynchronously vends the next proxy in the Round-Robin sequence."""
        if not self.nodes:
            return None, None
            
        async with self.lock:
            node = self.nodes[self.index]
            self.index = (self.index + 1) % len(self.nodes)
            return node["url"], node["auth"]

# Global Singleton Instance
mesh = ProxyMesh()
