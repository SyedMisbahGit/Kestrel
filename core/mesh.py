import random
import os
from rich.console import Console

console = Console()

class ProxyMesh:
    def __init__(self, proxy_file="config/proxies.txt"):
        self.proxies = []
        if os.path.exists(proxy_file):
            with open(proxy_file, 'r') as f:
                # Basic cleanup of proxy lists
                self.proxies = [line.strip() for line in f if line.strip() and ':' in line]
        
        if self.proxies:
            console.print(f"[green]  [+] PROJECT PHANTOM: Mesh Network Online. Loaded {len(self.proxies)} routing nodes.[/green]")
        else:
            console.print("[yellow]  [*] PROJECT PHANTOM: No proxies loaded. Operating in Direct/Transparent mode.[/yellow]")

    def get_random_node(self):
        """Returns a formatted proxy string, or None if mesh is offline."""
        if not self.proxies:
            return None
            
        proxy = random.choice(self.proxies)
        if not proxy.startswith('http'):
            proxy = f"http://{proxy}"
        return proxy

# Global instance for arbiter.py backwards compatibility
mesh = ProxyMesh()
