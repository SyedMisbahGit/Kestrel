import requests
import socket
from rich.console import Console

console = Console()

class OriginSniper:
    def __init__(self, target):
        self.target = target
        self.origin_ips = set()
        self.headers = {"User-Agent": "Kestrel-Grid-Engine"}

    def hunt_crt_sh(self):
        """Hunts for Origin IPs leaked in SSL Certificate Transparency logs."""
        try:
            url = f"https://crt.sh/?q={self.target}&output=json"
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '').split('\n')[0]
                    if '*' not in name and name != self.target:
                        try:
                            ip = socket.gethostbyname(name)
                            # Basic filter for Cloudflare/Fastly IPs
                            if not ip.startswith(('104.', '172.', '188.')): 
                                self.origin_ips.add(ip)
                        except:
                            pass
        except:
            pass

    def uncloak(self):
        console.print(f"INFO     Deploying Project Uncloak against {self.target} CDN Shield...")
        self.hunt_crt_sh()
        
        if self.origin_ips:
            console.print(f"  [+] UNCLOAKED: Discovered {len(self.origin_ips)} potential Origin IPs bypassing CDN.")
            for ip in self.origin_ips:
                console.print(f"      -> {ip}")
            return list(self.origin_ips)
        else:
            console.print("  [-] Shield holds. Origin remains hidden.")
            return []

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        OriginSniper(sys.argv[1]).uncloak()
