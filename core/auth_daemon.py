import threading
import time
import requests
import logging
import urllib3
from rich.console import Console
from modules.cerberus import AuthEngine

# Suppress insecure request warnings for background pings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
log = logging.getLogger("rich")

class KeepAliveDaemon(threading.Thread):
    def __init__(self, session, refresh_interval=300):
        super().__init__(daemon=True)
        self.session = session
        self.refresh_interval = refresh_interval
        self.running = True
        self.target_url = f"https://{self.session.target}"
        self.is_authenticated = bool(self.session.auth_cookies or self.session.auth_headers)

    def run(self):
        if not self.is_authenticated:
            return # Don't run the daemon if we are operating unauthenticated

        console.print("[dim]  * Auth Daemon spawned in background thread (Monitoring JWT/Cookie health).[/dim]")
        
        while self.running:
            # Sleep in small chunks so we can intercept a shutdown signal quickly
            for _ in range(self.refresh_interval):
                if not self.running: return
                time.sleep(1)
            
            # 1. Health Check
            try:
                r = requests.get(
                    self.target_url, 
                    headers=self.session.auth_headers, 
                    cookies=self.session.auth_cookies, 
                    timeout=10, 
                    verify=False,
                    allow_redirects=False
                )
                
                # 2. Token Degradation Intercept
                if r.status_code in [401, 403, 302]:
                    console.print("\n[bold yellow]⚠️ AUTH DAEMON: Session degradation detected. Initiating auto-refresh...[/bold yellow]")
                    
                    auth_data = AuthEngine(self.session.target).breach_perimeter()
                    
                    if auth_data and (auth_data.get("headers") or auth_data.get("cookies")):
                        self.session.auth_headers.update(auth_data.get("headers", {}))
                        self.session.auth_cookies.update(auth_data.get("cookies", {}))
                        console.print("[bold green]  + AUTH DAEMON: Session resurrected. New tokens injected into global state matrix.[/bold green]\n")
                    else:
                        console.print("[bold red]  ! AUTH DAEMON: Auto-refresh failed. Engine is operating degraded.[/bold red]\n")
            
            except Exception:
                pass # Fail open if target drops connection

    def stop(self):
        self.running = False
