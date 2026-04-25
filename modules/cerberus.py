import yaml
import os
from playwright.sync_api import sync_playwright
from rich.console import Console

console = Console()

class AuthEngine:
    def __init__(self, target):
        self.target = target
        self.config_path = "config/auth.yaml"
        self.session_state = {"headers": {}, "cookies": {}}

    def load_credentials(self):
        if not os.path.exists(self.config_path):
            return None
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('targets', {}).get(self.target)

    def breach_perimeter(self):
        creds = self.load_credentials()
        if not creds or not creds.get('username') or not creds.get('password'):
            console.print("  [*] CERBERUS: No valid credentials found. Operating unauthenticated.")
            return self.session_state

        console.print(f"\n[bold red]━━ PROJECT CERBERUS: BREACHING AUTHENTICATED PERIMETER ━━[/bold red]")
        console.print(f"INFO     Target Lock: {creds['login_url']}")
        
        try:
            with sync_playwright() as p:
                # Launch stealthy Chromium
                browser = p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
                context = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                page = context.new_page()

                # Navigate and wait for network idle to ensure JS loads
                page.goto(creds['login_url'], wait_until="networkidle", timeout=15000)
                
                # Heuristic Form Filling (Looks for common login field names)
                console.print("INFO     Injecting Cryptographic Identity (Credentials)...")
                page.fill("input[type='email'], input[name*='user'], input[name*='email']", creds['username'])
                page.fill("input[type='password'], input[name*='pass']", creds['password'])
                
                # Smash the login button
                page.click("button[type='submit'], input[type='submit'], button:has-text('Log In'), button:has-text('Sign In')")
                
                # Wait for the navigation/redirect post-login
                page.wait_for_load_state("networkidle", timeout=10000)

                # Extract the Loot (Cookies and LocalStorage JWTs)
                cookies = context.cookies()
                for cookie in cookies:
                    self.session_state["cookies"][cookie["name"]] = cookie["value"]
                    if "session" in cookie["name"].lower() or "token" in cookie["name"].lower():
                        console.print(f"  [+] SESSION HIJACKED: {cookie['name']} = {cookie['value'][:15]}...********")

                # Extract LocalStorage (often contains Bearer tokens for SPAs)
                local_storage = page.evaluate("() => JSON.stringify(window.localStorage)")
                if "token" in local_storage.lower() or "jwt" in local_storage.lower():
                    console.print("  [+] BEARER TOKEN LOCATED in LocalStorage.")
                    self.session_state["headers"]["Authorization"] = "Bearer [EXTRACTED_FROM_DOM]"

                browser.close()
                console.print("[green]INFO     Authenticated State Locked. Passing to Cortex & Fuzzer.[/green]")
                return self.session_state

        except Exception as e:
            console.print(f"  [!] CERBERUS BREACH FAILED: {e}")
            return self.session_state

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        AuthEngine(sys.argv[1]).breach_perimeter()
