import yaml
import os
from playwright.sync_api import sync_playwright
from rich.console import Console

console = Console()

class AuthEngine:
    def __init__(self, target):
        self.target = target
        self.config_path = "config/auth.yaml"
        self.profile_dir = "config/chrome_profile"
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
            os.makedirs(self.profile_dir, exist_ok=True)
            with sync_playwright() as p:
                # Launch PERSISTENT Chromium to cache cf_clearance cookies
                context = p.chromium.launch_persistent_context(
                    user_data_dir=self.profile_dir,
                    headless=False, # Keep headed to bypass Canvas anomalies
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                    viewport={"width": 1920, "height": 1080},
                    args=["--disable-blink-features=AutomationControlled", "--disable-infobars"]
                )
                
                # INJECT NATIVE V8 STEALTH ENGINE
                context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    window.chrome = { runtime: {} };
                """)

                page = context.pages[0] if context.pages else context.new_page()

                page.goto(creds['login_url'], wait_until="domcontentloaded", timeout=45000)
                
                console.print("[yellow]INFO     WAF Check: If Cloudflare challenges you, solve it manually in the browser window now. (60s timeout)[/yellow]")
                
                # Wait for the login form to appear, allowing you time to pass Turnstile
                page.wait_for_selector("input[type='email'], input[name*='user'], input[name*='email']", timeout=60000)
                
                console.print("INFO     WAF Cleared. Injecting Cryptographic Identity (Credentials)...")
                page.fill("input[type='email'], input[name*='user'], input[name*='email']", creds['username'])
                page.fill("input[type='password'], input[name*='pass']", creds['password'])
                
                page.click("button[type='submit'], input[type='submit'], button:has-text('Log In'), button:has-text('Sign In')")
                
                page.wait_for_timeout(8000) # Wait for post-login WAFs and redirects

                # Extract the Loot
                cookies = context.cookies()
                for cookie in cookies:
                    self.session_state["cookies"][cookie["name"]] = cookie["value"]
                    if "session" in cookie["name"].lower() or "token" in cookie["name"].lower() or "cf_bm" in cookie["name"].lower():
                        console.print(f"  [+] SESSION HIJACKED: {cookie['name']} = {cookie['value'][:15]}...********")

                local_storage = page.evaluate("() => JSON.stringify(window.localStorage)")
                if "token" in local_storage.lower() or "jwt" in local_storage.lower():
                    console.print("  [+] BEARER TOKEN LOCATED in LocalStorage.")
                    self.session_state["headers"]["Authorization"] = "Bearer [EXTRACTED_FROM_DOM]"

                context.close()
                console.print("[green]INFO     Authenticated State Locked. Passing to Cortex & Fuzzer.[/green]")
                return self.session_state

        except Exception as e:
            console.print(f"  [!] CERBERUS BREACH FAILED: {e}")
            return self.session_state

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        AuthEngine(sys.argv[1]).breach_perimeter()
