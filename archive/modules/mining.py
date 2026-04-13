import requests
import logging
from urllib.parse import urlencode
from rich.console import Console
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
log = logging.getLogger("rich")

CANARY = "arbiter_echo_1337"
PAYLOAD = f"{CANARY}<>\"'"
COMMON_PARAMS = ["q", "s", "search", "id", "lang", "page", "ref", "url", "redirect", "keyword"]

def run_mining(session, config):
    console.print("[bold blue]━━ PHASE 4.5: PARAMETER MINING (REFLECTION CARTOGRAPHY) ━━[/bold blue]")
    
    # Combine base hosts AND Spider-discovered URLs
    targets = [host.get('url') for host in session.live_hosts if host.get('url')]
    if hasattr(session, 'crawled_urls') and session.crawled_urls:
        targets.extend(session.crawled_urls)
        
    targets = list(set(targets)) # Deduplicate
    
    if not targets:
        log.warning("No targets available for parameter mining. Skipping.")
        return

    console.print(f"INFO     Mining and testing reflection on {len(targets)} endpoints...")
    
    findings = 0
    param_string = urlencode({p: PAYLOAD for p in COMMON_PARAMS})
    
    for url in targets:
        # Smart separator logic (if URL already has a '?' like search.php?cat=1)
        separator = "&" if "?" in url else "?"
        test_url = f"{url}{separator}{param_string}"
        
        try:
            r = requests.get(test_url, timeout=3, verify=False)
            
            if CANARY in r.text and "<>" in r.text:
                if PAYLOAD in r.text:
                    console.print(f"[bold orange1]  + UNFILTERED REFLECTION DETECTED: {url}[/bold orange1]")
                    session.vulnerabilities.append({
                        "name": "Parameter Reflection (Pre-XSS)",
                        "severity": "MEDIUM",
                        "url": url,
                        "info": "Unsanitized reflection of dangerous characters (<>\") detected."
                    })
                    findings += 1
        except Exception:
            pass

    if findings == 0:
        console.print("INFO     No obvious unfiltered parameters found in current URL set.")
    else:
        console.print(f"INFO     Reflection Cartography Complete. Found {findings} Pre-XSS vectors.")
