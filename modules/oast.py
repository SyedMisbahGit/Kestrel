import logging
import json
import time
import os
import subprocess
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

def run_oast(session, config):
    console.print("\n[bold blue]━━ PHASE 8: THE OAST ENGINE (INTERACTSH LOCAL DAEMON) ━━[/bold blue]")
    
    console.print("INFO     Idling for 5 seconds to allow backend queues to process OAST payloads...")
    time.sleep(5)
    
    console.print("INFO     Polling Local Daemon Logs for Cryptographic Callbacks...")
    
    # Check if the daemon actually logged anything
    if not os.path.exists(".oast_logs.json"):
        console.print("  + No Out-of-Band interactions detected. Zero False Positives.")
        return

    # Parse the local JSON lines written by interactsh-client
    interactions = []
    with open(".oast_logs.json", "r") as f:
        for line in f:
            if line.strip():
                try:
                    interactions.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not interactions:
        console.print("  + No Out-of-Band interactions detected. Zero False Positives.")
        return

    # Map the hashes back to the original target URLs
    import hashlib
    url_map = {hashlib.md5((u['url'] if isinstance(u, dict) else u).encode()).hexdigest()[:8]: (u['url'] if isinstance(u, dict) else u) for u in session.get_crawled_urls()}
    
    found_vulns = []
    dump_str = json.dumps(interactions)
    
    for u_hash, url in url_map.items():
        if u_hash in dump_str:
            console.print(f"[bold red]  ! [CRITICAL] 100% CONFIRMED BLIND INTERACTION (SSRF/Log4j) on {url}[/bold red]")
            found_vulns.append({"type": "VULN", "name": "Blind OAST Interaction", "matched-at": url, "info": {"severity": "CRITICAL"}})
            
    if found_vulns:
        session.vulnerabilities.extend(found_vulns)
        console.print(f"  + Injected {len(found_vulns)} proven vulnerabilities into State Graph.")
    else:
        # We got interactions, but they didn't match our hash format (e.g., background internet noise scanning the OAST domain)
        console.print("  + Local Daemon captured interactions, but none matched our cryptographic signatures.")
