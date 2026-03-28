import json
import subprocess
import logging
import os
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

def run_probing(session, config):
    console.print("[bold blue]━━ PHASE 2: ACTIVE PROBING & TECH PROFILING ━━[/bold blue]")
    
    targets = list(set(session.subdomains))
    if not targets:
        log.warning("No targets available for active probing.")
        return

    console.print(f"INFO     Probing {len(targets)} targets (Stealth Governor & Debug Logging Active)...")
    
    target_file = "data/temp_httpx_in.txt"
    out_file = "data/temp_httpx_out.json"

    with open(target_file, "w") as f:
        f.write("\n".join(targets) + "\n")

    # THE UPGRADE: Removed invalid '-tech' flag. Removed '-silent' to unblind error logging. 
    # Spelled out '-follow-redirects' for cross-version compatibility.
    cmd = [
        "httpx",
        "-l", target_file,
        "-sc", "-title", "-server", "-td",
        "-t", "10",
        "-rl", "20",
        "-follow-redirects",
        "-random-agent",
        "-json",
        "-o", out_file
    ]

    live_hosts = []
    
    try:
        # We capture stdout and stderr natively, so we don't need -silent hiding our bugs
        result = subprocess.run(cmd, capture_output=True, text=True, )
        
        if result.returncode != 0 and not os.path.exists(out_file):
            log.error(f"HTTPX Crash Report: {result.stderr.strip()}")
            
        if os.path.exists(out_file):
            with open(out_file, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        url = data.get("url")
                        status = data.get("status_code", 0)
                        
                        # Handle varied JSON keys depending on httpx version
                        tech = data.get("technologies", data.get("tech", [])) 
                        server = data.get("webserver", "Unknown")
                        title = data.get("title", "No Title")
                        
                        live_hosts.append({
                            "url": url, "status": status, "tech": tech,
                            "server": server, "title": title
                        })
                        
                        tech_str = ", ".join(tech[:3]) + ("..." if len(tech) > 3 else "")
                        tech_str = tech_str or "Undetected"
                        status_color = "green" if status in [200, 301, 302] else "yellow" if status in [401, 403] else "red"
                        console.print(f"[{status_color}]  + {url} [/{status_color}][dim] [{status}] | Tech: {tech_str}[/dim]")
                        
                    except json.JSONDecodeError: continue
    except Exception as e:
        log.error(f"HTTPX execution failed: {e}")
    finally:
        if os.path.exists(target_file): os.remove(target_file)
        if os.path.exists(out_file): os.remove(out_file)

    session.live_hosts.extend(live_hosts)
    console.print(f"INFO     Active Live Hosts Profiled: {len(live_hosts)}")
