import typer
import logging
import yaml
import os
import sys
import subprocess
import time
from rich.console import Console

# Core
from core.state import TargetSession
from core.intelligence import run_intelligence
from core.mesh import mesh

# Modules
from modules.osint import run_osint
from modules.horizontal import run_horizontal
from modules.vertical import run_vertical
from modules.ports import run_ports
from modules.permutations import run_permutations
from modules.probing import run_probing
from modules.spider import run_spider
from modules.cortex import run_cortex
from modules.nuclei_scan import run_nuclei
from modules.fuzzer import run_fuzzer
from modules.oast import run_oast
from modules.notifier import run_notifier
from modules.cloud import run_cloud
from modules.umbrella import run_umbrella
from modules.unmask import run_unmask

app = typer.Typer()
console = Console()
log = logging.getLogger("rich")

def load_config():
    config_path = "config/settings.yaml"
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    return {}

@app.command()
def scan(target: str, mode: str = "standard", resume: bool = typer.Option(False, "--resume"), cookie: str = typer.Option(None, "--cookie"), header: str = typer.Option(None, "--header")):
    KESTREL_LOGO = """[bold cyan]
      _______  _______  _______  _______  ______   _______  _       
     | \\    /|(  ____ \\(  ____ \\__   __/(  __  \\ (  ____ \\( \\      
     |  \\  / /| (    \\/| (    \\/   ) (   | (  \\  )| (    \\/| (      
     |  (_/ / | (__    | (_____    | |   | |   ) || (__    | |      
     |   _ (  |  __)   (_____  )   | |   | |   | ||  __)   | |      
     |  ( \\ \\ | (            ) |   | |   | |   ) || (      | |      
     |  /  \\ \\| (____/\\/\\____) |   | |   | (__/  )| (____/\\| (____/\\
     |_/    \\/(_______/\\_______)   )_(   (______/ (_______/(_______/
    [/bold cyan][bold white]
                      > THE TARGETED EASM ARCHITECTURE // v3.0
                      > ENGAGE PASSIVELY. STRIKE DETERMINISTICALLY.
    [/bold white]"""
    console.print(KESTREL_LOGO)
    console.print("\n[bold]SYSTEM INTEGRITY EVALUATOR // v2.2[/bold]\n")
    config = load_config()
    session = TargetSession(target, mode)
    
    # Auth-Injection Matrix
    session.auth_cookies = dict(item.split("=", 1) for item in cookie.split("; ") if "=" in item) if cookie else {}
    session.auth_headers = {header.split(":", 1)[0].strip(): header.split(":", 1)[1].strip()} if header and ":" in header else {}
    if session.auth_cookies or session.auth_headers:
        console.print("[bold magenta]  [*] STATEFUL AUTHENTICATION MATRIX ARMED.[/bold magenta]")

    # --- ARM THE PROXY MESH ---
    console.print("INFO     Initializing Tactical Routing Protocol...")
    mesh.arm_mesh("config/proxies.txt")

    def safe_run(name, func):
        try:
            func(session, config)
        except Exception as e:
            log.error(f"{name} failed: {e}")

    try:
        # --- LOCAL OAST DAEMON INITIALIZATION ---
        console.print("INFO     Initializing Local Interactsh Daemon...")
        if os.path.exists(".oast_logs.json"): os.remove(".oast_logs.json")
        if os.path.exists(".oast_payload.txt"): os.remove(".oast_payload.txt")

        # Spawn Daemon (FIX: Merge stderr into stdout to catch Go's startup logs)
        daemon = subprocess.Popen(
            [(os.path.expanduser("~/go/bin/interactsh-client") if os.path.exists(os.path.expanduser("~/go/bin/interactsh-client")) else "interactsh-client"), "-json", "-o", ".oast_logs.json"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True
        )

        # Non-blocking read with a strict 15-second timeout
        payload = None
        start_time = time.time()

        # We must use readline loop to avoid freezing
        import os as _os
        _os.set_blocking(daemon.stdout.fileno(), False)
        
        while time.time() - start_time < 15:
            line = daemon.stdout.readline()
            if line:
                if "interact.sh" in line or "oast." in line:
                    # Extract the domain from the log (e.g., "[INF] Payload: xxxxx.oast.fun")
                    words = line.strip().split()
                    for word in words:
                        if "interact.sh" in word or "oast." in word:
                            payload = word.strip('[]"')
                            break
                    if payload:
                        break
            time.sleep(0.1)

        if payload:
            with open(".oast_payload.txt", "w") as f:
                f.write(payload)
            console.print(f"INFO     Daemon Online. Assigned Receptor: {payload}")
        else:
            console.print("[yellow]WARNING  Interactsh server timeout. Falling back to static receptor.[/yellow]")
            with open(".oast_payload.txt", "w") as f:
                f.write("fallback.requestrepo.com")

        # --- THE DIRECTED ACYCLIC GRAPH (DAG) ---
        if not resume:
            # Stage 1: Recon & Expansion
            safe_run("OSINT", run_osint)           # Phase 1: Native SSL + API Circuit Breaker
            safe_run("HORIZONTAL", run_horizontal) # Phase 1.1: Origin / CDN Shield
            safe_run("UMBRELLA", run_umbrella)     # Phase 1.2: Corporate SSL Pivot
            safe_run("VERTICAL", run_vertical)     # Phase 1.3: Async DNS Bruteforce
            safe_run("CLOUD", run_cloud)           # Phase 1.4: Cloud Storage Sniper
            safe_run("PORTS", run_ports)           # Phase 1.5: Shielded Port Scan
            safe_run("UNMASK", run_unmask)         # Phase 1.6: Origin Unmasking via Shodan
            safe_run("PERMUTATIONS", run_permutations) # Phase 1.8: Subdomain Mutations
            # Stage 2: Application Mapping
            safe_run("PROBING", run_probing)       # Phase 2: Favicon/Tech Profiling
            safe_run("SPIDER", run_spider)         # Phase 2.2: Skeleton Hash Spider
            safe_run("CORTEX", run_cortex)         # Phase 3: Project Ghost & AST

        # Stage 3: Exploitation (Always runs, even on --resume)
        safe_run("NUCLEI", run_nuclei)             # Phase 4: Tech-Stack Targeted CVEs
        safe_run("FUZZER", run_fuzzer)             # Phase 5: Semantic Parameter Routing
        safe_run("OAST", run_oast)                 # Phase 8: Blind Poller (MUST BE AFTER FUZZER)

        # Stage 4: Intelligence & Delivery
        safe_run("INTELLIGENCE", run_intelligence) # Phase 7: Blast Radius Graph
        def phase6_notifier(session, config):
            db_path = f"data/sessions/{target.replace('.', '_')}.db"
            run_notifier(session.target, db_path)
        safe_run("NOTIFIER", phase6_notifier)         # Phase 6: Telegram Delta

    except KeyboardInterrupt:
        # THE GRACEFUL SHUTDOWN TRAP
        console.print("\n[bold red]⚠️ SIGINT RECEIVED: INITIATING GRACEFUL SHUTDOWN...[/bold red]")
        console.print("INFO     Flushing Write-Ahead Logs and securing State Graph...")
        if hasattr(session, 'close'):
            session.close()
        console.print("[green]  + State Graph secured. Terminating pipeline.[/green]")
        sys.exit(130) 
        
    finally:
        # Ensure database closes and background daemon is killed
        if hasattr(session, 'close'):
            session.close()
        if 'daemon' in locals() and daemon.poll() is None:
            daemon.terminate()
            if os.path.exists(".oast_payload.txt"): os.remove(".oast_payload.txt")

if __name__ == "__main__":
    app()
