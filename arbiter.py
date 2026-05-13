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
from modules.uncloak import OriginSniper
from modules.cerberus import AuthEngine

class SessionState:
    def __init__(self):
        self.auth_headers = {}
        self.auth_cookies = {}

from core.parser import parse_target

# Modules
from modules.osint import run_osint
from modules.horizontal import run_horizontal
from modules.vertical import run_vertical
from modules.ports import run_ports
from modules.permutations import run_permutations
from modules.scope_guard import run_scope_guard, sanitize_state_graph
from modules.probing import run_probing
from modules.spider import run_spider
from modules.cortex import run_cortex
from modules.graphx import GraphQLSniper
from modules.nuclei_scan import run_nuclei
from modules.cve_sniper import run_cve_sniper
from modules.fuzzer import run_fuzzer
from modules.oast import run_oast
from modules.notifier import run_notifier
from modules.cloud import run_cloud
from modules.umbrella import run_umbrella
from modules.unmask import run_unmask
from modules.hydra_strike import run_hydra

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

    sanitized = parse_target(target)
    if not sanitized:
        console.print("[bold red]⚠️ FATAL: Invalid Target Format. Halting.[/bold red]")
        sys.exit(1)

    target = sanitized["host"]

    session.auth_cookies = dict(item.split("=", 1) for item in cookie.split("; ") if "=" in item) if cookie else {}
    session.auth_headers = {header.split(":", 1)[0].strip(): header.split(":", 1)[1].strip()} if header and ":" in header else {}
    if session.auth_cookies or session.auth_headers:
        console.print("[bold magenta]  [*] STATEFUL AUTHENTICATION MATRIX ARMED.[/bold magenta]")

    console.print("INFO     Initializing Tactical Routing Protocol...")
    mesh.arm_mesh("config/proxies.txt")

    def safe_run(name, func):
        try:
            func(session, config)
        except Exception as e:
            log.error(f"{name} failed: {e}")

    try:
        console.print("INFO     Initializing Local Interactsh Daemon...")
        if os.path.exists(".oast_logs.json"): os.remove(".oast_logs.json")
        if os.path.exists(".oast_payload.txt"): os.remove(".oast_payload.txt")

        daemon = subprocess.Popen(
            [(os.path.expanduser("~/go/bin/interactsh-client") if os.path.exists(os.path.expanduser("~/go/bin/interactsh-client")) else "interactsh-client"), "-json", "-o", ".oast_logs.json"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True
        )

        payload = None
        start_time = time.time()
        import os as _os
        _os.set_blocking(daemon.stdout.fileno(), False)
        
        while time.time() - start_time < 15:
            line = daemon.stdout.readline()
            if line:
                if "interact.sh" in line or "oast." in line:
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

        # ====================================================================
        # THE DIRECTED ACYCLIC GRAPH (STRICT EXECUTION ORDER ENFORCED)
        # ====================================================================
        if not resume:
            console.print('\n[bold red]━━ PROJECT CERBERUS: BREACHING AUTHENTICATED PERIMETER ━━[/bold red]')
            try:
                auth_data = AuthEngine(target).breach_perimeter()
                if auth_data:
                    session.auth_headers.update(auth_data.get("headers", {}))
                    session.auth_cookies.update(auth_data.get("cookies", {}))
            except Exception as e:
                console.print(f'  [!] Cerberus Bypass Failed: {e}')

            # --- STAGE 1: INTELLIGENCE GATHERING ---
            safe_run("OSINT", run_osint)               # Phase 1.0: Native SSL + API
            safe_run("HORIZONTAL", run_horizontal)     # Phase 1.1: BGP ASN
            safe_run("UMBRELLA", run_umbrella)         # Phase 1.2: Corporate SSL Pivot
            safe_run("VERTICAL", run_vertical)         # Phase 1.3: Async DNS Bruteforce
            safe_run("CLOUD", run_cloud)               # Phase 1.4: Cloud Storage Sniper
            safe_run("PERMUTATIONS", run_permutations) # Phase 1.8: Subdomain Mutations
            
            # --- CRITICAL FIREWALL 1: SAAS BOUNDARY ENFORCEMENT ---
            safe_run("SCOPE_GUARD", run_scope_guard)   # Phase 1.9: MUST run before port scanning

            # --- STAGE 2: INFRASTRUCTURE MAPPING ---
            safe_run("PORTS", run_ports)               # Phase 1.5: Layer-7 Port Scanning
            safe_run("UNMASK", run_unmask)             # Phase 1.6: Origin Unmasking via JARM
            safe_run("HYDRA", run_hydra)               # Phase 1.7: Network Protocol Bruteforcing
            
            # --- STAGE 3: APPLICATION PROFILING ---
            safe_run("PROBING", run_probing)           # Phase 2.0: Active HTTP Profiling
            
            # THE WAF CIRCUIT BREAKER
            if not session.get_live_hosts():
                console.print("\n[bold red]FATAL  Phase 2 failed to profile any live hosts.[/bold red]")
                console.print("[yellow]REASON Target is likely behind an aggressive WAF dropping automated probes.[/yellow]")
                console.print("[dim]ACTION Aborting execution pipeline to preserve stealth. Rerun with --mode authenticated.[/dim]\n")
                sys.exit(0)

            safe_run("SPIDER", run_spider)             # Phase 2.2: Phantom DOM

            # --- CRITICAL FIREWALL 2: SPIDER QUEUE SANITIZATION ---
            safe_run("SCOPE_FIREWALL", sanitize_state_graph) # Phase 2.5: Purge SaaS URLs before Exploitation

            safe_run("CORTEX", run_cortex)             # Phase 3.0: AST Extraction
            
            try:
                from modules.cortex import sanitize_database
                sanitize_database(f"data/sessions/{target.replace('.', '_')}.db")
            except: pass

        # --- STAGE 4: EXPLOITATION (Always runs, even on --resume) ---
        safe_run("NUCLEI", run_nuclei)             # Phase 4.0: Tech-Stack Targeted CVEs
        safe_run("CVE_SNIPER", run_cve_sniper)     # Phase 4.5: Surgical OAST Injection
        safe_run("FUZZER", run_fuzzer)             # Phase 5.0: Semantic Parameter Routing
        safe_run("OAST", run_oast)                 # Phase 8.0: Blind Poller (MUST BE AFTER FUZZER)

        # --- STAGE 5: REPORTING ---
        safe_run("INTELLIGENCE", run_intelligence) # Phase 7.0: Blast Radius Graph
        
        def phase6_notifier(sess, conf):
            db_path = f"data/sessions/{target.replace('.', '_')}.db"
            os.environ["KESTREL_CONFIDENCE_THRESHOLD"] = "85.0"
            run_notifier(target, db_path)
        safe_run("NOTIFIER", phase6_notifier)

    except KeyboardInterrupt:
        console.print("\n[bold red]⚠️ SIGINT RECEIVED: INITIATING GRACEFUL SHUTDOWN...[/bold red]")
        console.print("INFO     Flushing Write-Ahead Logs and securing State Graph...")
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            for task in asyncio.all_tasks(loop):
                task.cancel()
            loop.stop()
        except: pass
        if hasattr(session, 'close'):
            session.close()
        console.print("[green]  + State Graph secured. Terminating pipeline.[/green]")
        sys.exit(130) 
        
    finally:
        if hasattr(session, 'close'):
            session.close()
        if 'daemon' in locals() and daemon.poll() is None:
            daemon.terminate()
            if os.path.exists(".oast_payload.txt"): os.remove(".oast_payload.txt")

if __name__ == "__main__":
    app()

import subprocess
subprocess.run(['python3', 'modules/reporter.py'])
subprocess.run(['python3', 'modules/lake.py'])
