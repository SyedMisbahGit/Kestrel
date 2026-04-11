import typer
import logging
import yaml
import os
import sys
from rich.console import Console

# Core
from core.state import TargetSession
from core.intelligence import run_intelligence

# Modules
from modules.recon import run_recon
from modules.horizontal import run_horizontal
from modules.dns_forensics import run_dns_forensics
from modules.ports import run_ports
from modules.permutations import run_permutations
from modules.probing import run_probing
from modules.spider import run_spider
from modules.takeover import run_takeover
from modules.cloud import run_cloud
from modules.email import run_email
from modules.github_recon import run_github
from modules.cortex import run_cortex
from modules.nuclei_scan import run_nuclei
from modules.fuzzer import run_fuzzer

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
def scan(target: str, mode: str = "standard", resume: bool = typer.Option(False, "--resume")):
    console.print("\n[bold]SYSTEM INTEGRITY EVALUATOR // v2.0[/bold]\n")
    config = load_config()
    session = TargetSession(target, mode)

    def safe_run(name, func):
        try:
            func(session, config)
        except Exception as e:
            log.error(f"{name} failed: {e}")

    try:
        # THE DIRECTED ACYCLIC GRAPH (DAG)
        if not resume:
            safe_run("RECON", run_recon)
            safe_run("HORIZONTAL", run_horizontal)
            safe_run("DNS FORENSICS", run_dns_forensics)
            safe_run("PORT SCAN", run_ports)
            safe_run("PERMUTATIONS", run_permutations)
            safe_run("PROBING", run_probing)
            safe_run("SPIDER", run_spider)
            safe_run("TAKEOVER", run_takeover)
            safe_run("CLOUD", run_cloud)
            safe_run("EMAIL", run_email)
            safe_run("GITHUB", run_github)
            safe_run("CORTEX", run_cortex)
            
        safe_run("NUCLEI", run_nuclei)
        safe_run("FUZZER", run_fuzzer)
        safe_run("INTELLIGENCE", run_intelligence)

    except KeyboardInterrupt:
        # THE GRACEFUL SHUTDOWN TRAP
        console.print("\n[bold red]⚠️ SIGINT RECEIVED: INITIATING GRACEFUL SHUTDOWN...[/bold red]")
        console.print("INFO     Flushing Write-Ahead Logs and securing State Graph...")
        if hasattr(session, 'close'):
            session.close()
        console.print("[green]  + State Graph secured. Terminating pipeline.[/green]")
        sys.exit(130) # Standard exit code for SIGINT
        
    finally:
        # Ensure cleanup always happens, even on standard exit
        if hasattr(session, 'close'):
            session.close()

if __name__ == "__main__":
    app()
