import typer
import yaml
import sys
import logging
import shutil
import os
from rich.logging import RichHandler
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.prompt import Confirm
from core.intelligence import run_intelligence

# --- THE UPGRADE: SQLite Memory Core ---
from core.state import TargetSession

# Import Modules
from modules.recon import run_recon
from modules.horizontal import run_horizontal
from modules.dns_forensics import run_dns_forensics
from modules.permutations import run_permutations
from modules.ports import run_ports
from modules.probing import run_probing
from modules.spider import run_spider
from modules.cloud import run_cloud
from modules.email import run_email
from modules.github_recon import run_github
from modules.takeover import run_takeover
from modules.cortex import run_cortex
from modules.offensive import run_offensive
from modules.mining import run_mining
from modules.oast import run_oast
from modules.chaos import run_chaos
from modules.nuclei_scan import run_nuclei
from modules.report import run_report

# Setup Logging
logging.basicConfig(
    level="INFO", 
    format="%(message)s", 
    datefmt="[%X]", 
    handlers=[RichHandler(rich_tracebacks=True, markup=True, show_time=False)]
)
log = logging.getLogger("rich")
console = Console()

# Define App
app = typer.Typer(help="ARBITER: System Integrity Evaluator")

def load_config():
    try:
        with open("config/settings.yaml", "r") as f: return yaml.safe_load(f)
    except: return {}

CONFIG = load_config()

BANNER = """
[bold cyan]
   ▄▄▄       ██▀███   ▄▄▄▄    ██▓▄▄▄█████▓▓█████  ██▀███  
  ▒████▄    ▓██ ▒ ██▒▓█████▄ ▓██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
  ▒██  ▀█▄  ▓██ ░▄█ ▒▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
  ░██▄▄▄▄██ ▒██▀▀█▄  ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  
   ▓█   ▓██▒░██▓ ▒██▒░▓█  ▀█▓░██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
   ▒▒   ▓▒█░░ ▒▓ ░▒▓░░▒▓███▀▒░▓    ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
    ▒   ▒▒ ░  ░▒ ░ ▒░▒░▒   ░  ▒ ░    ░      ░ ░  ░▒ ░ ▒░
    ░   ▒     ░░   ░  ░    ░  ▒ ░  ░         ░     ░░   ░ 
        ░  ░   ░      ░       ░              ░  ░   ░     
                       ░                                  
[/bold cyan][bold white]SYSTEM INTEGRITY EVALUATOR // v2.0[/bold white]
"""

@app.callback()
def main(): pass

@app.command()
def scan(target: str = typer.Argument(...), mode: str = typer.Option("stealth", "--mode", "-m"), resume: bool = typer.Option(False, "--resume", "-r")):
    console.print(Align.center(BANNER))
    console.print(Panel.fit(f"[bold cyan]TARGET ACQUIRED:[/bold cyan] {target}\n[bold cyan]PROTOCOL:[/bold cyan] {mode.upper()}", border_style="cyan"))

    # Initialize SQLite Core Engine
    # (SQLite naturally handles resuming without duplicating data thanks to 'UNIQUE' constraints)
    session = TargetSession(target)
    
    # In-memory phase tracker for the current run
    completed_phases = []

    try:
        phases = [
            ("recon", run_recon), 
            ("horizontal", run_horizontal), 
            ("dns_forensics", run_dns_forensics), 
            ("ports", run_ports), 
            ("permutations", run_permutations),
            ("probing", run_probing), 
            ("spider", run_spider), 
            ("takeover", run_takeover), 
            ("cloud", run_cloud),
            ("email", run_email), 
            ("github", run_github), 
            ("cortex", run_cortex), 
            ("nuclei", run_nuclei),
            ("intelligence", run_intelligence),            
            ("oast", run_oast), 
            ("chaos", run_chaos)
        ]

        for name, func in phases:
            if name not in completed_phases or name == "intelligence":
                func(session, CONFIG)
                completed_phases.append(name)

        run_report(session, CONFIG)
        console.print(f"[bold green]>> EVALUATION COMPLETE.[/bold green]")

        # --- GHOST PROTOCOL ---
        if Confirm.ask("[bold yellow]Do you want to SAVE the mission data locally?[/bold yellow]"):
            console.print(f"[green]✔ Data preserved in output/{target} and data/sessions/{target.replace('.', '_')}.db[/green]")
        else:
            console.print(f"[red]! PURGING MISSION DATA...[/red]")
            output_dir = f"output/{target}"
            
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            
            # Fire the SQLite Purge command
            session.purge()
            console.print(f"[red]✔ TRACE DELETED.[/red]")

    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]SYSTEM FAILURE: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    app()
