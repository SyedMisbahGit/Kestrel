import requests
import logging
from rich.console import Console
from rich.panel import Panel
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
log = logging.getLogger("rich")

def run_offensive(session, config):
    """
    Phase 4: Offensive Strikes (CORS Cartographer)
    Hunts for Cross-Origin Resource Sharing misconfigurations.
    """
    console.print("[bold blue]━━ PHASE 4: OFFENSIVE STRIKES (CORS CARTOGRAPHER) ━━[/bold blue]")
    
    if not session.live_hosts:
        log.warning("No live hosts to strike. Skipping.")
        return

    evil_origin = "https://evil-arbiter.com"
    headers = {"Origin": evil_origin}
    
    console.print(f"INFO     Launching CORS_STRIKE against {len(session.live_hosts)} targets...")
    
    findings = 0
    for host in session.live_hosts:
        target = host.get('url')
        if not target: continue
        
        try:
            r = requests.get(target, headers=headers, timeout=5, verify=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "false").lower()
            
            # The Logic: Does it reflect our evil origin AND allow credentials?
            if (acao == evil_origin or acao == "*") and acac == "true":
                console.print(Panel(
                    f"[bold red]CRITICAL: CORS MISCONFIGURATION DETECTED[/bold red]\n"
                    f"Target: {target}\n"
                    f"Origin Allowed: {acao}\n"
                    f"Credentials Allowed: {acac}",
                    title="❌ API HIJACK RISK", border_style="red"
                ))
                session.vulnerabilities.append({
                    "name": "CORS Misconfiguration (API Hijack)",
                    "severity": "HIGH",
                    "url": target,
                    "info": f"Server blindly trusts Origin: {acao} with Credentials: {acac}"
                })
                findings += 1
        except Exception:
            pass
            
    if findings == 0:
        console.print("[green]  + No CORS misconfigurations detected (Secure).[/green]")
