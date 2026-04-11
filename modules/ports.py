import os
import subprocess
import logging
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.panel import Panel

console = Console()
log = logging.getLogger("rich")

CDN_SIGNATURES = ["cloudflare", "cloudfront", "fastly", "akamai", "incapsula", "sucuri", "imperva"]

def is_cdn(domain):
    """Lightweight CNAME resolution to detect CDN presence."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        answers = resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            target = str(rdata.target).lower()
            if any(cdn in target for cdn in CDN_SIGNATURES):
                return domain, True
    except Exception:
        pass
    return domain, False

def run_ports(session, config):
    console.print("[bold blue]━━ PHASE 1.5: PORT SCANNING (CDN SHIELD ACTIVE) ━━[/bold blue]")
    
    if not session.get_subdomains():
        log.warning("No subdomains found to scan.")
        return

    direct_targets = []
    cdn_targets = []
    
    console.print(f"[cyan]  + Analyzing {len(session.get_subdomains())} hosts for CDN routing (50 Threads)...[/cyan]")
    
    # THE UPGRADE: Multi-threaded CDN classification
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(is_cdn, session.get_subdomains())
        for domain, is_fronted in results:
            if is_fronted:
                cdn_targets.append(domain)
            else:
                direct_targets.append(domain)
            
    if cdn_targets:
        console.print(f"[yellow]  ! Bypassing deep scan for {len(cdn_targets)} CDN-fronted hosts.[/yellow]")

    if not direct_targets:
        log.info("All targets are CDN-fronted. Skipping deep port scan.")
        return

    target_file = "data/temp_port_targets.txt"
    with open(target_file, "w") as f:
        for t in direct_targets:
            f.write(t + "\n")

    log.info(f"Executing Naabu against {len(direct_targets)} direct-origin hosts...")
    out_file = "data/temp_naabu.txt"
    
    cmd = [
        "naabu",
        "-l", target_file,
        "-top-ports", "100", 
        "-c", "50",          
        "-silent",
        "-o", out_file
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True)
        if os.path.exists(out_file):
            with open(out_file, "r") as f:
                lines = f.readlines()
                console.print(f"[green]  + Port Scan Complete. Found {len(lines)} open ports.[/green]")
            os.remove(out_file)
        else:
            console.print("[dim]  + No new open ports discovered.[/dim]")
    except Exception as e:
        log.error(f"Port scan failed: {e}")
        
    if os.path.exists(target_file):
        os.remove(target_file)
