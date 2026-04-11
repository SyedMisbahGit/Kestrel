import asyncio
import socket
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- THE CDN SHIELD ---
CDN_DOMAINS = ["cloudflare", "akamai", "fastly", "cloudfront", "incapdns", "sucuri", "edgecast"]

# Top 25 most common exposed infrastructure ports
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 9200, 27017]

async def check_port(host, port, sem):
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=1.0)
            writer.close()
            await writer.wait_closed()
            return port
        except Exception:
            return None

async def scan_host(host, sem_global):
    async with sem_global:
        is_cdn = False
        try:
            # Resolve CNAME to detect CDN routing
            _, aliases, _ = socket.gethostbyname_ex(host)
            for alias in aliases:
                if any(cdn in alias.lower() for cdn in CDN_DOMAINS):
                    is_cdn = True
                    break
        except Exception:
            pass

        # If CDN is detected, deep port scanning is useless. Stick to web ports.
        target_ports = [80, 443] if is_cdn else TOP_PORTS
        
        sem_local = asyncio.Semaphore(20)
        tasks = [check_port(host, p, sem_local) for p in target_ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [p for p in results if p]
        return is_cdn, len(open_ports)

async def deploy_port_scanner(targets):
    sem_global = asyncio.Semaphore(50)
    tasks = [scan_host(target, sem_global) for target in targets]
    results = await asyncio.gather(*tasks)
    
    cdn_count = sum(1 for r in results if r[0])
    total_ports = sum(r[1] for r in results)
    return cdn_count, total_ports

def run_ports(session, config):
    console.print("\n[bold blue]━━ PHASE 1.5: PORT SCANNING (CDN SHIELD ACTIVE) ━━[/bold blue]")
    targets = session.get_subdomains()
    
    if not targets:
        console.print("WARNING  No targets available for port scanning.")
        return
        
    console.print(f"  + Analyzing {len(targets)} hosts for CDN routing...")
    
    cdn_count, total_ports = asyncio.run(deploy_port_scanner(targets))
    
    if cdn_count > 0:
        console.print(f"  [yellow]! Bypassing deep scan for {cdn_count} CDN-fronted hosts.[/yellow]")
    console.print(f"  + Port Scan Complete. Found {total_ports} open ports across infrastructure.")
