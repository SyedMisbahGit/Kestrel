import asyncio
import aiohttp
import socket
import logging
import ipaddress
import sqlite3
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

TOP_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 22, 21, 3306, 5432, 27017, 6379]

async def fetch_cdn_cidrs():
    """Fetches official CDN edge-node CIDR blocks dynamically."""
    cidrs = []
    urls = [
        "https://www.cloudflare.com/ips-v4/",
        "https://api.fastly.com/public-ip-list"
    ]
    try:
        async with aiohttp.ClientSession() as client:
            # Fetch Cloudflare
            async with client.get(urls[0], timeout=5) as r:
                if r.status == 200:
                    text = await r.text()
                    cidrs.extend([line.strip() for line in text.splitlines() if line.strip()])
            
            # Fetch Fastly
            async with client.get(urls[1], timeout=5) as r:
                if r.status == 200:
                    data = await r.json()
                    cidrs.extend(data.get("addresses", []))
    except Exception:
        pass
    return [ipaddress.ip_network(cidr, strict=False) for cidr in cidrs]

def is_cdn_ip(ip_str, cdn_networks):
    """Mathematically verifies if an IP belongs to a known CDN edge network."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in cdn_networks)
    except ValueError:
        return False

async def check_port(sem, target, port, session_state):
    async with sem:
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.5)
            console.print(f"[green]  + [OPEN] {target}:{port}[/green]")
            session_state.open_ports.add(f"{target}:{port}")
            session_state.vulnerabilities.append({"type": "VULN", "name": "Exposed Port", "matched-at": f"{target}:{port}", "info": {"severity": "MEDIUM"}})
            writer.close()
            await writer.wait_closed()
            # In a real setup, you'd save this to your state graph
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass

async def deploy_port_scan(session_state, targets):
    console.print("INFO     Fetching dynamic edge-node CIDR blocks (Cloudflare, Fastly)...")
    cdn_networks = await fetch_cdn_cidrs()
    
    sem = asyncio.Semaphore(200) # Control open file descriptors
    tasks = []
    
    scannable_targets = []
    for t in targets:
        # Resolve to IP to check against CDN filter
        try:
            ip = socket.gethostbyname(t)
            if is_cdn_ip(ip, cdn_networks):
                console.print(f"[dim]  * {t} ({ip}) is a CDN Edge Node. Bypassing port scan (Assuming 80/443).[/dim]")
                continue
            scannable_targets.append(t)
        except socket.gaierror:
            pass

    if not scannable_targets:
        console.print("[yellow]WARNING  All active hosts are shielded by CDNs. Zero viable targets for deep port scanning.[/yellow]")
        return

    console.print(f"INFO     Executing Deep Port Scan on {len(scannable_targets)} Origin IPs...")
    for target in scannable_targets:
        for port in TOP_PORTS:
            tasks.append(check_port(sem, target, port, session_state))
            
    await asyncio.gather(*tasks)

def run_ports(session, config):
    console.print("\n[bold blue]━━ PHASE 1.5: PORT SCANNING (EDGE-NODE DROP FILTER ACTIVE) ━━[/bold blue]")
    targets = [sub for sub in session.get_subdomains()]
    
    if not targets:
        console.print("WARNING  No targets available for port scanning.")
        return
        
    asyncio.run(deploy_port_scan(session, targets))
    console.print("  + Port Scan Complete. CDN Traps successfully bypassed.")
