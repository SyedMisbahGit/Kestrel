import asyncio
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

TARGET_PORTS = [21, 22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9000, 27017]

async def verify_l7_service(host, port, sem):
    async with sem:
        try:
            # 1. Establish the TCP Connection (Layer 4)
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=4.0)
            
            # 2. Coax the Application Banner (Layer 7)
            # Some services (SSH, FTP) send a banner immediately. Others (HTTP, Redis) wait for the client to speak.
            if port in [6379]:
                writer.write(b"PING\r\n")
            elif port in [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]:
                writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            
            await writer.drain()
            
            # 3. Read the Service Response
            banner = await asyncio.wait_for(reader.read(1024), timeout=4.0)
            writer.close()
            await writer.wait_closed()
            
            if not banner:
                return None  # Connection accepted but immediately dropped (Tarpit / Edge Firewall)
                
            banner_lower = banner.lower()
            
            # 4. Behavioral Protocol Validation (The Trap Filter)
            if port == 22 and b"ssh-" not in banner_lower: 
                return None
            if port == 21 and b"220" not in banner_lower: 
                return None
            if port == 6379 and b"+pong" not in banner_lower and b"-noauth" not in banner_lower and b"-err" not in banner_lower: 
                return None
            
            # THE ANYCAST TRAP FILTER: If a database port responds with an HTTP header, it's a Vercel/GCP edge node hallucination.
            if port in [3306, 5432, 27017]:
                if b"http/" in banner_lower or b"html" in banner_lower:
                    return None
            
            return port
            
        except Exception:
            return None

async def scan_origin(host, session, sem):
    tasks = [verify_l7_service(host, port, sem) for port in TARGET_PORTS]
    results = await asyncio.gather(*tasks)
    
    valid_ports = [p for p in results if p is not None]
    
    if valid_ports:
        for p in valid_ports:
            console.print(f"  + [OPEN] {host}:{p} [green](L7 Verified)[/green]")
        
        # Inject the verified L7 ports back into Kestrel's state graph
        session.add_live_host(ip=host, ports=valid_ports, url=f"http://{host}")

async def deploy_scanner(session, targets):
    sem = asyncio.Semaphore(100) # Throttle concurrent socket connections
    tasks = [scan_origin(target, session, sem) for target in targets]
    await asyncio.gather(*tasks)

def run_ports(session, config):
    console.print("\n[bold blue]━━ PHASE 1.5: PORT SCANNING (LAYER-7 BANNER GRABBING) ━━[/bold blue]")
    
    # Fetch origin IPs unmasked in previous phases
    origins = session.get_subdomains()
    
    # Filter out known edge nodes dynamically
    active_targets = [ip for ip in origins if not session.is_cdn_edge(ip)]
    
    if not active_targets:
        console.print("WARNING  No bare origin IPs available for scanning. All targets shielded.")
        return
        
    console.print(f"INFO     Executing Deep L7 Application Profiling on {len(active_targets)} Origin IPs...")
    asyncio.run(deploy_scanner(session, active_targets))
    console.print("  + Application Port Profiling Complete. CDN Anycast Traps successfully bypassed.")
