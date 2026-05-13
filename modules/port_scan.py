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
            if port in [6379]:
                writer.write(b"PING\r\n")
            elif port in [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]:
                writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            else:
                # 3306, 5432, 27017, 21, 22
                writer.write(b"\x00\x00\x00\x01\x00")
            
            await writer.drain()
            
            # 3. Read the Service Response
            banner = await asyncio.wait_for(reader.read(1024), timeout=4.0)
            writer.close()
            await writer.wait_closed()
            
            if not banner:
                return None  # Dropped connection (Tarpit)
                
            banner_lower = banner.lower()
            
            # 4. THE SYNTHETIC CLOUD EDGE FILTER
            # If we see HTTP signatures or cloud headers on ANY port, we evaluate context.
            cloud_signatures = [b"server: vercel", b"server: cloudflare", b"x-amz-request-id", b"http/1.", b"bad request", b"308 permanent redirect"]
            is_http_response = any(sig in banner_lower for sig in cloud_signatures)
            
            if is_http_response:
                # If this is supposed to be a DB/SSH/FTP port, but we got an HTTP response, it's a cloud hallucination.
                if port not in [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]:
                    return None
                return port # It's a valid web port
            
            # 5. Strict Protocol Validation for Non-Web Services
            if port == 22 and b"ssh-" not in banner_lower: 
                return None
            if port == 21 and b"220" not in banner_lower: 
                return None
            if port == 6379 and b"+pong" not in banner_lower and b"-noauth" not in banner_lower and b"-err" not in banner_lower: 
                return None
            if port == 3306 and b"mysql" not in banner_lower and b"\x00" not in banner_lower:
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
        session.add_live_host(ip=host, ports=valid_ports, url=f"http://{host}")

async def deploy_scanner(session, targets):
    sem = asyncio.Semaphore(100)
    tasks = [scan_origin(target, session, sem) for target in targets]
    await asyncio.gather(*tasks)

def run_ports(session, config):
    console.print("\n[bold blue]━━ PHASE 1.5: PORT SCANNING (STRICT L7 PROTOCOL BOUNDING) ━━[/bold blue]")
    
    origins = session.get_subdomains()
    active_targets = [ip for ip in origins if not session.is_cdn_edge(ip)]
    
    if not active_targets:
        console.print("WARNING  No bare origin IPs available for scanning. All targets shielded.")
        return
        
    console.print(f"INFO     Executing Deep L7 Application Profiling on {len(active_targets)} Origin IPs...")
    asyncio.run(deploy_scanner(session, active_targets))
    console.print("  + Application Port Profiling Complete. Synthetic Cloud Edges successfully bypassed.")
