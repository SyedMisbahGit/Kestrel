import asyncio
import logging
import ipaddress
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

TARGET_PORTS = [21, 22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9000, 27017]
HTTP_PORTS = [80, 443, 3000, 5000, 8000, 8080, 8443, 9000]

# Static Vercel Anycast CIDRs
VERCEL_CIDRS = [
    ipaddress.ip_network("76.76.21.0/24"),
    ipaddress.ip_network("64.239.0.0/19")
]

def is_vercel_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in cidr for cidr in VERCEL_CIDRS)
    except Exception:
        return False

async def verify_l7_service(host, port, sem):
    async with sem:
        try:
            # 1. Establish TCP Connection
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=4.0)
            
            # 2. Coax the Application Banner
            if port in [6379]:
                writer.write(b"PING\r\n")
            elif port in HTTP_PORTS:
                writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            else:
                # Send generic dummy bytes to trigger an error response from synthetic proxies
                writer.write(b"\x00\x00\x00\x01\x00")
            
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=4.0)
            writer.close()
            await writer.wait_closed()
            
            if not banner: return None
            banner_lower = banner.lower()
            
            # 3. THE STRICT HTTP SYNTHETIC TRAP
            # If we see HTTP headers, we evaluate context.
            http_signatures = [b"http/", b"server:", b"content-type:", b"<html", b"bad request", b"308 permanent redirect"]
            if any(sig in banner_lower for sig in http_signatures):
                if port not in HTTP_PORTS:
                    # We asked for a database/SSH, it gave us HTTP. It's a synthetic CDN edge.
                    return None 
                return port # It's a valid web port
            
            # 4. ZERO-TRUST POSITIVE VALIDATION
            if port == 22 and b"ssh-" not in banner_lower: return None
            if port == 21 and b"220" not in banner_lower: return None
            if port == 6379 and b"+pong" not in banner_lower and b"-noauth" not in banner_lower and b"-err" not in banner_lower: return None
            if port == 3306 and not any(sig in banner_lower for sig in [b"mysql", b"mariadb", b"caching_sha2_password", b"mysql_native_password", b"\x00\x00\x00\n"]): return None
            if port == 5432 and not any(sig in banner_lower for sig in [b"fatal", b"postgres", b"\x00"]): return None
            if port == 27017 and not any(sig in banner_lower for sig in [b"mongodb", b"mongo", b"\x00"]): return None
            
            return port
            
        except Exception:
            return None

async def scan_origin(host, session, sem):
    tasks = [verify_l7_service(host, port, sem) for port in TARGET_PORTS]
    results = await asyncio.gather(*tasks)
    valid_ports = [p for p in results if p is not None]
    
    if valid_ports:
        for p in valid_ports:
            console.print(f"  + [OPEN] {host}:{p} [green](Zero-Trust L7 Verified)[/green]")
        session.add_live_host(ip=host, ports=valid_ports, url=f"http://{host}")

async def deploy_scanner(session, targets):
    sem = asyncio.Semaphore(100)
    tasks = [scan_origin(target, session, sem) for target in targets]
    await asyncio.gather(*tasks)

def run_ports(session, config):
    console.print("\n[bold blue]━━ PHASE 1.5: PORT SCANNING (ZERO-TRUST L7 PROTOCOL BOUNDING) ━━[/bold blue]")
    
    origins = session.get_subdomains()
    
    # Apply standard CDN edge drop + explicit Vercel CIDR drop
    active_targets = []
    for ip in origins:
        if session.is_cdn_edge(ip):
            continue
        if is_vercel_ip(ip):
            console.print(f"  * {ip} matches known Vercel Anycast CIDR. Bypassing port scan.")
            continue
        active_targets.append(ip)
    
    if not active_targets:
        console.print("WARNING  No bare origin IPs available for scanning. All targets shielded.")
        return
        
    console.print(f"INFO     Executing Deep L7 Application Profiling on {len(active_targets)} Origin IPs...")
    asyncio.run(deploy_scanner(session, active_targets))
    console.print("  + Application Port Profiling Complete. Synthetic cloud endpoints eliminated.")
