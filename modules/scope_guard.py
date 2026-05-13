import dns.resolver
import logging
import concurrent.futures
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- THE SAAS BLACKLIST ---
# If a target CNAME resolves to any of these root domains, it is stripped from the attack surface.
SAAS_BLACKLIST = [
    "tally.so", "zendesk.com", "hubspot.net", "wpengine.com", "webflow.io",
    "force.com", "salesforce.com", "atlassian.net", "intercom.io", "shopify.com",
    "squarespace.com", "readme.io", "statuspage.io", "ghost.io", "netlify.app",
    "freshdesk.com", "helpscout.com", "breezy.hr", "greenhouse.io", "workable.com", "vanta.com", "github.io", "github.com"
]

def resolve_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME', lifetime=3)
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
        return None

def run_scope_guard(session, config):
    console.print("\n[bold blue]━━ PHASE 1.9: THE SCOPE GUARD (CNAME BOUNDING FILTER) ━━[/bold blue]")
    
    subdomains = session.get_subdomains()
    if not subdomains:
        return

    console.print(f"INFO     Tracing CNAME chains for {len(subdomains)} active targets to prevent SaaS collateral damage...")

    safe_targets = []
    out_of_scope = []

    # Parallelize the DNS lookups for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(resolve_cname, domain): domain for domain in subdomains}
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            cname = future.result()

            is_safe = True
            if cname:
                for saas in SAAS_BLACKLIST:
                    if saas in cname:
                        out_of_scope.append((domain, cname, saas))
                        is_safe = False
                        break
            
            if is_safe:
                safe_targets.append(domain)

    # Overwrite the session state with ONLY the legally authorized targets
    session.subdomains = safe_targets
    
    # Purge from the persistent SQLite state database so downstream modules can't resurrect them
    if out_of_scope:
        try:
            cursor = session.conn.cursor()
            for domain, cname, saas in out_of_scope:
                # Use a wildcard to ensure subdomains are wiped across all tables
                cursor.execute("DELETE FROM subdomains WHERE name = ?", (domain,))
            session.conn.commit()
        except Exception:
            pass

    if out_of_scope:
        console.print(f"[bold yellow]WARNING  {len(out_of_scope)} Subdomains identified as Third-Party SaaS. Removing from Attack Surface:[/bold yellow]")
        for domain, cname, saas in out_of_scope:
            console.print(f"  [dim]- {domain} → {cname} [OUT OF SCOPE: {saas.upper()}][/dim]")
    else:
        console.print("  + All targets verified as native infrastructure. No SaaS collisions detected.")
    
    console.print(f"INFO     Authorized Attack Surface reduced to {len(safe_targets)} targets.")

from urllib.parse import urlparse

def sanitize_state_graph(session, config):
    console.print("\n[bold blue]━━ PHASE 2.5: THE SCOPE FIREWALL (GLOBAL STATE SANITIZATION) ━━[/bold blue]")
    
    live_hosts = session.get_live_hosts()
    if not live_hosts: return
    
    console.print(f"INFO     Auditing {len(live_hosts)} harvested endpoints against SaaS Blacklist and CNAME restrictions...")
    
    safe_hosts = []
    purged_count = 0
    domain_cache = {}
    
    for host in live_hosts:
        url = host.get('url', '')
        if not url: continue
        
        domain = urlparse(url).netloc.split(':')[0]
        
        # Cache resolutions so we don't spam DNS for 1,500 spidered endpoints
        if domain not in domain_cache:
            cname = resolve_cname(domain)
            is_safe = True
            
            if any(saas in domain for saas in SAAS_BLACKLIST):
                is_safe = False
            elif cname and any(saas in cname for saas in SAAS_BLACKLIST):
                is_safe = False
                
            domain_cache[domain] = is_safe
            
        if domain_cache[domain]:
            safe_hosts.append(host)
        else:
            purged_count += 1
            console.print(f"  [dim]- Purged unauthorized SaaS URL from state graph: {url}[/dim]")
            
    # Overwrite the in-memory execution queue
    session.live_hosts = safe_hosts
    
    if purged_count > 0:
        console.print(f"[bold yellow]WARNING  Purged {purged_count} out-of-scope URLs harvested by the Spider.[/bold yellow]")
    else:
        console.print("  + State Graph is clean. No unauthorized URLs detected.")
