import asyncio
import aiodns
import logging
import random
import string
import os
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- THE WILDCARD SINKHOLE ---
async def generate_wildcard_profile(resolver, domain):
    """Generates a cryptographic collision to profile Wildcard DNS responses."""
    junk_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
    junk_target = f"{junk_sub}.{domain}"
    wildcard_ips = set()
    
    try:
        res = await resolver.query(junk_target, 'A')
        for r in res:
            wildcard_ips.add(r.host)
        console.print(f"[yellow]  ! Wildcard DNS Detected. Sinkhole established for IPs: {', '.join(wildcard_ips)}[/yellow]")
    except aiodns.error.DNSError:
        console.print("[green]  + No Wildcard DNS detected. Clean resolution space confirmed.[/green]")
    except Exception:
        pass
        
    return wildcard_ips

# --- THE ASYNC RESOLVER ---
async def resolve_candidate(resolver, sub, domain, wildcard_ips, sem, session_state):
    async with sem:
        target = f"{sub}.{domain}"
        try:
            res = await resolver.query(target, 'A')
            ips = {r.host for r in res}
            
            # Mathematical intersection: If the resolved IPs overlap with the Wildcard Sinkhole, drop it.
            if wildcard_ips and ips.intersection(wildcard_ips):
                return
                
            console.print(f"[green]  + [SHADOW ASSET] {target} -> {list(ips)[0]}[/green]")
            session_state.add_subdomain(target)
            
        except aiodns.error.DNSError:
            pass # NXDOMAIN (Does not exist)
        except Exception:
            pass

async def deploy_vertical_bruteforce(session_state, wordlist_path):
    domain = session_state.domain
    resolver = aiodns.DNSResolver(timeout=2.0, tries=2)
    sem = asyncio.Semaphore(1000) # 1,000 concurrent UDP packets
    
    wildcard_ips = await generate_wildcard_profile(resolver, domain)
    
    try:
        with open(wordlist_path, 'r') as f:
            words = [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]WARNING  Wordlist {wordlist_path} not found. Skipping Vertical Bruteforce.[/red]")
        return

    console.print(f"INFO     Executing High-Velocity UDP Blast: {len(words)} payloads...")
    
    # Fire the async blasts in chunks to respect system ulimits
    tasks = [resolve_candidate(resolver, word, domain, wildcard_ips, sem, session_state) for word in words]
    await asyncio.gather(*tasks)

def run_vertical(session, config):
    console.print("\n[bold blue]━━ PHASE 1.3: VERTICAL DNS BRUTEFORCING (NATIVE C-ARES) ━━[/bold blue]")
    
    # We map the wordlist from the config file. Default to a fast 5k list.
    wordlist = config.get("wordlists", {}).get("dns", "data/wordlists/dns_top5000.txt")
    
    if not os.path.exists("data/wordlists"):
        os.makedirs("data/wordlists")
        
    # If the wordlist doesn't exist, we generate a highly-targeted tactical mini-list on the fly
    if not os.path.exists(wordlist):
        console.print("[dim]  * Local wordlist not found. Generating tactical internal dictionary...[/dim]")
        tactical_words = ["dev", "staging", "test", "uat", "internal", "vpn", "api", "api-dev", "admin", "portal", "db", "sql", "gitlab", "jenkins", "kibana", "grafana", "monitor", "metrics", "stage", "prod", "beta", "alpha", "jira", "confluence", "wiki", "sso", "auth", "secure"]
        with open(wordlist, 'w') as f:
            f.write("\n".join(tactical_words))

    initial_count = len(session.get_subdomains())
    asyncio.run(deploy_vertical_bruteforce(session, wordlist))
    final_count = len(session.get_subdomains())
    
    console.print(f"  + Vertical Bruteforce complete. Unearthed {final_count - initial_count} hidden shadow assets.")
