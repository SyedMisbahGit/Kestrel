import dns.resolver
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# Common environments and prefixes for shadow IT
ENV_PREFIXES = ["dev-", "stage-", "test-", "prod-", "uat-", "internal-", "corp-", "api-", "new-", "old-", "bak-"]
ENV_SUFFIXES = ["-dev", "-stage", "-test", "-prod", "-uat", "-internal", "-corp", "-api", "-new", "-old", "-bak"]

def get_wildcard_ips(domain):
    """Detects if the target uses Wildcard DNS by resolving an impossible subdomain."""
    impossible_sub = f"arbiter-wildcard-test-{uuid.uuid4().hex[:8]}.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    try:
        answers = resolver.resolve(impossible_sub, 'A')
        ips = {str(rdata) for rdata in answers}
        return ips
    except Exception:
        return set()

def resolve_permutation(args):
    candidate, wildcard_ips = args
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    try:
        answers = resolver.resolve(candidate, 'A')
        resolved_ips = {str(rdata) for rdata in answers}
        
        # THE FILTER: If it resolves to the wildcard IP, it's a false positive
        if wildcard_ips and resolved_ips.intersection(wildcard_ips):
            return None
            
        return candidate
    except Exception:
        return None

def run_permutations(session, config):
    """
    Phase 1.8: Subdomain Permutations
    Generates and resolves environment-based permutations with Wildcard filtering.
    """
    console.print("[bold blue]━━ PHASE 1.8: SUBDOMAIN PERMUTATIONS ━━[/bold blue]")
    
    bases = list(set(session.get_subdomains()))
    if not bases:
        log.warning("No base subdomains to permute.")
        return

    domain = session.domain
    
    # 1. Detect Wildcard DNS
    console.print("INFO     Testing for Wildcard DNS traps...")
    wildcard_ips = get_wildcard_ips(domain)
    if wildcard_ips:
        console.print(f"[yellow]  ! Wildcard DNS Detected. Filtering junk resolutions...[/yellow]")
    else:
        console.print("[green]  + No Wildcard DNS detected. Proceeding normally.[/green]")

    console.print(f"INFO     Generating permutations for {len(bases)} unique prefixes...")
    candidates = set()
    
    for base in bases:
        sub = base.replace(f".{domain}", "")
        if sub == domain or not sub: continue
        
        for p in ENV_PREFIXES:
            candidates.add(f"{p}{sub}.{domain}")
            candidates.add(f"{sub}.{p[:-1]}.{domain}")
        for s in ENV_SUFFIXES:
            candidates.add(f"{sub}{s}.{domain}")

    candidates = list(candidates)
    if not candidates: return

    console.print(f"INFO     Resolving {len(candidates)} candidate permutations (Wildcard Filter Active)...")
    
    valid_new_subs = set()
    args_list = [(c, wildcard_ips) for c in candidates]
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(resolve_permutation, args_list)
        for res in results:
            if res and res not in bases:
                valid_new_subs.add(res)
                console.print(f"[green]  + Found Hidden Sub: {res}[/green]")

    if valid_new_subs:
        session.get_subdomains().extend(list(valid_new_subs))
        console.print(f"INFO     Permutations found {len(valid_new_subs)} validated subdomains.")
    else:
        console.print("[dim]  + No valid new subdomains found via permutations.[/dim]")
