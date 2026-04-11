import dns.resolver
import requests
import logging
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.panel import Panel
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
log = logging.getLogger("rich")

# Cloud Provider Signatures
# Format: {"Provider": {"cnames": ["cname_string"], "fingerprint": "HTML error string"}}
SIGNATURES = {
    "AWS S3": {
        "cnames": ["s3.amazonaws.com", "s3-website"],
        "fingerprint": "The specified bucket does not exist"
    },
    "GitHub Pages": {
        "cnames": ["github.io"],
        "fingerprint": "There isn't a GitHub Pages site here."
    },
    "Heroku": {
        "cnames": ["herokuapp.com"],
        "fingerprint": "No such app"
    },
    "Shopify": {
        "cnames": ["myshopify.com"],
        "fingerprint": "Sorry, this shop is currently unavailable."
    },
    "Zendesk": {
        "cnames": ["zendesk.com"],
        "fingerprint": "Help Center Closed"
    },
    "Azure": {
        "cnames": ["azurewebsites.net", "cloudapp.net"],
        "fingerprint": "404 Web Site not found"
    },
    "Fastly": {
        "cnames": ["fastly.net"],
        "fingerprint": "Fastly error: unknown domain"
    }
}

def check_takeover(domain):
    """Resolves CNAME and checks against provider fingerprints."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    try:
        answers = resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname_target = str(rdata.target).lower()
            
            # Check if CNAME points to a known cloud provider
            for provider, data in SIGNATURES.items():
                if any(c in cname_target for c in data["cnames"]):
                    # CNAME matches. Fetch the page to check the exact fingerprint.
                    try:
                        r = requests.get(f"http://{domain}", timeout=5, verify=False)
                        if data["fingerprint"] in r.text:
                            return {
                                "domain": domain,
                                "provider": provider,
                                "cname": cname_target,
                                "vulnerable": True
                            }
                    except Exception:
                        pass
    except Exception:
        pass
    return None

def run_takeover(session, config):
    """
    Phase 1.9: The Seizure
    Hunts for dangling DNS pointers and vulnerable cloud providers.
    """
    console.print("[bold blue]━━ PHASE 1.9: THE SEIZURE (SUBDOMAIN TAKEOVER) ━━[/bold blue]")
    
    # Target all discovered subdomains
    targets = list(set(session.get_subdomains()))
    if not targets:
        log.warning("No targets to check for takeover.")
        return

    console.print(f"INFO     Hunting for dangling CNAMEs across {len(targets)} subdomains (50 Threads)...")
    
    findings = 0
    # Multi-threaded execution for massive scope handling
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check_takeover, targets)
        for res in results:
            if res and res["vulnerable"]:
                findings += 1
                console.print(Panel(
                    f"[bold red]CRITICAL: SUBDOMAIN TAKEOVER DETECTED[/bold red]\n"
                    f"Target: {res['domain']}\n"
                    f"Provider: {res['provider']}\n"
                    f"Dangling CNAME: {res['cname']}",
                    title="❌ HIJACK RISK", border_style="red"
                ))
                
                # Write directly to the SQLite Database Core
                session.vulnerabilities.append({
                    "name": f"Subdomain Takeover ({res['provider']})",
                    "severity": "CRITICAL",
                    "url": res['domain'],
                    "info": f"Dangling pointer to {res['cname']}. Provider fingerprint matched."
                })

    if findings == 0:
        console.print("[green]  + No dangling pointers or takeover vectors found.[/green]")
    else:
        console.print(f"INFO     The Seizure Complete. Logged {findings} critical hijacks.")
