from core.ui import print_briefing
import asyncio
import aiohttp
import logging
import sqlite3
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# Common environments and suffixes used by DevOps
MUTATIONS = ["", "-prod", "-dev", "-staging", "-test", "-uat", "-bak", "-backup", "-assets", "-static", "-media", "-public", "-private", "-internal", "-logs", "-data", "-api", "prod", "dev", "staging"]

# Cloud Provider Signatures
PROVIDERS = {
    "AWS S3": "https://{}.s3.amazonaws.com",
    "Azure Blob": "https://{}.blob.core.windows.net",
    "GCP Storage": "https://storage.googleapis.com/{}"
}

async def check_bucket(client, sem, provider_name, url, session_state, candidate):
    async with sem:
        try:
            async with client.get(url, timeout=5, ssl=False, allow_redirects=False) as r:
                status = r.status
                text = await r.text()
                headers_str = str(r.headers).lower()

                if "nosuchbucket" in text.lower() or status == 404:
                    return

                # OWNERSHIP VALIDATION: Does the target domain appear in the bucket's headers, redirects, or body?
                # Or does the bucket name perfectly match the apex domain (e.g., target.com.s3.amazonaws.com)?
                target_domain = session_state.domain.lower()
                is_owned = False
                
                if target_domain in headers_str or target_domain in text.lower() or target_domain in candidate:
                    is_owned = True
                
                if not is_owned:
                    return # Drop the bucket to prevent tracking squatted infrastructure

                if status == 200:
                    console.print(f"[bold red]  ! [CRITICAL] Open {provider_name} Bucket Discovered (Verified): {url}[/bold red]")
                    session_state.cloud_buckets.add(url)
                    
                    cmd = f"aws s3 ls s3://{candidate} --no-sign-request" if "s3.amazonaws" in url else f"curl -s {url} | xmlstarlet format"
                    print_briefing(
                        title="Unauthenticated Cloud Storage",
                        happening=f"Kestrel mathematically generated the bucket name '{candidate}', verified ownership, and received a 200 OK from {provider_name}.",
                        action="Immediately verify if the bucket contains Terraform states, PII, or internal source code.",
                        command=cmd,
                        style="red"
                    )
                    session_state.vulnerabilities.append({
                        "type": "VULN", "name": f"Open {provider_name} Bucket", "matched-at": url, "info": {"severity": "CRITICAL"}
                    })
                elif status in [403, 301, 302, 307] or "accessdenied" in text.lower():
                    console.print(f"[yellow]  * [INFO] Protected {provider_name} Bucket Found (Verified): {url}[/yellow]")
                    session_state.add_subdomain(url)
        except Exception:
            pass

async def deploy_cloud_sniper(session_state, base_name):
    sem = asyncio.Semaphore(100) # 100 concurrent checks
    connector = aiohttp.TCPConnector(limit=0, ssl=False)
    
    tasks = []
    async with aiohttp.ClientSession(connector=connector) as client:
        for mut in MUTATIONS:
            # Try appending and prepending (e.g., target-prod and prod-target)
            candidates = [f"{base_name}{mut}", f"{mut}-{base_name}" if mut else base_name]
            
            for candidate in set(candidates):
                if not candidate or candidate.startswith('-') or candidate.endswith('-'): continue
                
                for provider, template in PROVIDERS.items():
                    url = template.format(candidate)
                    tasks.append(check_bucket(client, sem, provider, url, session_state, candidate))
                    
        await asyncio.gather(*tasks)

def run_cloud(session, config):
    console.print("\n[bold blue]━━ PHASE 1.4: CLOUD STORAGE SNIPER (NATIVE AWS/GCP/AZURE HUNTING) ━━[/bold blue]")
    
    # Extract the core company name (e.g., 'bugcrowd.com' -> 'bugcrowd')
    domain = session.domain
    base_name = domain.split('.')[0] if len(domain.split('.')) > 1 else domain
    
    console.print(f"INFO     Generating permutations for base keyword: '{base_name}'...")
    console.print(f"INFO     Blasting AWS S3, Azure Blob, and GCP Storage architectures...")
    
    asyncio.run(deploy_cloud_sniper(session, base_name))
    
    console.print("  + Cloud Storage recon complete.")
