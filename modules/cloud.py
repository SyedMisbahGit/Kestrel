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

            async with client.get(url, timeout=5, ssl=False) as r:

                status = r.status

                text = await r.text()

                

                if "NoSuchBucket" in text or status == 404:

                    return

                

                if status == 200:

                    console.print(f"[bold red]  ! [CRITICAL] Open {provider_name} Bucket Discovered: {url}[/bold red]")

                    import sqlite3






                    session_state.cloud_buckets.add(url)

                    

                    cmd = f"aws s3 ls s3://{candidate} --no-sign-request" if "s3.amazonaws" in url else f"curl -s {url} | xmlstarlet format"

                    print_briefing(

                        title="Unauthenticated Cloud Storage",

                        happening=f"Kestrel mathematically generated the bucket name '{candidate}' and received a 200 OK from {provider_name}, indicating total exposure.",

                        action="Immediately verify if the bucket contains Terraform states, PII, or internal source code.",

                        command=cmd,

                        style="red"

                    )

                    session_state.vulnerabilities.append({

                        "type": "VULN", "name": f"Open {provider_name} Bucket", "matched-at": url, "info": {"severity": "CRITICAL"}

                    })

                elif status == 403 or "AccessDenied" in text:

                    console.print(f"[yellow]  * [INFO] Protected {provider_name} Bucket Found: {url}[/yellow]")

                    session_state.add_subdomain(url)

        except Exception:

            pass
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
