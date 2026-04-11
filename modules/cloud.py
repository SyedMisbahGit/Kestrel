import logging
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("rich")

def run_cloud(session, config):
    console.print("\n[bold blue]━━ PHASE 2.5: CLOUD RECON (GRAPH-BASED INTELLIGENCE) ━━[/bold blue]")
    
    live_hosts = session.get_live_hosts()
    if not live_hosts:
        console.print("WARNING  No hosts available for cloud footprinting.")
        return

    # 1. Define the Cloud Provider Signatures we are looking for
    cloud_signatures = {
        'AWS S3': ['Amazon S3', 's3.amazonaws.com'],
        'AWS EC2 / CloudFront': ['Amazon Web Services', 'Amazon CloudFront'],
        'Microsoft Azure': ['Microsoft Azure', 'Azure', 'azureedge.net'],
        'Google Cloud': ['Google Cloud', 'Google Cloud CDN', 'storage.googleapis.com'],
        'DigitalOcean': ['DigitalOcean', 'digitalocean.com'],
        'Heroku': ['Heroku', 'herokuapp.com'],
        'Vercel/Netlify': ['Vercel', 'Netlify']
    }

    cloud_assets = []

    # 2. Traverse the Intelligence Graph
    for host in live_hosts:
        if not isinstance(host, dict): continue
        
        url = host.get('url', '')
        tech = str(host.get('tech', [])).lower()
        cname = host.get('cname', '').lower() # Assuming HTTPX grabbed CNAMEs
        
        detected_providers = []
        for provider, sigs in cloud_signatures.items():
            if any(sig.lower() in tech or sig.lower() in cname for sig in sigs):
                detected_providers.append(provider)
        
        if detected_providers:
            cloud_assets.append({
                "url": url,
                "providers": ", ".join(detected_providers)
            })

    # 3. Output the Intelligence
    if cloud_assets:
        table = Table(title="☁️ EXPOSED CLOUD INFRASTRUCTURE", style="cyan", header_style="bold cyan")
        table.add_column("Asset URL", style="white")
        table.add_column("Cloud Provider Identity", style="yellow")
        
        for asset in cloud_assets:
            table.add_row(asset['url'], asset['providers'])
        console.print(table)
        console.print(f"  + Extracted {len(cloud_assets)} cloud footprints directly from the State Graph.")
    else:
        console.print("  + No identifiable cloud infrastructure exposed on live hosts.")

