import ssl
import socket
import json
import requests
import logging
from urllib.parse import urlparse
from rich.console import Console
import tldextract

console = Console()
log = logging.getLogger("rich")

def get_live_cert_data(domain):
    """Extracts live SANs and Org data from the target's SSL/TLS certificate."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract Subject Organization
                org_name = None
                for sub in cert.get('subject', ()):
                    for key, val in sub:
                        if key == 'organizationName' and val.lower() not in ['cloudflare, inc.', 'amazon.com, inc.', 'let\'s encrypt']:
                            org_name = val
                
                # Extract SANs
                sans = []
                for ext in cert.get('subjectAltName', ()):
                    if ext[0] == 'DNS':
                        sans.append(ext[1])
                        
                return org_name, sans
    except Exception:
        return None, []

def get_historical_org(domain):
    """Queries crt.sh for legacy certificates to find historical Organization names."""
    try:
        req = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10)
        if req.status_code != 200: return None
        
        data = req.json()
        for entry in data:
            issuer = entry.get('issuer_name', '').lower()
            name_val = entry.get('name_value', '')
            
            # Skip modern automated issuers
            if 'let\'s encrypt' in issuer or 'cloudflare' in issuer or 'amazon' in issuer:
                continue
                
            # If we find a legacy cert, we'd ideally fetch the full cert to get the O= field.
            # For speed, if the issuer is a classic CA (DigiCert, Symantec, GlobalSign), 
            # we log it as a potential vector for deeper manual reverse-whois.
            if any(ca in issuer for ca in ['digicert', 'symantec', 'globalsign', 'sectigo']):
                return f"[Legacy CA Found: {issuer.split(',')[0].strip('CN=')}]"
                
        return None
    except Exception:
        return None

def extract_root_domains(sans, base_domain):
    """Filters a list of SANs to find unique root domains different from the target."""
    unique_roots = set()
    base_ext = tldextract.extract(base_domain)
    base_root = f"{base_ext.domain}.{base_ext.suffix}"
    
    for san in sans:
        san = san.lstrip('*.')
        ext = tldextract.extract(san)
        if not ext.suffix: continue # Invalid TLD
        
        root = f"{ext.domain}.{ext.suffix}"
        if root != base_root and root not in unique_roots:
            unique_roots.add(root)
            
    return list(unique_roots)

def run_umbrella(session, config):
    console.print("\n[bold blue]━━ PHASE 1.2: CORPORATE UMBRELLA (CRYPTOGRAPHIC PIVOTING) ━━[/bold blue]")
    
    base_domain = session.target
    console.print(f"INFO     Extracting X.509 Cryptographic Identity for {base_domain}...")
    
    # 1. Live Certificate Analysis
    org_name, sans = get_live_cert_data(base_domain)
    
    # 2. Historical Fallback
    if not org_name:
        console.print("  * No proprietary Corporate Identity found in live SSL (likely DV/CDN).")
        console.print("INFO     Mining historical certificate transparency logs for legacy identities...")
        legacy_ca = get_historical_org(base_domain)
        if legacy_ca:
            console.print(f"  + Historical footprint detected via {legacy_ca}. Target previously utilized OV/EV certificates.")
        else:
            console.print("  * No legacy corporate identity recovered.")
    else:
        console.print(f"  + Cryptographic Identity Confirmed: [bold green]{org_name}[/bold green]")
        # Future implementation: Query CRT.sh for ALL certs matching this org_name
        
    # 3. Horizontal SAN Expansion
    if sans:
        sibling_roots = extract_root_domains(sans, base_domain)
        if sibling_roots:
            console.print(f"  + [bold yellow]HORIZONTAL PIVOT:[/bold yellow] Found {len(sibling_roots)} sibling root domains bundled in SAN array:")
            for root in sibling_roots:
                console.print(f"    - {root}")
        else:
            console.print("  + SAN array analyzed. No sibling root domains found.")
    else:
        console.print("  * Failed to extract SAN array from live certificate.")

