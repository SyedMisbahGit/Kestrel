import ssl
import socket
import requests
import logging
import re
import tldextract
import urllib3
from rich.console import Console

# Suppress insecure request warnings for raw IP/domain probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
log = logging.getLogger("rich")

def get_sni_cert_sans(domain):
    """Forces an SNI TLS handshake to extract the SAN array, bypassing generic CDN certs."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            # server_hostname enforces SNI
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                sans = []
                for ext in cert.get('subjectAltName', ()):
                    if ext[0] == 'DNS':
                        sans.append(ext[1])
                return sans
    except Exception:
        return []

def extract_dom_intelligence(domain):
    """Scrapes the frontend for legal footprints and marketing telemetry IDs."""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
    intel = {
        "trackers": [],
        "legal_entity": None
    }
    
    try:
        r = requests.get(f"https://{domain}", headers=headers, timeout=6, verify=False)
        text = r.text
        
        # 1. Telemetry & Tracker Extraction (GA4, GTM, Legacy UA)
        ga_ids = re.findall(r'G-[A-Z0-9]{8,12}', text)
        gtm_ids = re.findall(r'GTM-[A-Z0-9]{6,10}', text)
        ua_ids = re.findall(r'UA-\d{6,10}-\d{1,4}', text)
        intel["trackers"] = list(set(ga_ids + gtm_ids + ua_ids))
        
        # 2. Legal Footprint Extraction (Copyright)
        copy_match = re.search(r'(?:©|Copyright)\s*(?:[0-9]{4})?\s+([A-Za-z0-9\s\,\.\-]+?)(?:All Rights Reserved|<\/|\||\. )', text, re.IGNORECASE)
        if copy_match:
            candidate = copy_match.group(1).strip()
            # Filter out generic CMS footers
            if len(candidate) > 2 and "Theme" not in candidate and "WordPress" not in candidate:
                intel["legal_entity"] = candidate
                
    except Exception:
        pass
        
    return intel

def check_security_txt(domain):
    """Probes for RFC 9116 security.txt files to find official contact/scope data."""
    headers = {'User-Agent': 'Kestrel-EASM-Engine'}
    contacts = []
    try:
        r = requests.get(f"https://{domain}/.well-known/security.txt", headers=headers, timeout=5, verify=False)
        if r.status_code == 200 and "Contact:" in r.text:
            contacts = re.findall(r'Contact:\s*(.*)', r.text, re.IGNORECASE)
    except Exception:
        pass
    return list(set([c.strip() for c in contacts]))

def extract_root_domains(sans, base_domain):
    unique_roots = set()
    base_ext = tldextract.extract(base_domain)
    base_root = f"{base_ext.domain}.{base_ext.suffix}"
    
    for san in sans:
        san = san.lstrip('*.')
        ext = tldextract.extract(san)
        if not ext.suffix: continue
        root = f"{ext.domain}.{ext.suffix}"
        if root != base_root and root not in unique_roots:
            unique_roots.add(root)
            
    return list(unique_roots)

def run_umbrella(session, config):
    console.print("\n[bold blue]━━ PHASE 1.2: CORPORATE UMBRELLA (MULTI-SOURCE PIVOTING) ━━[/bold blue]")
    
    # Dynamically derive root domain
    subs = session.get_subdomains()
    if not subs: 
        console.print("  ! No targets available for Umbrella profiling.")
        return
        
    ext = tldextract.extract(subs[0])
    base_domain = f"{ext.domain}.{ext.suffix}"
    
    console.print(f"INFO     Executing Multi-Source Identity Extraction for {base_domain}...")
    
    # 1. Cryptographic Pivot (SNI SAN Extraction)
    sans = get_sni_cert_sans(base_domain)
    if sans:
        sibling_roots = extract_root_domains(sans, base_domain)
        if sibling_roots:
            console.print(f"  + [bold yellow]CRYPTOGRAPHIC PIVOT:[/bold yellow] Found {len(sibling_roots)} sibling root domains in SNI SAN array:")
            for root in sibling_roots:
                console.print(f"    - {root}")
    else:
        console.print("  * SNI Cryptographic Extraction failed (Strict CDN termination).")
        
    # 2. DOM Intelligence (Trackers & Legal)
    dom_intel = extract_dom_intelligence(base_domain)
    if dom_intel.get("legal_entity"):
        console.print(f"  + [bold green]LEGAL FOOTPRINT:[/bold green] {dom_intel['legal_entity']}")
    
    if dom_intel.get("trackers"):
        console.print(f"  + [bold yellow]TELEMETRY PIVOT:[/bold yellow] Extracted {len(dom_intel['trackers'])} unique tracker IDs for reverse-lookup:")
        for t in dom_intel["trackers"]:
            console.print(f"    - {t}")
            
    # 3. RFC 9116 Policy Extraction
    sec_contacts = check_security_txt(base_domain)
    if sec_contacts:
        console.print("  + [bold cyan]POLICY DISCLOSURE:[/bold cyan] Recovered official security contacts:")
        for c in sec_contacts:
            console.print(f"    - {c}")
            
    if not sans and not dom_intel.get("trackers") and not dom_intel.get("legal_entity"):
        console.print("  * Target is highly opaque. All horizontal pivoting heuristics failed.")

