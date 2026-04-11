import subprocess
import json
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- THE TECH-TO-TAG MATRIX ---
TECH_TAG_MAP = {
    "wordpress": "wordpress",
    "php": "php",
    "nginx": "nginx",
    "apache": "apache",
    "cloudflare": "cloudflare",
    "spring boot": "springboot",
    "jenkins": "jenkins",
    "tomcat": "tomcat",
    "next.js": "nextjs",
    "react": "react",
    "vue.js": "vue",
    "laravel": "laravel",
    "gitlab": "gitlab",
    "bootstrap": "bootstrap",
    "jquery": "jquery"
}

def run_nuclei(session, config):
    console.print("\n[bold blue]━━ PHASE 4: THE NUCLEI PIPELINE (TECH-STACK TARGETED) ━━[/bold blue]")

    targets = set()
    detected_techs = set()
    
    # 1. Extract Intelligence from State Graph
    for h in session.get_live_hosts():
        if isinstance(h, dict):
            if 'url' in h: targets.add(h['url'])
            if 'tech' in h:
                for t in h['tech']: detected_techs.add(t.lower())
        elif isinstance(h, str): targets.add(h)
        
    for u in session.get_crawled_urls():
        if isinstance(u, dict) and 'url' in u: targets.add(u['url'])
        elif isinstance(u, str): targets.add(u)

    if not targets:
        console.print("WARNING  No targets available for the Nuclei pipeline. Skipping.")
        return

    # 2. Construct the Targeted Tag Payload
    nuclei_tags = set(["exposure", "misconfig"]) # Base tags we always enforce
    
    for tech in detected_techs:
        for key, tag in TECH_TAG_MAP.items():
            if key in tech:
                nuclei_tags.add(tag)
                
    tag_string = ",".join(nuclei_tags)
    
    console.print(f"INFO     Extracted Target Ontology: {', '.join(detected_techs) if detected_techs else 'Unknown'}")
    console.print(f"INFO     Deploying Targeted Nuclei Engine with tags: [cyan]{tag_string}[/cyan]")
    console.print(f"INFO     Piping {len(targets)} targets into memory stream...")
    
    # Pre-Flight: Force Template Update
    subprocess.run(["nuclei", "-ut", "-silent"], capture_output=True)

    target_list = "\n".join(targets)
    
    # Execute with precise tags
    cmd = [
        "nuclei", "-silent", "-json", 
        "-tags", tag_string,
        "-severity", "low,medium,high,critical",
        "-c", "50"
    ]

    try:
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=target_list)

        if stderr and "error" in stderr.lower():
            log.error(f"Nuclei Engine Error: {stderr.strip()}")

        vulns = []
        for line in stdout.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                vulns.append(data)
                
                info = data.get('info', {})
                sev = info.get('severity', 'info').upper()
                name = info.get('name', 'Unknown')
                url = data.get('matched-at', '')
                color = "red" if sev in ["HIGH", "CRITICAL"] else "yellow" if sev == "MEDIUM" else "cyan"
                console.print(f"[{color}]  ! [{sev}] {name} -> {url}[/{color}]")
            except json.JSONDecodeError:
                pass

        if vulns:
            session.vulnerabilities.extend(vulns)
            console.print(f"  + Nuclei pipeline complete. {len(vulns)} vulnerabilities mapped into State Graph.")
        else:
            console.print("  + Nuclei pipeline complete. No automated vulnerabilities detected.")

    except Exception as e:
        log.error(f"Nuclei execution failed: {e}")
