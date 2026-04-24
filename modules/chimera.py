import base64
import json
import hmac
import hashlib

class JWTSniper:
    def __init__(self):
        # A micro-dictionary of the most common weak JWT secrets
        self.weak_secrets = [b'secret', b'123456', b'password', b'admin', b'secret123', b'dev', b'test']

    def analyze_token(self, target_url, token):
        vulnerabilities = []
        parts = token.split('.')
        if len(parts) != 3:
            return vulnerabilities

        try:
            # Fix Base64 padding
            header_b64 = parts[0] + '=' * (-len(parts[0]) % 4)
            payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)

            header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())

            print(f"  [*] CHIMERA: Analyzing JWT for {target_url} (alg: {header.get('alg', 'UNKNOWN')})")

            # Attack 1: Unsecured Algorithm (alg: none)
            if header.get('alg', '').lower() == 'none':
                print(f"  [+] [CRITICAL] JWT accepts 'alg: none' signature bypass!")
                vulnerabilities.append({
                    "type": "VULN",
                    "name": "JWT Signature Bypass (alg: none)",
                    "matched-at": target_url,
                    "info": {"severity": "CRITICAL", "description": "The server accepts forged tokens without a cryptographic signature."}
                })

            # Attack 2: Weak HMAC Secret Bruteforce
            if header.get('alg', '').upper() == 'HS256':
                for secret in self.weak_secrets:
                    message = (parts[0] + "." + parts[1]).encode()
                    sig = hmac.new(secret, message, hashlib.sha256).digest()
                    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')

                    if sig_b64 == parts[2]:
                        print(f"  [+] [CRITICAL] JWT HMAC Secret Cracked: '{secret.decode()}'")
                        vulnerabilities.append({
                            "type": "VULN",
                            "name": "JWT Weak Secret Cracked",
                            "matched-at": target_url,
                            "info": {"severity": "CRITICAL", "description": f"The JWT signature was cracked using the weak secret: {secret.decode()}. Full ATO possible."}
                        })
                        break
        except Exception:
            pass

        return vulnerabilities
