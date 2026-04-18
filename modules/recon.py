import ssl
import socket
import concurrent.futures
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time

class HybridIntelligenceEngine:
    def __init__(self, target):
        self.target = target
        self.subdomains = set()
        self.session = self._build_robust_session()

    def _build_robust_session(self):
        """Builds an HTTP session that automatically handles 429s and 500s."""
        session = requests.Session()
        # Exponential backoff: 0.5s, 1s, 2s, 4s, 8s
        retries = Retry(total=5, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session

    def fetch_crtsh(self):
        print(f"[*] Querying CRT.sh for {self.target}...")
        try:
            res = self.session.get(f"https://crt.sh/?q=%25.{self.target}&output=json", timeout=15)
            if res.status_code == 200:
                for entry in res.json():
                    self.subdomains.add(entry['name_value'].lower())
                return True
        except Exception as e:
            print(f"[!] CRT.sh failed: {e}")
        return False

    def fetch_alienvault(self):
        print(f"[*] Fallback: Querying AlienVault OTX for {self.target}...")
        try:
            res = self.session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns", timeout=15)
            if res.status_code == 200:
                for entry in res.json().get('passive_dns', []):
                    self.subdomains.add(entry['hostname'].lower())
                return True
        except Exception as e:
            print(f"[!] AlienVault failed: {e}")
        return False
        
    def fetch_threatcrowd(self):
        print(f"[*] Fallback: Querying ThreatCrowd for {self.target}...")
        try:
            res = self.session.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target}", timeout=15)
            if res.status_code == 200:
                for entry in res.json().get('subdomains', []):
                    self.subdomains.add(entry.lower())
                return True
        except Exception as e:
            print(f"[!] ThreatCrowd failed: {e}")
        return False

    
    def fetch_native_san(self):
        print(f"[*] Extracting Native SANs from X.509 Certificate for {self.target}...")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    for san in cert.get('subjectAltName', []):
                        if san[0] == 'DNS':
                            self.subdomains.add(san[1].lower())
            return True
        except Exception as e:
            print(f"[!] Native SAN extraction failed: {e}")
        return False
def execute_recon(self):
        print("[*] Initiating Full-Spectrum Reconnaissance...")
        
        # Execute all zero-cost sources concurrently for maximum speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.fetch_crtsh),
                executor.submit(self.fetch_alienvault),
                executor.submit(self.fetch_threatcrowd),
                executor.submit(self.fetch_native_san)
            ]
            concurrent.futures.wait(futures)
            
        # Clean wildcard entries (*.target.com) and out-of-scope domains
        clean_subs = {sub.replace('*.', '') for sub in self.subdomains if self.target in sub}
        print(f"[+] Phase 1 Complete: Discovered {len(clean_subs)} unique subdomains.")
        return list(clean_subs)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        engine = HybridIntelligenceEngine(sys.argv[1])
        engine.execute_recon()
