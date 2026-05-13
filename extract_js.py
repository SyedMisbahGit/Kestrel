import requests
from bs4 import BeautifulSoup
import re

session = requests.Session()
session.headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
}

# Get the main page
r = session.get('https://store.coupa.com')
soup = BeautifulSoup(r.text, 'html.parser')

# Extract all script sources
for script in soup.find_all('script', src=True):
    js_url = script['src']
    if not js_url.startswith('http'):
        js_url = f"https://store.coupa.com{js_url}" if js_url.startswith('/') else f"https://store.coupa.com/{js_url}"
    
    try:
        js_content = session.get(js_url).text
        # Check for secrets
        if any(x in js_content.lower() for x in ['apiKey', 'secret', 'token', 'password', 'mongodb:', 'postgres:', 'redis:']):
            print(f"\n[!] Potential secrets in: {js_url}")
            # Print lines with secrets
            for line in js_content.split('\n'):
                if re.search(r'(apiKey|secret|token|password|mongodb:|postgres:|redis:)', line, re.I):
                    print(f"  {line.strip()[:200]}")
    except:
        pass
