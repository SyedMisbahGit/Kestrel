#!/usr/bin/env python3
"""Register a user on Coupa's Salesforce Support Community"""
import requests
import re

session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
})

BASE = "https://support.coupa.com"

# Step 1: Get the self-registration page and extract the Aura context
r = session.get(f"{BASE}/s/login/SelfRegister?language=en_US")

# Extract the Aura fwuid and app details from the page
fwuid_match = re.search(r'"fwuid"%3A%22([^%"]+)', r.text)
if fwuid_match:
    fwuid = fwuid_match.group(1)
    print(f"[+] Aura FWUID: {fwuid}")

# Step 2: The self-registration form is an Aura component
# The actual registration endpoint is typically:
# /s/sfsites/aura?r=1&aura.SelfRegisterController.execute=1
# We need to POST the registration data with proper Aura format

# Step 3: Extract the Aura context cookie
aura_cookies = session.cookies.get_dict()
print(f"[+] Session cookies: {list(aura_cookies.keys())}")

# Step 4: The self-reg Aura action
# The component is siteforce:loginApp2 with selfRegister flow
# POST format for Aura:
register_url = f"{BASE}/s/sfsites/aura"
register_data = {
    "message": {
        "actions": [{
            "id": "1",
            "descriptor": "serviceComponent://ui.force.components.controllers.community.selfRegister.SelfRegisterController.executeSelfRegister",
            "callingDescriptor": "UNKNOWN",
            "params": {
                "firstName": "Security",
                "lastName": "Researcher",
                "email": "security.test@example.com",
                "password": "CoupaTest2026!Secure",
                "confirmPassword": "CoupaTest2026!Secure",
                "companyName": "Security Research",
                "country": "US"
            }
        }]
    },
    "aura.context": {
        "mode": "PROD",
        "fwuid": fwuid if fwuid_match else "ZkJhOVpLN2NZQkJrd2NWd3pMcnFOdzJEa1N5enhOU3R5QWl2VzNveFZTbGcxMy4tMjE0NzQ4MzY0OC4xMzEwNzIwMA",
        "app": "siteforce:loginApp2",
        "loaded": {},
        "dn": [],
        "globals": {},
        "uad": False
    },
    "aura.pageURI": "/s/login/SelfRegister?language=en_US",
    "aura.token": "null"
}

print(f"[*] Attempting self-registration...")
r = session.post(
    register_url,
    json=register_data,
    headers={
        'Content-Type': 'application/json',
        'X-User-Agent': 'Salesforce/1.0'
    }
)
print(f"[+] Response: {r.status_code}")
print(f"[+] Body: {r.text[:500]}")
