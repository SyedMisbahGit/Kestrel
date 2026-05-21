"""Payload Library Loader & Context-Aware Router for Kestrel Phase 6."""

import json
import os
from typing import Dict, List, Optional

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

PARAMETER_TO_VULN_MAP = {
    "id": ["sqli"], "user_id": ["sqli"], "product_id": ["sqli"],
    "query": ["sqli", "xss"], "search": ["sqli", "xss"],
    "filter": ["sqli"], "sort": ["sqli"], "limit": ["sqli"],
    "offset": ["sqli"], "username": ["sqli", "auth_bypass"],
    "password": ["auth_bypass"], "email": ["sqli"],
    "url": ["ssrf", "open_redirect"], "redirect": ["ssrf", "open_redirect"],
    "redirect_url": ["ssrf", "open_redirect"], "callback": ["ssrf"],
    "webhook": ["ssrf"], "return_url": ["ssrf", "open_redirect"],
    "next": ["open_redirect"], "continue": ["open_redirect"],
    "link": ["ssrf"], "path": ["lfi", "ssrf"], "file": ["lfi"],
    "document": ["lfi"], "template": ["ssti", "lfi"],
    "cmd": ["cmdi"], "exec": ["cmdi"], "command": ["cmdi"],
    "run": ["cmdi"], "ping": ["cmdi"], "host": ["cmdi"],
    "ip": ["cmdi"], "domain": ["cmdi"],
    "q": ["xss"], "message": ["xss"], "comment": ["xss"],
    "name": ["xss"], "title": ["xss"], "description": ["xss"],
    "keyword": ["xss"], "msg": ["xss"], "term": ["xss"],
    "data": ["xxe", "ssti"], "xml": ["xxe"], "input": ["ssti"],
    "preview": ["ssti"], "content": ["xss", "ssti"],
    "token": ["jwt"], "jwt": ["jwt"], "session": ["jwt"],
    "auth": ["auth_bypass"], "login": ["auth_bypass"],
}

TECH_STACK_TO_DIALECT = {
    "mysql": {"sqli": "mysql"},
    "mariadb": {"sqli": "mysql"},
    "postgresql": {"sqli": "postgresql"},
    "mssql": {"sqli": "mssql"},
    "oracle": {"sqli": "oracle"},
    "sqlite": {"sqli": "sqlite"},
    "php": {"sqli": "mysql", "lfi": "linux", "cmdi": "linux"},
    "nginx": {"lfi": "linux", "cmdi": "linux"},
    "apache": {"lfi": "linux", "cmdi": "linux"},
    "iis": {"lfi": "windows", "cmdi": "windows"},
    "java": {"ssti": "freemarker", "sqli": "generic"},
    "spring": {"ssti": "freemarker", "sqli": "generic"},
    "python": {"ssti": "jinja2"},
    "flask": {"ssti": "jinja2"},
    "django": {"ssti": "jinja2"},
    "ruby": {"ssti": "generic"},
    "node": {"ssti": "generic"},
    "aws": {"ssrf": "aws_metadata"},
    "gcp": {"ssrf": "gcp_metadata"},
    "azure": {"ssrf": "azure_metadata"},
    "linux": {"cmdi": "linux", "lfi": "linux"},
    "windows": {"cmdi": "windows", "lfi": "windows"},
}

def load_payload_library() -> Dict:
    """Load all payload JSON files into memory."""
    library = {}
    for filename in os.listdir(PAYLOAD_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(PAYLOAD_DIR, filename)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    category = data.get('category', filename.replace('.json', ''))
                    library[category] = data
            except (json.JSONDecodeError, KeyError):
                continue
    return library

def classify_parameter(param_name: str) -> List[str]:
    """Map parameter names to vulnerability types."""
    p = param_name.lower()
    return PARAMETER_TO_VULN_MAP.get(p, ["sqli", "xss"])

def route_payloads_for_param(param_name: str, tech_stacks: List[str], oast_id: str) -> List[Dict]:
    """Select payloads based on parameter name and detected tech stack."""
    library = load_payload_library()
    vuln_types = classify_parameter(param_name)
    
    routed = []
    
    for vuln_type in vuln_types:
        if vuln_type not in library:
            continue
        
        payload_data = library[vuln_type]
        dialects = payload_data.get('dialects', {})
        
        for tech in tech_stacks:
            tech_lower = tech.lower().replace('/', ' ').replace('_', ' ')
            dialect_map = TECH_STACK_TO_DIALECT.get(tech_lower, {})
            preferred_dialect = dialect_map.get(vuln_type)
            
            if preferred_dialect and preferred_dialect in dialects:
                for entry in dialects[preferred_dialect]:
                    payload = entry.get('payload', '')
                    payload = payload.replace('{oast_id}', oast_id)
                    payload = payload.replace('{delay}', str(entry.get('delay', 5)))
                    routed.append({
                        'vuln_type': vuln_type,
                        'dialect': preferred_dialect,
                        'name': entry.get('name'),
                        'payload': payload,
                        'oast': entry.get('oast', False),
                        'headers': entry.get('headers', {}),
                        'type': entry.get('type'),
                    })
        
        if 'generic' in dialects:
            for entry in dialects['generic']:
                payload = entry.get('payload', '')
                payload = payload.replace('{oast_id}', oast_id)
                payload = payload.replace('{delay}', str(entry.get('delay', 5)))
                routed.append({
                    'vuln_type': vuln_type,
                    'dialect': 'generic',
                    'name': entry.get('name'),
                    'payload': payload,
                    'oast': entry.get('oast', False),
                    'headers': entry.get('headers', {}),
                    'type': entry.get('type'),
                })
    
    return routed

def get_payload_count() -> Dict[str, int]:
    """Return count of payloads per vulnerability type."""
    library = load_payload_library()
    counts = {}
    for category, data in library.items():
        total = 0
        for dialect_entries in data.get('dialects', {}).values():
            total += len(dialect_entries)
        counts[category] = total
    return counts
