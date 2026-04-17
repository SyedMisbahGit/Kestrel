import yaml
import re
import os

def load_whitelist():
    if not os.path.exists('config/whitelist.yaml'):
        return []
    with open('config/whitelist.yaml', 'r') as f:
        data = yaml.safe_load(f)
        return [re.compile(pattern) for pattern in data.get('entropy_exclusions', [])]

WHITELIST_REGEXES = load_whitelist()

def is_whitelisted(string_literal: str) -> bool:
    """Checks if a string matches any known harmless framework patterns."""
    for regex in WHITELIST_REGEXES:
        if regex.search(string_literal):
            return True
    return False
