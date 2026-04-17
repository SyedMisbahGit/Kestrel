from urllib.parse import urlparse

def parse_target(url: str):
    """
    Safely extracts the protocol, host, and port from any URL, 
    natively supporting IPv4, Domains, and IPv6 bracket notation.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        scheme = parsed.scheme
        
        # Handle IPv6 with RFC 3986 brackets
        if '[' in netloc and ']' in netloc:
            host = netloc[netloc.find('[')+1 : netloc.find(']')]
            port_str = netloc.split(']:')[-1] if ']:' in netloc else None
        else:
            # Handle standard IPv4 / Domains
            parts = netloc.split(':')
            host = parts[0]
            port_str = parts[1] if len(parts) > 1 else None

        # Fallback to default ports if none specified
        if port_str and port_str.isdigit():
            port = int(port_str)
        else:
            port = 443 if scheme == 'https' else 80

        return {
            "scheme": scheme,
            "host": host,
            "port": port,
            "base_url": f"{scheme}://[{host}]:{port}" if ':' in host else f"{scheme}://{host}:{port}"
        }
    except Exception as e:
        return None
