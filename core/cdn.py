import ipaddress

# Core CDN and Cloud Edge-Node CIDR Blocks
CDN_CIDRS = [
    # Cloudflare Core Ranges
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Fastly Core Ranges (Truncated for speed)
    "151.101.0.0/16", "199.232.0.0/16",
    # AWS CloudFront Edge (Truncated)
    "13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14"
]

def is_cdn_ip(ip_str: str) -> bool:
    """Evaluates if an IP address belongs to a known CDN provider."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in CDN_CIDRS:
            if ip in ipaddress.ip_network(cidr):
                return True
        return False
    except ValueError:
        return False
