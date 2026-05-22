"""Phase 2.3: Sensitive File Discovery — Kestrel"""

import asyncio
import aiohttp
import logging
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

SENSITIVE_FILES = [
    # Environment & Config
    ".env", ".env.local", ".env.production", ".env.staging", ".env.backup",
    ".env.example", ".env.dev", ".env.test", ".env.old",
    "env.js", "config.js", "config.json", "app.config.json",
    
    # Laravel
    ".env.laravel", "storage/logs/laravel.log",
    
    # WordPress
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old", "wp-config.php~",
    "wp-content/debug.log",
    
    # Git & VCS
    ".git/config", ".git/HEAD", ".gitignore",
    ".svn/entries", ".hg/hgrc",
    
    # Docker & CI
    "Dockerfile", "docker-compose.yml", ".dockerignore",
    ".gitlab-ci.yml", ".github/workflows/deploy.yml", "Jenkinsfile",
    
    # Backup & Database
    "backup.sql", "backup.tar.gz", "backup.zip", "backup.rar",
    "database.sql", "dump.sql", "export.sql",
    "db.sql", "db_backup.sql",
    
    # PHP Info & Debug
    "phpinfo.php", "info.php", "test.php", "php_info.php",
    "server-status", "server-info", "status", "health",
    "debug.log", "error.log", "error_log",
    
    # Common Config Files
    "config.php", "config.php.bak", "config.php.old",
    "configuration.php", "settings.php",
    "database.yml", "database.yaml",
    "credentials.json", "credentials.xml",
    "secrets.yml", "secrets.json",
    
    # AWS & Cloud
    ".aws/credentials", ".aws/config",
    
    # SSH & Keys
    "id_rsa", "id_rsa.pub", "id_ed25519", "id_ecdsa",
    "known_hosts", "authorized_keys",
    
    # Package Manager
    "package.json", "package-lock.json", "yarn.lock",
    "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    
    # Other
    "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    ".DS_Store", ".well-known/security.txt",
]

CRITICAL_PATTERNS = [
    "DB_PASSWORD", "DB_USERNAME", "APP_KEY", "APP_SECRET",
    "MAIL_PASSWORD", "MAIL_USERNAME", "SMTP_PASS",
    "AWS_SECRET", "AWS_ACCESS_KEY", "PRIVATE KEY",
    "REDIS_PASSWORD", "JWT_SECRET", "ENCRYPTION_KEY",
    "API_KEY", "API_SECRET", "AUTH_TOKEN",
    "PASSWORD=", "SECRET=", "TOKEN=", "CREDENTIALS",
]

async def probe_file(client, base_url, filepath):
    """Probe a single sensitive file and check for credential patterns."""
    url = f"{base_url.rstrip('/')}/{filepath}"
    try:
        async with client.get(url, timeout=8, ssl=False) as r:
            if r.status == 200:
                body = await r.text()
                if body and len(body) > 10:
                    findings = []
                    for pattern in CRITICAL_PATTERNS:
                        if pattern.lower() in body.lower():
                            findings.append(pattern)
                    
                    if findings:
                        return {
                            'url': url,
                            'file': filepath,
                            'size': len(body),
                            'patterns': findings,
                            'severity': 'CRITICAL' if any(p in ['DB_PASSWORD', 'APP_KEY', 'MAIL_PASSWORD', 'AWS_SECRET'] for p in findings) else 'HIGH'
                        }
                    else:
                        return {
                            'url': url,
                            'file': filepath,
                            'size': len(body),
                            'patterns': [],
                            'severity': 'INFO'
                        }
    except Exception:
        pass
    return None

async def probe_host(client, host_url):
    """Probe all sensitive files on a single host."""
    results = []
    sem = asyncio.Semaphore(5)
    
    async def probe_with_limit(f):
        async with sem:
            return await probe_file(client, host_url, f)
    
    tasks = [probe_with_limit(f) for f in SENSITIVE_FILES]
    responses = await asyncio.gather(*tasks)
    
    for r in responses:
        if r:
            results.append(r)
    
    return results

def run_sensitive_files(session, config):
    """Phase 2.3: Probe all live hosts for sensitive exposed files."""
    console.print("\n[bold blue]━━ PHASE 2.3: SENSITIVE FILE DISCOVERY ━━[/bold blue]")
    
    hosts = session.get_live_hosts()
    if not hosts:
        console.print("  * No live hosts to probe.")
        return
    
    urls = []
    for h in hosts:
        if isinstance(h, dict):
            url = h.get('url', '')
        else:
            url = str(h)
        if url and url.startswith('http'):
            urls.append(url)
    
    if not urls:
        console.print("  * No valid URLs to probe.")
        return
    
    console.print(f"INFO     Probing {len(SENSITIVE_FILES)} sensitive files across {len(urls)} hosts...")
    
    async def run():
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as client:
            all_results = []
            for url in urls:
                results = await probe_host(client, url)
                all_results.extend(results)
            return all_results
    
    findings = asyncio.run(run())
    
    if not findings:
        console.print("  + No sensitive files discovered.")
        return
    
    critical_count = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high_count = sum(1 for f in findings if f['severity'] == 'HIGH')
    info_count = sum(1 for f in findings if f['severity'] == 'INFO')
    
    console.print(f"  + Discovered {len(findings)} exposed files:")
    console.print(f"    ├─ CRITICAL: {critical_count}")
    console.print(f"    ├─ HIGH: {high_count}")
    console.print(f"    └─ INFO: {info_count}")
    
    for f in findings:
        if f['severity'] in ['CRITICAL', 'HIGH']:
            console.print(f"\n[bold red]  ! [{f['severity']}] {f['url']}[/bold red]")
            console.print(f"    Size: {f['size']} bytes")
            console.print(f"    Credentials found: {', '.join(f['patterns'])}")
            
            session.vulnerabilities.append({
                "type": "VULN",
                "name": f"Exposed Sensitive File: {f['file']}",
                "matched-at": f['url'],
                "info": {
                    "severity": f['severity'],
                    "description": f"Found {len(f['patterns'])} credential patterns: {', '.join(f['patterns'][:5])}",
                    "phase": "sensitive_files",
                    "file_size": f['size']
                }
            })
        else:
            console.print(f"[dim]    └─ [INFO] {f['url']} ({f['size']} bytes)[/dim]")
