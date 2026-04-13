# KESTREL (The Targeted EASM Architecture)

> **"Hover passively. Calculate deterministically. Strike with absolute precision."**

Kestrel (formerly Sentinel-X) is not a vulnerability scanner; it is a deterministic, stateful attack surface management (EASM) architecture. Designed to bypass the limitations of third-party wrappers, regular expressions, and WAF tarpits, Kestrel is a 100% self-contained Python intelligence engine.

It abandons probabilistic guessing. Instead, it utilizes an embedded SQLite Write-Ahead Logging (WAL) core, native Local OAST daemons, Abstract Syntax Tree (AST) reverse-engineering, and Double-Blind temporal verification to extract mathematical proof of exploitation on modern Web 3.0 infrastructure.

---

## 🧠 Core Engineering Principles

* **Deterministic Exploitation:** Eliminates WAF hallucinations. If Cloudflare dynamically delays a request, Kestrel's Double-Blind Cache-Buster mathematically compares active payloads (`SLEEP(6)`) against control payloads (`SLEEP(0)`) to prove native backend execution.
* **The Stateful Graph Engine:** Replaces flat JSON dumps with a relational SQLite graph. The Delta Engine natively tracks temporal changes across the attack surface, dropping duplicate hosts and mapping the "Blast Radius" of critical bugs across shared root cookies.
* **Zero-Dependency Reconnaissance:** Eradicates supply-chain bottlenecks. No `subfinder` or `httpx`. Powered by `aiohttp`, `aiodns`, and native C-Ares, Kestrel directly carves SSL certificates, calculates BGP ASN origins, and executes 1,000+ concurrent UDP blasts entirely in memory.

---

## ⚔️ The Kestrel Kill-Chain

### Stage 1: Intelligence & Expansion
* **Phase 1: Hybrid Intelligence Engine:** Abandons brittle APIs. Uses a highly concurrent Circuit Breaker array to query OSINT, while simultaneously connecting to the target to rip Subject Alternative Names (SANs) directly from live SSL cryptography.
* **Phase 1.1: CDN Shield & Origin Unmasking:** Resolves apex domains, bypassing BGP/CIDR horizontal expansion if the target is shielded by Cloudflare or Fastly, saving hours of wasted port scanning.
* **Phase 1.3: Vertical DNS Bruteforcing:** Unleashes a high-velocity UDP blast using native `c-ares`. Automatically detects wildcard configurations (`*.target.com`) and establishes a cryptographic "Wildcard Sinkhole" to drop false positives before mapping undocumented shadow IT.

### Stage 2: Application Mapping & Resurrection
* **Phase 2: Favicon Fingerprinting:** Bypasses header-stripping WAFs. Fetches the raw `favicon.ico`, encodes it, and calculates its MurmurHash3 value to mathematically profile the exact backend framework (e.g., Spring Boot, Next.js).
* **Phase 2.2: The Ghost Archive & Skeleton Spider:** Queries the internet's memory (Wayback Machine/AlienVault) to resurrect unlinked, historical "Zombie" APIs. The live spider then maps the current perimeter, utilizing a structural "Skeleton Hash" depth-limiter to dynamically identify and drop infinite crawler traps (like calendars).
* **Phase 3: Cortex & Project Ghost:** Upgrades from regex to compiler-level SAST. Hunts for leaked `.map` files to completely reconstruct minified Webpack/React repositories in memory. Employs an Esprima AST (Abstract Syntax Tree) parser to execute Taint Tracking, concatenating hidden variables to reveal undocumented Shadow APIs.

### Stage 3: Surgical Exploitation
* **Phase 4: Targeted Nuclei Pipeline:** Stops blind spraying. Reads the exact Tech-Stack ontology from the SQLite Graph (Phase 2) and restricts Nuclei to firing *only* mathematically relevant CVEs (e.g., deploying only Nginx/PHP payloads against a profiled server).
* **Phase 5: Semantic Parameter Routing:** Upgrades the fuzzer from a sledgehammer to a scalpel. Semantically classifies parameters (`?user=` vs `?url=`) and routes the exact vulnerability class needed, injecting native cache-busters to bypass CDN edge rules.
* **Phase 8: The Local OAST Engine:** Total WAF evasion. Spawns a background `interactsh` daemon locally, generates unique RSA keypairs, injects them via the Fuzzer, and reads the local JSON logs to cryptographically prove Blind SSRF and Log4j execution without relying on intercepted third-party APIs.

### Stage 4: Contextual Delivery
* **Phase 7 & 6: Blast Radius & Delta Comm:** Evaluates if a compromised staging server shares a wildcard root domain with a High-Value Target (HVT), elevating the severity automatically before dispatching the clean delta report directly to the Operator's Telegram HUD.

---

## 🛡️ Operational Directives
Kestrel is an automated, enterprise-grade security evaluation framework. It is designed strictly for authorized penetration testing, bug bounty hunting on sanctioned programs, and advanced academic security research. The architect assumes no liability for the deployment or misuse of this framework.
