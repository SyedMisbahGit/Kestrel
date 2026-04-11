# SENTINEL-X (Codename: Arbiter v2.0)

> **"A Zero-Dependency, Native Python Intelligence Apparatus for Modern Attack Surface Management."**

Sentinel-X is not a scanner; it is a stateful decision engine. Designed to bypass the limitations of third-party wrappers, regular expressions, and blind fuzzing, Sentinel-X is a 100% self-contained Python architecture. 

It does not rely on Go binaries or shell sub-processes. Instead, it utilizes an embedded SQLite Write-Ahead Logging (WAL) core, Abstract Syntax Tree (AST) compilation, and native asynchronous network pools to hunt for vulnerabilities on modern Web 3.0 infrastructure.

---

## 🧠 The Masterclass Architecture

* **The Stateful Graph Engine:** Replaces flat JSON dumps with a relational SQLite graph. Utilizing Deterministic MD5 Hashing and `UPSERT` diffing, the Delta Engine natively tracks temporal changes across the attack surface, only alerting on modified or new infrastructure.
* **Zero-Dependency Native I/O:** Eradicates supply chain risks. No `httpx`, no `subfinder`, no `cloud_enum`. Powered by `aiohttp` and `asyncio`, Sentinel-X handles its own concurrency, network pooling, and heuristic tech-fingerprinting natively in memory.
* **Asynchronous Backpressure & OOM Protection:** Engineered with strict `asyncio.Semaphore` governors and chunked event loops. It can process 100,000+ assets simultaneously without causing Out-of-Memory (OOM) failures or OS socket exhaustion.
* **Graceful SIGINT Interception:** The orchestrator intercepts `Ctrl+C` commands, safely draining active TCP connections and flushing the WAL cache to prevent database corruption during manual overrides.

---

## ⚔️ The Kill-Chain Pipeline

### Phase 1: Native OSINT & Intelligence Gathering
* **The Omniscient Archivist:** Concurrent, in-memory scrapers querying `crt.sh`, `HackerTarget`, `AlienVault`, and `URLScan.io` via pure async Python—eliminating the need for third-party reconnaissance binaries.
* **Horizontal & Infrastructure Forensics:** Maps ASN/CIDR blocks, hunts for dangling NS pointers (Subdomain Takeovers), and extracts exposed verification tokens.

### Phase 2: Active Profiling & Surface Mapping
* **Native Probing & The Stealth Governor:** A custom HTTP engine utilizing exponential backoff and rate-limiting. Employs "Wappalyzer Lite" logic to heuristically fingerprint Nginx, React, AWS, and Next.js entirely in memory.
* **The AST Spider:** Maps standard HTML links while aggressively extracting hidden Webpack and React JavaScript bundles to feed the Neural Cortex.
* **Graph-Based Cloud Recon:** Instantly cross-references the mapped SQLite graph to identify exposed AWS, Azure, and GCP infrastructure without sending a single noisy brute-force request.

### Phase 3: The AST Neural Cortex (Offensive SAST)
* **Abstract Syntax Tree Extraction:** Abandons traditional Regex. The Cortex downloads JS bundles and compiles them into logical execution trees in memory. By mathematically resolving variable concatenations and performing Static Taint Analysis, it extracts the "Shadow APIs" that developers forgot they exposed.

### Phase 4: The Weaponized Nuclei Pipeline
* **Direct-to-RAM Execution:** The only remaining external dependency, retained strictly for its crowdsourced CVE templates. Feeds both root hosts and AST-extracted Shadow APIs directly into Nuclei's standard input stream. Unleashes deep-scan templates (`-tags exposure,vulnerabilities,misconfiguration`) while catching silent binary crashes.

### Phase 5: The Native API Fuzzer (Polyglot & Chronos)
* **Semantic Swagger Engine:** Actively hunts for exposed `openapi.json` and `swagger.json` blueprints, dynamically expanding the attack surface by parsing undocumented backend routes.
* **Polyglot Payload Injection:** Recognizes that modern Web 3.0 APIs reject standard `GET` attacks. Automatically crafts structural JSON bodies (`{"email": "admin'--"}`) to inject SQLi, LFI, and XSS natively via `POST`.
* **Chronos (Temporal Blind Fuzzing):** Bypasses modern ORMs (like Prisma/Sequelize) that swallow database errors. Injects temporal payloads (`pg_sleep(6)`) and uses high-precision perf-counters to measure network time dilation, catching invisible blind vulnerabilities.

### Phase 6: The Heuristic Brain (HUD)
* **Threat Prioritization Matrix:** Eliminates alert fatigue. The decision engine analyzes HTTP status codes, tech stacks, and URL context to automatically route findings. It knows an exposed Pre-Production API is a **P1 Critical**, while a dead 404 Webmail server is **P4 Noise**.

---

## 🛡️ Operational Directives
Sentinel-X is an automated security evaluation tool. It is designed strictly for authorized penetration testing, bug bounty hunting on sanctioned programs, and academic security research. The architect assumes no liability for the misuse of this framework.
