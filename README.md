# Kestrel

Autonomous External Attack Surface Management (EASM) and Continuous Penetration Testing Framework.

## Overview

Kestrel is a state-aware, highly targeted offensive security engine designed to map, unmask, and exploit hardened cloud perimeters. Engineered to operate with a zero-percent infrastructure false-positive rate, it strictly bounds execution logic to authorized targets, bypasses CDN Anycast traps via Layer-7 protocol validation, and executes asynchronous out-of-band (OAST) exploitation.

## Architecture & Execution Flow

Kestrel operates on a strict Directed Acyclic Graph (DAG) divided into five core stages:

### 1. Intelligence Gathering
* **BGP ASN Unmasking:** Native UDP DNS querying of global BGP tables to map target CIDR ranges.
* **Vertical DNS Bruteforcing:** High-velocity asynchronous resolution for shadow asset discovery.
* **Corporate Umbrella:** Multi-source horizontal pivoting utilizing SNI-forced SAN extraction, DOM telemetry tracking (GA/GTM), and RFC 9116 policies.
* **Cloud Storage Sniper:** Automated permutation hunting across AWS S3, GCP, and Azure blob architectures.

### 2. Infrastructure Bounding & Mapping
* **Scope Firewall:** Strict CNAME resolution filters that automatically sever execution chains against out-of-scope third-party SaaS environments (e.g., HubSpot, Zendesk).
* **Zero-Trust Layer-7 Port Scanning:** Eliminates cloud-edge hallucination (Vercel, Fastly, Cloudflare) by requiring explicit cryptographic or text-based protocol banners (e.g., `mysql_native_password`, `SSH-2.0`) rather than relying on TCP SYN completion.
* **Origin Unmasking:** Active JARM TLS fingerprinting correlated against Shodan, strictly validated via SNI certificate verification to prevent mass-scanning collateral damage.

### 3. Application Profiling
* **Phantom DOM:** Headless Chromium spidering with authentication state injection to map complex single-page applications.
* **Cortex Engine:** Webpack AST compilation and Shannon Entropy mathematics to extract hardcoded proprietary secrets and shadow APIs from minified JavaScript bundles.

### 4. Exploitation
* **Nuclei Integration:** Tech-stack targeted execution based on dynamically profiled server topologies.
* **CVE Sniper:** Surgical OAST payload injection for high-value architectural vulnerabilities (e.g., Log4Shell, Struts OGNL).
* **Omni-Fuzzer:** Semantic parameter routing that maps inputs to specific vulnerability classes, utilizing Chronos double-blind cache-busting for WAF evasion and State-Encoded OAST subdomains to catch asynchronous SSRF, XSS, and SQLi.

### 5. Telemetry & Reporting
* **Intelligence Decoder:** Parses local Interactsh daemon logs to decode state-injected DNS callbacks, achieving 100% confidence on blind vulnerabilities.
* **Blast Radius Matrix:** Contextual risk compilation mapping isolated vulnerabilities against lateral pivot paths.

## State Management

Kestrel is a stateful engine. It utilizes a local SQLite database for session continuity, ensuring that target environments are dynamically updated and historically tracked across execution runs without redundant network degradation.
