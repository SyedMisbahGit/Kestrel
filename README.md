# Kestrel

Autonomous External Attack Surface Management (EASM) and Continuous Threat Intelligence Pipeline.

## Overview

Kestrel is a state-aware, highly targeted offensive security engine designed to map, unmask, and exploit hardened cloud perimeters. Engineered for zero-infrastructure false positives, it strictly bounds execution logic to authorized targets, bypasses CDN Anycast traps via Layer-7 protocol validation, and feeds reconnaissance telemetry into a continuous machine learning pipeline.

## System Architecture

The framework operates via a serverless, continuously rotating execution grid, divided into the Core Engine and the Cloud Infrastructure.

### I. The Core Engine (DAG Pipeline)

The execution flow is governed by a strict Directed Acyclic Graph (DAG) utilizing local SQLite state management.

1.  **Reconnaissance & Bounding**
    * **Horizontal Pivoting:** Multi-source identity extraction utilizing SNI-forced SAN arrays, DOM telemetry tracking (GA4/GTM), and RFC 9116 policies.
    * **Scope Firewall:** Aggressive CNAME resolution filters that automatically sever execution chains against out-of-scope third-party SaaS environments.
    * **Zero-Trust Layer-7 Port Scanning:** Eliminates cloud-edge hallucinations (Vercel, Fastly, Cloudflare) by filtering explicit Anycast CIDRs and demanding strict cryptographic or text-based protocol banners (e.g., `mysql_native_password`) instead of TCP SYN completion.

2.  **Application Mapping**
    * **Phantom DOM:** Headless Chromium spidering with authentication state injection for complex single-page applications.
    * **Cortex Engine:** Webpack AST compilation and Shannon Entropy analysis to extract shadow APIs and hardcoded secrets from minified JavaScript bundles.

3.  **Out-of-Band Exploitation**
    * **Omni-Fuzzer:** Semantic parameter routing that maps inputs to specific vulnerability classes, utilizing Chronos double-blind cache-busting and State-Encoded OAST subdomains to capture asynchronous SSRF, Blind XSS, and SQLi.
    * **Intelligence Decoder:** Parses local Interactsh daemon logs to decode state-injected DNS callbacks, achieving 100% confidence validation on blind vulnerabilities.

### II. Cloud Infrastructure & Telemetry

Kestrel operates as a self-feeding, continuous intelligence loop rather than a static script.

* **The Grid (Orchestration):** Serverless cron execution via GitHub Actions. Ephemeral Ubuntu runners continuously rotate through target queues, ensuring unbiased network routing and operational stealth.
* **The Vault (Data Lake):** Immutable synchronization of structured EASM telemetry and vulnerability ledgers directly to an AWS S3 data lake upon pipeline completion.
* **The Brain (Machine Learning):** Authenticated webhooks trigger a downstream Hugging Face pipeline, ingesting the structured EASM data to train and fine-tune Random Forest anomaly detection models.
