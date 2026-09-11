# 🔍 JOCKY — Forensic Programming Language & Investigation Framework

> **"JOCKY transforms Computer and Network forensic analysis into a programmable, repeatable, and evidence-driven workflow."**

**Version:** 0.1.0  
**Test Status:** Automated test suite included; run `python -m pytest -q` after installing project dependencies.  
**Supported Platforms:** Windows 10/11/Server (AMD64), Ubuntu 22.04/24.04 LTS (x86_64, aarch64)

---

## 🎯 What is JOCKY?

JOCKY is a **domain-specific programming language and framework** engineered specifically for authorized computer and network digital forensics and incident response (DFIR). 

Instead of ad-hoc scripts and fragmented tools, investigators author formal, repeatable forensic workflows in the JOCKY DSL. The program is compiled through a multi-stage LLVM compiler pipeline and executed by a forensic runtime that normalizes artifacts into canonical schemas protected by deterministic SHA-256 cryptographic integrity.

---

## 🏗️ Core Architecture & Pipelines

```text
JOCKY Source (.jky)
        ↓
Lexer & Parser (Lark Earley CFG Grammar)
        ↓
Semantic Analysis & Symbol Resolution
        ↓
JOCKY Intermediate Representation (IR with BasicBlocks & CFG)
        ↓
LLVM IR Generation & Verification
        ↓
Native Compilation (.obj) & LLVM JIT Execution
        ↓
Runtime ABI (C-Linkage Callback Bridge)
        ↓
Forensic Runtime Engine & Platform Adapters (Windows & Linux)
        ↓
Collectors (Processes, Files, Network Sockets, Event Logs, Registry)
        ↓
Evidence Normalizer → CanonicalEvidenceItem Store
        ↓
Deterministic Cryptographic Integrity (Merkle Root SHA-256 Manifest)
        ↓
IOC Rule Engine (Configurable JSON) & Correlation Graph (No Blind PID Joins)
        ↓
Chronological Super-Timeline Builder (ISO-8601 UTC)
        ↓
Court-Admissible Reporting (HTML, JSON, PDF) & REST API / Dashboard
```

---

## 🚀 Quick Start

### 1. Prerequisites
* **Python $\ge$ 3.10** (tested on 3.10, 3.11, 3.12, 3.13)
* Windows (native Win32/Winreg) or Ubuntu/Linux (`/proc`, system logs)

### 2. Installation
```bash
# Clone the repository
git clone <repository_url> jocky
cd jocky

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate       # On Windows
# source venv/bin/activate    # On Linux

# Install dependencies in editable mode
pip install -e .[dev,windows]

# Run the environment doctor to verify dependencies
jocky doctor
```

### 3. Running JOCKY Programs
```bash
# Validate syntax and semantics
jocky check examples/runtime/process_scan.jky

# Compile through JOCKY IR to verified LLVM IR
jocky compile examples/runtime/process_scan.jky --emit-llvm

# Execute via LLVM JIT compiled runtime pipeline
jocky run examples/runtime/process_scan.jky

# Run an automated full-system forensic investigation
jocky investigate --case-id JOCKY-CASE-001

# Cryptographically verify evidence integrity
jocky verify ./jocky_output/manifest.json

# Generate court-admissible forensic reports
jocky report ./jocky_output/investigation_report.json --html --json
```

---

## 🖥️ Central Web Console & REST API

Launch the central server and web dashboard:
```bash
jocky-server
# Or: python -m backend.app.main
```
Open **http://localhost:8000/dashboard** in your browser.

### Available Dashboard Views
1. **Command Center (`/dashboard`):** Real-time investigation overview and telemetry.
2. **Investigations (`/investigations`):** Case management, severity filtering, tags.
3. **Endpoints (`/endpoints`):** Remote agent identities, heartbeats, and status.
4. **Evidence (`/evidence`):** Canonical normalized forensic items with SHA-256 digests.
5. **IOC Findings (`/iocs`):** Behavioral anomalies, LOLBins, and threat indicators.
6. **Relationships (`/relationships`):** Cross-artifact correlation graph.
7. **Super-Timeline (`/timeline`):** Chronological event sequencing.
8. **Reports (`/reports`):** Standalone verified HTML and JSON forensic reports.
9. **Audit Trail (`/audit`):** Cryptographically hashed chain-of-custody audit logs.
10. **System Health (`/health`):** Subsystem diagnostics (LLVM, DB, integrity).
11. **Settings (`/settings`):** Global security policies, RBAC roles, and configuration.

---

## 📝 JOCKY DSL Example

```jocky
// Authorized Host Investigation Script
TARGET SYSTEM;

CONFIG output_format = "JSON";

// Collect active evidence
SCAN PROCESSES;
SCAN NETWORK;
SCAN FILES;

// Forensic analysis
FIND IOC;
BUILD CORRELATIONS;
BUILD TIMELINE;

// Export verified outputs
EXPORT REPORT TO "host_investigation_report.html";
```

---

## 🔒 Security & Integrity Model

* **Deterministic Cryptography:** Individual evidence items and Merkle root hashes are computed using sorted-key canonical JSON representations.
* **Tamper Detection:** `jocky verify` detects altered data fields, missing items, or corrupt digests (`VALID`, `MODIFIED`, `CORRUPTED`).
* **Zero Hardcoded Credentials:** First-run admin setup dynamically locks after the initial `ADMIN` is provisioned.
* **Role-Based Access Control (RBAC):** Strict permissions enforced across `ADMIN`, `ANALYST`, and `VIEWER`.
* **Path Traversal Protection:** File upload filenames are stripped, sanitized, and boundary-checked using `os.path.realpath`.

---

## 📚 Technical Documentation

* [Architecture Overview](docs/ARCHITECTURE.md)
* [Language Specification](docs/JOCKY_LANGUAGE_SPEC.md)
* [JOCKY IR Design](docs/JOCKY_IR.md)
* [Runtime ABI Specification](docs/RUNTIME_ABI.md)
* [Development Guide](docs/DEVELOPMENT.md)
* [Testing Guide](docs/TESTING.md)
* [Security Guide](docs/SECURITY.md)
* [Deployment & Operations](docs/DEPLOYMENT.md)
* [Controlled Resilience Threat Model](docs/THREAT_MODEL_RESILIENCE.md)
