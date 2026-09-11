# JOCKY Security-Resilience Research Framework: Threat Model & Safety Boundaries

## 1. Executive Summary & Purpose
The JOCKY Security-Resilience module (`resilience/`) provides a controlled, authorized scientific research framework designed to evaluate how code transformations affect security-control observation, signature matching, and heuristic telemetry.

The purpose is defensive understanding, compiler robustness, and authorized evaluation—**not** offensive weaponization.

---

## 2. Strict Safety Boundaries

The JOCKY architecture strictly prohibits and does **NOT** implement:
* **No EDR/AV Disabling:** No code paths attempt to disable, terminate, unhook, or tamper with security telemetry sensors or Endpoint Detection and Response agents.
* **No Kernel Callback Tampering:** No kernel drivers, BYOVD (Bring Your Own Vulnerable Driver) exploits, or SSDT/filter-driver unhooking mechanisms are permitted or implemented.
* **No Credential Access:** No LSASS dumping, SAM extraction, or credential scraping functionality exists.
* **No Covert C2 or Persistence:** No stealth rootkits, bootkits, or unauthorized persistent autoruns are deployed against unauthorized targets.
* **No Destructive Capabilities:** No data encryption (ransomware), data wiper, or system degradation routines exist.

---

## 3. Scientific Methodology & Architecture

```text
JOCKY IR
   ↓
Provenance Stamping / Canonical Formatting / Control-Flow Validation
   ↓
Transparent Validation Artifact & Cryptographic Hashing
   ↓
Isolated Lab Sandbox Evaluation
   ↓
Telemetry Observation & Event Measurement
   ↓
Comparative Research Report
```

### Supported Validation Operations
1. **Provenance Stamping:** Records an explicit lab-validation identifier.
2. **Canonical Formatting:** Normalizes whitespace and line endings without altering semantics.
3. **Control-Flow Validation:** Confirms that a validation run preserves the original executable IR.

The module rejects symbol renaming, padding and control-flow variations intended
to alter detection coverage.

---

## 4. Evaluated Metrics
* **Provenance Integrity:** Records the relationship between the source and validation artifact.
* **Structural Metrics:** Measures formatting-only size or line-count changes.
* **Detection Coverage:** Confirms a rule that matches the source also matches the validation artifact.
* **Performance Overhead:** Measures compilation and execution time impact of transformations.
