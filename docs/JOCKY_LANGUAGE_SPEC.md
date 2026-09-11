# JOCKY Language Specification

**Version:** 0.2.0 (Stage 2 Specification)  
**Status:** Active Implemented DSL  
**File Extension:** `.jky`  

---

## 1. Overview

JOCKY is a cross-platform domain-specific language (DSL) designed for computer and network forensic triage and investigation. It provides declarative primitives for orchestrating evidence collection, correlation, indicator-of-compromise (IOC) scanning, timeline generation, and report export.

---

## 2. Program Structure

A JOCKY script consists of a sequence of statements.

1. **Target Declaration:** Every forensic investigation script that performs collection or analysis operations must begin with a `TARGET` declaration.
2. **Statement Termination:** All simple statements must terminate with a semicolon (`;`). Control flow blocks (`IF`, `FOREACH`) use curly braces (`{ ... }`) and do not require trailing semicolons.
3. **Execution Order:** Statements execute top-to-bottom within their lexical scopes.

```jocky
// Basic Program Structure
TARGET SYSTEM;

SET output_format = "JSON";

SCAN PROCESSES;
SCAN NETWORK;

FIND IOC;
BUILD TIMELINE;

EXPORT REPORT TO "triage_report";
```

---

## 3. Lexical Grammar

### 3.1 Whitespace and Comments

*   **Whitespace:** Spaces, horizontal tabs, carriage returns, and newlines serve as token delimiters and are otherwise ignored.
*   **Comments:** Single-line comments start with `//` and extend to the end of the line:
    ```jocky
    // This is a single-line comment
    SCAN PROCESSES; // Collect active processes
    ```

### 3.2 Identifiers

Identifiers start with an ASCII letter or underscore (`_`), followed by any number of alphanumeric characters or underscores:
*   Regex: `[a-zA-Z_][a-zA-Z0-9_]*`
*   Identifiers are case-sensitive.

### 3.3 Keywords

The following reserved words cannot be used as variable identifiers:

| Category | Keywords |
|---|---|
| Target & Environment | `TARGET`, `SYSTEM`, `REMOTE`, `ALL` |
| Collectors & Artifacts | `SCAN`, `WHERE`, `FIND`, `BUILD`, `EXPORT`, `TO` |
| Variable & Configuration | `SET`, `LET`, `FILTER` |
| Control Flow | `IF`, `THEN`, `ELSE`, `FOREACH`, `IN` |
| Logical Operators | `AND`, `OR`, `NOT`, `CONTAINS` |
| Literals | `TRUE`, `FALSE`, `true`, `false` |
| Evidence Sources | `PROCESSES`, `FILES`, `NETWORK`, `EVENTLOGS`, `REGISTRY` |
| Analysis Targets | `IOC`, `SUSPICIOUS`, `MALWARE`, `PERSISTENCE`, `TIMELINE`, `CORRELATIONS`, `PROCESSGRAPH`, `REPORT`, `EVIDENCE` |

### 3.4 Literals

*   **Integer Literals:** Sequences of decimal digits: `42`, `0`, `1048576`.
*   **Float Literals:** Decimal numbers with fractional part: `3.14`, `0.005`.
*   **String Literals:** Double-quoted character sequences supporting standard escapes (`\"`, `\\`, `\n`, `\t`): `"powershell.exe"`, `"192.168.1.1"`.
*   **Boolean Literals:** `true`, `false`, `TRUE`, `FALSE`.

---

## 4. Statements and Syntax

### 4.1 Target Declarations

Declares the host environment under investigation. Must precede any forensic operations.

```jocky
TARGET SYSTEM;              // Local system
TARGET REMOTE "10.0.0.5";   // Remote host
TARGET ALL;                 // All configured endpoints
```

### 4.2 Variable Declarations (`LET`) and Assignments (`SET`)

*   **`LET`:** Declares a new local variable in the current lexical scope with an initial expression:
    ```jocky
    LET threshold = 5;
    LET suspicious_name = "cmd.exe";
    ```
    Re-declaring a variable with `LET` in the same scope produces diagnostic `E2002 (Duplicate Variable)`.

*   **`SET`:** Updates an existing declared variable or sets a recognized global configuration variable:
    ```jocky
    SET threshold = 10;
    SET output_format = "JSON";
    SET severity_threshold = "HIGH";
    ```
    Attempting to `SET` an undeclared non-configuration identifier produces diagnostic `E2001 (Undefined Variable)`.

### 4.3 Forensic Collection (`SCAN`)

Dispatches forensic collectors to acquire host evidence artifacts:

```jocky
SCAN PROCESSES;
SCAN FILES;
SCAN NETWORK;
SCAN EVENTLOGS;
SCAN REGISTRY;
SCAN ALL;
```

#### Conditional Scans (`WHERE`)
Filters artifact collection based on entity properties:
```jocky
SCAN PROCESSES WHERE name == "powershell.exe";
SCAN FILES WHERE size > 1048576;
SCAN NETWORK WHERE remote_port == 443;
```

### 4.4 Analysis and Correlation (`FIND` & `BUILD`)

*   **`FIND`:** Dispatches rule matching and heuristic anomaly detection:
    ```jocky
    FIND IOC;          // Known Indicators of Compromise (MD5/SHA256, C2 IPs)
    FIND SUSPICIOUS;   // Heuristic anomaly detection
    FIND MALWARE;      // Signatures and persistence artifacts
    FIND PERSISTENCE;  // Run keys, scheduled tasks, startup entries
    ```

*   **`BUILD`:** Constructs analytical models from collected evidence:
    ```jocky
    BUILD TIMELINE;      // Unified temporal super-timeline
    BUILD CORRELATIONS;  // Cross-artifact causality linking
    BUILD PROCESSGRAPH;  // Parent-child process execution tree
    ```

### 4.5 Export and Reporting (`EXPORT`)

Outputs forensic findings and evidence packages:
```jocky
EXPORT REPORT;                       // Default report output
EXPORT REPORT TO "triage.json";      // Specific output destination
EXPORT EVIDENCE TO "evidence_pkg/";  // Raw collected evidence bundle
EXPORT TIMELINE TO "timeline.csv";   // Normalized timeline
```

### 4.6 Control Flow (`IF` and `FOREACH`)

#### Conditional Branching (`IF`)
Executes a block of statements if the condition evaluates to true. An optional `ELSE` block executes if false:
```jocky
IF alert.severity == "HIGH" THEN {
    EXPORT EVIDENCE TO "critical_evidence/";
    FIND MALWARE;
} ELSE {
    EXPORT REPORT;
}
```

#### Iteration (`FOREACH`)
Iterates over evidence items from a collection. The loop variable is bound inside the loop body scope:
```jocky
FOREACH proc IN PROCESSES {
    IF proc.name == "mimikatz.exe" THEN {
        EXPORT REPORT;
    }
}
```

---

## 5. Expressions, Operators, and Conditions

### 5.1 Comparison Operators

| Operator | Meaning | Supported Types |
|---|---|---|
| `==` | Equality | Integer, Float, String, Boolean |
| `!=` | Inequality | Integer, Float, String, Boolean |
| `<` | Less than | Numeric, String |
| `<=` | Less than or equal | Numeric, String |
| `>` | Greater than | Numeric, String |
| `>=` | Greater than or equal | Numeric, String |
| `CONTAINS` | Substring or member test | String, Collection |

### 5.2 Logical Operators

*   `AND`: Logical conjunction (both operands true)
*   `OR`: Logical disjunction (either operand true)
*   `NOT`: Logical negation

```jocky
IF proc.pid > 1000 AND proc.name == "cmd.exe" THEN { ... }
IF NOT (proc.status == "RUNNING") THEN { ... }
```

---

## 6. Type System and Entity Properties

### 6.1 Primitive Types
*   `INT`: 64-bit integer
*   `FLOAT`: 64-bit floating point number
*   `STRING`: UTF-8 character string
*   `BOOL`: Boolean (`true` or `false`)

### 6.2 Entity Types and Properties

During iteration (`FOREACH <var> IN <SOURCE>`) or property access (`<var>.<prop>`), the semantic analyzer validates that `<prop>` belongs to `<var>`'s entity type.

| Entity Type | Source | Valid Properties (and Types) |
|---|---|---|
| **Process** | `PROCESSES` | `pid` (INT), `ppid` (INT), `name` (STRING), `exe_path` (STRING), `cmdline` (STRING), `username` (STRING), `created_time` (STRING), `status` (STRING), `threads` (INT), `memory_bytes` (INT) |
| **Network** | `NETWORK` | `protocol` (STRING), `local_ip` (STRING), `local_port` (INT), `remote_ip` (STRING), `remote_port` (INT), `status` (STRING), `pid` (INT) |
| **File** | `FILES` | `path` (STRING), `size` (INT), `created_time` (STRING), `modified_time` (STRING), `accessed_time` (STRING), `permissions` (STRING), `md5` (STRING), `sha256` (STRING) |
| **EventLog** | `EVENTLOGS` | `source` (STRING), `event_id` (INT), `timestamp` (STRING), `level` (STRING), `message` (STRING) |
| **Registry** | `REGISTRY` | `key` (STRING), `value_name` (STRING), `value_data` (STRING), `value_type` (STRING), `modified_time` (STRING) |
| **Alert** | `ALERTS` | `type` (STRING), `severity` (STRING), `details` (STRING), `timestamp` (STRING) |

---

## 7. Diagnostics and Error Codes

JOCKY uses structured error codes with source line and column numbers:

| Code | Severity | Description |
|---|---|---|
| `E1001` | ERROR | Unexpected character / invalid token |
| `E1002` | ERROR | Unterminated string literal |
| `E1003` | ERROR | General syntax error |
| `E1004` | ERROR | Unexpected token |
| `E1005` | ERROR | Missing semicolon `;` after statement |
| `E1006` | ERROR | Unclosed block `{ ... }` |
| `E2001` | ERROR | Undefined variable or object |
| `E2002` | ERROR | Duplicate variable declaration (`LET`) in same scope |
| `E2003` | ERROR | Variable accessed out of scope |
| `W2001` | WARNING | Unused variable |
| `E3001` | ERROR | Missing `TARGET` declaration before forensic operations |
| `E3002` | ERROR | Invalid target type |
| `W3001` | WARNING | Redundant `TARGET` declaration |
| `E4001` | ERROR | Unsupported collector in `SCAN` |
| `E4002` | ERROR | Unsupported target in `FIND` |
| `E4003` | ERROR | Unsupported target in `BUILD` |
| `E4004` | ERROR | Unsupported target in `EXPORT` |
| `E4005` | ERROR | Unsupported source in `FOREACH` |
| `E5001` | ERROR | Type mismatch in comparison or assignment |
| `E5002` | ERROR | Invalid operator for operand types |
| `E5003` | ERROR | Invalid property access on entity |
| `E5004` | ERROR | Attempted property access on non-entity type |

---

## 8. CLI Usage

Validate scripts without execution:

```bash
jocky check investigation.jky
```

Print Abstract Syntax Tree:

```bash
jocky check investigation.jky --ast
```
