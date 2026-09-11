# JOCKY Forensic Runtime ABI Specification

## 1. Overview & Calling Convention

The JOCKY Runtime Application Binary Interface (ABI) defines the standard C-compatible interface between compiled JOCKY object code (or JIT-compiled LLVM modules) and forensic runtime libraries.

* **Calling Convention:** Standard platform C convention (`cdecl` / `__cdecl` on x86, standard System V / Windows x64 ABI on x86_64).
* **Linkage:** External C linkage (`extern "C"`).
* **Memory Model:** Strings are passed as null-terminated UTF-8 byte pointers (`const char*`). Collections and entities are passed as opaque pointers (`void*`). Memory allocated by runtime libraries remains owned by the runtime.

---

## 2. Function Declarations & Signatures

### 2.1 Lifecycle & Configuration

```c
// Initializes runtime subsystem, audit log buffers, and memory allocators
void jocky_rt_init(void);

// Sets the active investigation target
// target_type: 0 = SYSTEM, 1 = ALL, 2 = REMOTE
// hostname: null-terminated hostname/IP string for REMOTE, or empty string
void jocky_set_target(int32_t target_type, const char* hostname);

// Sets runtime engine configuration parameters
// key: parameter name (e.g., "output_format", "severity_threshold", "case_id")
// val: parameter value string
void jocky_set_config(const char* key, const char* val);
```

### 2.2 Forensic Collection & Ingestion

```c
void jocky_scan_processes(void);
void jocky_scan_files(void);
void jocky_scan_network(void);
void jocky_scan_eventlogs(void);
void jocky_scan_registry(void);
void jocky_scan_all(void);
```

### 2.3 Correlation & Analytics

```c
void jocky_find_ioc(void);
void jocky_find_suspicious(void);
void jocky_find_malware(void);
void jocky_find_persistence(void);

void jocky_build_timeline(void);
void jocky_build_correlations(void);
void jocky_build_processgraph(void);
```

### 2.4 Evidence & Report Exports

```c
// Exports formatted investigation report (JSON/HTML/PDF)
void jocky_export_report(const char* path);

// Exports collected forensic artifacts archive
void jocky_export_evidence(const char* path);

// Exports chronological timeline dataset
void jocky_export_timeline(const char* path);
```

---

## 3. Collection Iteration & Entity Property ABI

To enable `FOREACH` loops and property expressions (`proc.pid > 1000`) in compiled native code without exposing high-level language runtimes, JOCKY specifies an opaque collection and property indexing protocol:

### 3.1 Collection Iteration

```c
// Source IDs:
// 1 = PROCESSES, 2 = FILES, 3 = NETWORK, 4 = EVENTLOGS, 5 = REGISTRY
void* jocky_get_collection(int32_t source_id);

// Returns total count of entities in collection
int64_t jocky_collection_count(void* collection_ptr);

// Retrieves entity pointer at zero-based index
void* jocky_collection_get_item(void* collection_ptr, int64_t index);
```

### 3.2 Property Extractors

Property IDs allow compiled code to extract fields via direct numeric dispatch:

```c
// Retrieves 64-bit integer property (e.g., PID, size, port)
int64_t jocky_entity_get_int(void* entity_ptr, int32_t prop_id);

// Retrieves null-terminated string property (e.g., name, path, hash)
const char* jocky_entity_get_str(void* entity_ptr, int32_t prop_id);

// Tests if str contains substr (case-insensitive)
bool jocky_str_contains(const char* str, const char* substr);
```

### 3.3 Property ID Catalog

#### Process (Source ID: 1)
| Property ID | Property Name | Return Type | Description |
|---|---|---|---|
| `1` | `pid` | `int64_t` | Process Identifier |
| `2` | `ppid` | `int64_t` | Parent Process Identifier |
| `3` | `name` | `const char*` | Executable file name |
| `4` | `exe_path` | `const char*` | Full executable path |
| `5` | `cmdline` | `const char*` | Command line arguments |
| `6` | `username` | `const char*` | Running security context |
| `8` | `status` | `const char*` | Execution state |
| `9` | `threads` | `int64_t` | Active thread count |
| `10` | `memory_bytes` | `int64_t` | Working set memory usage |

#### Network (Source ID: 3)
| Property ID | Property Name | Return Type | Description |
|---|---|---|---|
| `101` | `protocol` | `const char*` | TCP / UDP |
| `102` | `local_ip` | `const char*` | Source address |
| `103` | `local_port` | `int64_t` | Source port |
| `104` | `remote_ip` | `const char*` | Destination address |
| `105` | `remote_port` | `int64_t` | Destination port |

#### File (Source ID: 2)
| Property ID | Property Name | Return Type | Description |
|---|---|---|---|
| `201` | `path` | `const char*` | Absolute filesystem path |
| `202` | `size` | `int64_t` | File size in bytes |
| `205` | `md5` | `const char*` | MD5 cryptographic hash |
| `206` | `sha256` | `const char*` | SHA256 cryptographic hash |

