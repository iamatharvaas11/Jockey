# JOCKY Testing Strategy & Test Suite Reference

## 1. Overview
The JOCKY test suite validates the forensic compiler pipeline, cross-platform runtime, collectors, evidence normalization, deterministic SHA-256 integrity, IOC engine, correlation engine, super-timeline builder, reporting subsystem, backend REST API, RBAC permissions, multi-endpoint agents, dashboard pages, and controlled resilience evaluation.

---

## 2. Test Execution
Execute the entire test suite using `pytest`:

```powershell
pytest
```

To run with verbose output and test timings:
```powershell
pytest -v --durations=10
```

---

## 3. Test Modules & Coverage

| Test File | Subsystem / Stage | Test Count | Scope & Verification |
|---|---|---|---|
| `tests/test_lexer.py` | Stage 2 Lexer | 12 | Token types, source locations, keywords, string escapes, errors |
| `tests/test_parser.py` | Stage 2 Parser | 15 | Grammatical statements, loops, conditionals, filters, declarations |
| `tests/test_parser_negative.py` | Stage 2 Negative Tests | 19 | Invalid syntax, missing semicolons, malformed expressions |
| `tests/test_ast.py` | Stage 2 AST Nodes | 3 | Deterministic AST hierarchy, string formatting, locations |
| `tests/test_semantic.py` | Stage 2 Semantics | 21 | Scope tracking, variable resolution, entity attribute checking |
| `tests/test_ir.py` | Stage 3 JOCKY IR | 7 | CFG construction, IR instructions, blocks, validator |
| `tests/test_llvm_codegen.py` | Stage 3 LLVM Codegen | 4 | Real LLVM IR emission, variables, branches, verification |
| `tests/test_native_compiler.py` | Stage 3 Native Engine | 5 | Machine code generation, target triples, object emission, JIT |
| `tests/test_runtime.py` | Stage 4 Runtime & ABI | 21 | Runtime context, ABI callbacks, platform adapters, scan dispatch |
| `tests/test_collectors.py` | Stage 4 Collectors | 19 | Process, file, network, eventlog, registry on Windows & Linux |
| `tests/test_evidence_schema.py` | Stage 5 Schema | 15 | CanonicalEvidenceItem, validation, ISO-8601 formatting |
| `tests/test_evidence_integrity.py`| Stage 5 Integrity | 15 | Deterministic SHA-256, Merkle root, manifests, tamper detection |
| `tests/test_analysis_ioc.py` | Stage 6 IOC Engine | 11 | Rule schema, LOLBins, parent-child, known hashes, temp paths |
| `tests/test_analysis_correlation.py` | Stage 6 Correlation | 7 | Process-file, process-net, parent-child, cross-host isolation |
| `tests/test_analysis_timeline.py`| Stage 6 Timeline | 5 | Chronological UTC sorting, mixed evidence types, estimated timestamps |
| `tests/test_reporting.py` | Stage 7 Reports | 9 | Complete reports, verified/unverified/failed statuses, HTML/JSON/PDF |
| `tests/test_backend_api.py` | Stage 8 Repositories & RBAC | 7 | Generic repositories, migrations, ADMIN/ANALYST/VIEWER role checks |
| `tests/test_api_security.py` | Stage 8 API Security | 5 | Setup endpoint, no self-admin, path traversal rejection, JWT |
| `tests/test_agent_system.py` | Stage 9 Multi-Agent | 11 | Registration, token auth, heartbeats, offline, task lifecycle, multi-agent |
| `tests/test_dashboard.py` | Stage 10 Dashboard | 12 | Route rendering for all 11 dashboard views, redirect check |
| `tests/test_resilience.py` | Stage 11 Resilience | 5 | Safe IR transformations, metrics, telemetry, safety boundaries |
| `tests/test_cli_check.py` | CLI & Diagnostic Tests | 5 | `jocky check` semantic diagnostics |
| `tests/test_cli_compile.py` | CLI & Compilation Tests | 4 | `jocky compile` flags and output emission |

---

## 4. Test Constraints & Integrity Rules
1. **0 Failures Policy:** All test suites must pass with zero failures before deployment.
2. **Explicit Skip Rationale:** Any skipped tests (e.g. Linux `/proc` checks on Windows) must use explicit `@pytest.mark.skipif` with documented platform constraints.
3. **No Faked Mocks:** All cryptographic tests compute actual SHA-256 digests over genuine canonical JSON strings.

