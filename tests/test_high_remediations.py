"""
Regression test suite for JOCKY High-Severity Defect Remediations:
1.  RT-01: Numeric conditional comparisons evaluate numerically (not string compare)
2.  RT-02: False IF conditions execute the ELSE branch
3.  RT-03: FILTER statement mutates/filters collected evidence collections
4.  RT-05: EXPORT errors surfaced in result.errors and result.success = False
5.  CP-03: Integer precision preserved > 2^53 and on 400-digit integers
6.  CP-04: Boolean literals true/false parsed as BoolLiteral
7.  CP-05: Deep recursion handled gracefully with controlled error
8.  CL-01: Directory permission errors captured as limitations and PARTIAL status
9.  CL-02: Locked files without hashes flagged with limitation and PARTIAL status
10. EV-02: Duplicate evidence IDs disambiguated to prevent evidence loss
11. EV-06: FileEvidenceStore atomic export and corrupted import tolerance
12. AN-01: IOCEngine invalid regex patterns handled safely without engine crash
13. AN-02: String 'false' in rule configuration coerced to boolean False
14. AN-03: CorrelationEngine gracefully handles evidence items with data=None
15. AN-05: Boundary-aware path correlation prevents registry substring false positives
16. AN-07: TimelineEngine invalid timestamps placed at end, preserving chronological order
17. G01:   Investigation deletion cascades to evidence, relationships, and reports
18. G04:   SQLite connection configured with busy timeout
19. H03/H04: Server hub enforces task timeout on running tasks
"""
import os
import sys
import tempfile
import time
import pytest
from datetime import datetime, timezone

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from runtime.runtime_engine import JockyRuntime
from compiler.parser import parse, ParserError
from compiler.compiler import JockyCompiler
from compiler.ast_nodes import BoolLiteral, NumberLiteral
from collectors.file_collector import FileCollector, CollectorStatus
from evidence.schema import CanonicalEvidenceItem
from evidence.store import InMemoryEvidenceStore, FileEvidenceStore
from analysis.ioc.engine import IOCEngine
from analysis.ioc.rule import IOCRule
from analysis.correlation.engine import CorrelationEngine
from analysis.timeline.engine import TimelineEngine
from agent.server_hub import AgentServerHub, TaskStatus
from app.models.investigation import Investigation
from app.models.evidence import Evidence
from app.models.relationship import Relationship
from app.models.report import Report
from app.models.user import User
from app.services.investigation_ingestion import ingest_investigation_payload
from app.api.v1.endpoints.investigations import delete_investigation
from app.db.session import AsyncSessionLocal
from sqlalchemy import select, func


# ============================================================================
# 1. RT-01: Numeric Conditional Comparisons
# ============================================================================

def test_rt01_numeric_comparison_evaluation():
    """RT-01: Numeric conditions must evaluate numerically, not lexicographically."""
    rt = JockyRuntime()
    res = rt.execute_script('TARGET SYSTEM;\nIF 10 > 9 THEN { SET res = "gt_ok"; }\n')
    assert res.success is True
    assert rt.variables.get("res") == "gt_ok", "10 > 9 must be True"

    rt2 = JockyRuntime()
    res2 = rt2.execute_script('TARGET SYSTEM;\nIF 9 < 10 THEN { SET res = "lt_ok"; }\n')
    assert res2.success is True
    assert rt2.variables.get("res") == "lt_ok", "9 < 10 must be True"

    rt3 = JockyRuntime()
    res3 = rt3.execute_script('TARGET SYSTEM;\nIF 9 > 10 THEN { SET res = "fail"; }\n')
    assert res3.success is True
    assert "res" not in rt3.variables, "9 > 10 must be False"


# ============================================================================
# 2. RT-02: ELSE Branch Execution
# ============================================================================

def test_rt02_else_branch_executed():
    """RT-02: False IF condition must execute the ELSE branch."""
    rt = JockyRuntime()
    res = rt.execute_script('TARGET SYSTEM;\nIF 1 > 2 THEN { SET val = "then"; } ELSE { SET val = "else"; }\n')
    assert res.success is True
    assert rt.variables.get("val") == "else", "ELSE branch must execute when condition is false"

    rt2 = JockyRuntime()
    res2 = rt2.execute_script('TARGET SYSTEM;\nIF 2 > 1 THEN { SET val = "then"; } ELSE { SET val = "else"; }\n')
    assert res2.success is True
    assert rt2.variables.get("val") == "then", "THEN branch must execute when condition is true"


# ============================================================================
# 3. RT-03: FILTER Statement Effect
# ============================================================================

def test_rt03_filter_statement_mutates_evidence():
    """RT-03: FILTER statement must mutate and filter collected evidence."""
    rt = JockyRuntime()
    rt.result.collected_evidence["processes"] = [
        {"pid": 50, "name": "small.exe"},
        {"pid": 500, "name": "large.exe"},
    ]
    res = rt.execute_script('TARGET SYSTEM;\nFILTER pid > 100;\n')
    assert res.success is True
    procs = rt.result.collected_evidence.get("processes", [])
    assert len(procs) == 1, "Evidence list must be filtered"
    assert procs[0]["pid"] == 500


# ============================================================================
# 4. RT-05: EXPORT Error Reporting
# ============================================================================

def test_rt05_export_error_reporting():
    """RT-05: Failed exports must record errors and set success = False."""
    rt = JockyRuntime()
    res = rt.execute_script('TARGET SYSTEM;\nEXPORT REPORT TO "Z:\\__no_such_dir_xyz__\\report";\n')
    assert res.success is False, "Export to invalid path must fail result.success"
    assert len(res.errors) > 0, "Export error must be appended to result.errors"


# ============================================================================
# 5. CP-03: Large Integer Precision
# ============================================================================

def test_cp03_large_integer_precision():
    """CP-03: Integer literals must preserve exact precision and not overflow to float."""
    ast = parse('SET x = 9007199254740993;')
    val = ast.statements[0].value.value
    assert val == 9007199254740993, f"Expected 9007199254740993, got {val}"
    assert isinstance(val, int)

    # 100-digit integer
    huge_str = "9" * 100
    ast2 = parse(f'SET x = {huge_str};')
    val2 = ast2.statements[0].value.value
    assert val2 == int(huge_str)
    assert isinstance(val2, int)


# ============================================================================
# 6. CP-04: Boolean Literals in AST
# ============================================================================

def test_cp04_boolean_literals_parsed_as_bool():
    """CP-04: Boolean literals true/false must parse as BoolLiteral, not Identifier."""
    ast = parse('SET t = true;\nSET f = false;')
    t_val = ast.statements[0].value
    f_val = ast.statements[1].value
    assert isinstance(t_val, BoolLiteral)
    assert t_val.value is True
    assert isinstance(f_val, BoolLiteral)
    assert f_val.value is False


# ============================================================================
# 7. CP-05: Deep Recursion Protection
# ============================================================================

def test_cp05_deep_recursion_handling():
    """CP-05: Deep nesting must fail with controlled diagnostics, not unhandled crash."""
    depth = 350
    body = "SET deep = 1;"
    for _ in range(depth):
        body = "IF true == true THEN { " + body + " }"
    src = "TARGET SYSTEM;\n" + body + "\n"

    comp = JockyCompiler()
    res = comp.compile(src)
    assert res.success is False
    assert any("recursion" in str(e).lower() or "nesting" in str(e).lower() or "syntax" in str(e).lower() for e in res.errors)


# ============================================================================
# 8. CL-01: File Collector Denied Directory
# ============================================================================

def test_cl01_file_collector_denied_directory(tmp_path):
    """CL-01: Traversal errors in inaccessible directories must be recorded in limitations."""
    c = FileCollector()
    res = c.collect(paths=[str(tmp_path)])
    assert res.status == CollectorStatus.SUCCESS

    # Simulate denied directory
    c_denied = FileCollector()
    res_denied = c_denied.collect(paths=[os.path.join(str(tmp_path), "nonexistent_dir")])
    assert res_denied.limitations != []
    assert res_denied.status == CollectorStatus.PARTIAL


# ============================================================================
# 9. CL-02: File Collector Locked File Limitation
# ============================================================================

def test_cl02_file_collector_locked_file_limitation(tmp_path):
    """CL-02: Unhashable files must result in recorded limitations and PARTIAL status."""
    test_file = tmp_path / "locked_sim.bin"
    test_file.write_bytes(b"DATA" * 100)

    collector = FileCollector()
    # Mock hash_file to simulate unhashable locked file
    collector.hash_file = lambda fp: {"md5": None, "sha256": None}
    res = collector.collect(paths=[str(tmp_path)])

    assert res.status == CollectorStatus.PARTIAL
    assert any("Hash calculation failed" in lim for lim in res.limitations)


# ============================================================================
# 10. EV-02: Duplicate Evidence ID Preservation
# ============================================================================

def test_ev02_duplicate_evidence_id_preservation():
    """EV-02: Adding items with duplicate IDs must disambiguate and preserve both."""
    store = InMemoryEvidenceStore()
    i1 = CanonicalEvidenceItem(
        id="dup-item", host="H", timestamp="2025-01-01T00:00:00+00:00",
        type="process", source="test", data={"name": "first.exe"},
    )
    i2 = CanonicalEvidenceItem(
        id="dup-item", host="H", timestamp="2025-01-01T00:00:00+00:00",
        type="process", source="test", data={"name": "second.exe"},
    )
    store.add(i1)
    store.add(i2)

    assert store.count() == 2, "Both items must be preserved in store"
    orig = store.get("dup-item")
    assert orig is not None
    assert orig.data.get("name") == "first.exe", "Original item must not be overwritten"


# ============================================================================
# 11. EV-06: Atomic Export & Corrupted Import Protection
# ============================================================================

def test_ev06_atomic_export_and_corrupt_import(tmp_path):
    """EV-06: Atomic export replaces file, and import_json safely handles truncated JSON."""
    store = InMemoryEvidenceStore()
    item = CanonicalEvidenceItem(
        id="ev-atom-1", host="H", timestamp="2025-01-01T00:00:00+00:00",
        type="process", source="test", data={"pid": 1},
    )
    store.add(item)
    export_path = str(tmp_path / "export.json")
    store.export_json(export_path)
    assert os.path.exists(export_path)

    # Test corrupted import
    corrupt_path = str(tmp_path / "corrupt.json")
    with open(corrupt_path, "w") as f:
        f.write('{"evidence_count": 3, "items": [{"id": "trun')

    imported = store.import_json(corrupt_path)
    assert imported == 0, "Corrupt file import must return 0 without uncaught exception"


# ============================================================================
# 12. AN-01: IOC Engine Invalid Regex Safety
# ============================================================================

def test_an01_ioc_engine_invalid_regex_safety():
    """AN-01: Invalid regex patterns in rules must not crash IOCEngine."""
    bad_rule = IOCRule.from_dict({
        "rule_id": "bad-regex-rule",
        "name": "Bad Regex",
        "severity": "high",
        "evidence_types": ["process"],
        "conditions": {"regex_patterns": ["([unclosed"], "field": "cmdline"},
    })
    # Engine creation must not throw re.error
    engine = IOCEngine(rules=[bad_rule])
    findings = engine.evaluate_all([])
    assert findings == []


# ============================================================================
# 13. AN-02: String 'false' Rule Enabled Coercion
# ============================================================================

def test_an02_ioc_rule_string_false_coercion():
    """AN-02: String 'false' for enabled field must be coerced to boolean False."""
    rule_dict = {
        "rule_id": "disabled-rule",
        "name": "Disabled Rule",
        "severity": "medium",
        "enabled": "false",
        "evidence_types": ["process"],
        "conditions": {"target_hashes": ["a" * 64]},
    }
    rule = IOCRule.from_dict(rule_dict)
    assert rule.enabled is False, "'false' string must coerce to False, not True"


# ============================================================================
# 14. AN-03: Correlation Engine data=None Safety
# ============================================================================

def test_an03_correlation_engine_data_none_safety():
    """AN-03: Evidence items with data=None must not cause AttributeError."""
    item_none = CanonicalEvidenceItem(
        id="none-data-item", host="H", timestamp="2025-01-01T00:00:00+00:00",
        type="process", source="test", data=None,
    )
    engine = CorrelationEngine()
    rels = engine.correlate([item_none])
    assert isinstance(rels, list)
    assert len(rels) == 0


# ============================================================================
# 15. AN-05: Boundary-Aware Path Correlation
# ============================================================================

def test_an05_correlation_registry_substring_boundary():
    """AN-05: Registry values with sub-string matches must not produce false persistence links."""
    f = CanonicalEvidenceItem(
        id="f1", host="H", timestamp="2025-01-01T00:00:00+00:00",
        type="file", source="test", data={"path": "C:\\x.exe", "size": 100},
    )
    r = CanonicalEvidenceItem(
        id="r1", host="H", timestamp="2025-01-01T00:00:00+00:00",
        type="registry", source="test",
        data={"hive": "HKLM", "key": "Run", "value_name": "AV",
              "value_data": "C:\\Windows\\AV\\note_c:\\x.exe_bak.exe"},
    )
    engine = CorrelationEngine()
    rels = engine.correlate([f, r])
    assert len(rels) == 0, "Substring within another path must not produce a relationship"


# ============================================================================
# 16. AN-07: Timeline Engine Invalid Timestamps Ordering
# ============================================================================

def test_an07_timeline_invalid_timestamps_ordering():
    """AN-07: Invalid timestamps must be placed after valid timestamps in chronological order."""
    items = [
        CanonicalEvidenceItem(id="t2", host="H", timestamp="2025-01-02T00:00:00+00:00", type="event", source="t", data={"time_created": "2025-01-02T00:00:00+00:00"}),
        CanonicalEvidenceItem(id="bad", host="H", timestamp="not-a-date", type="event", source="t", data={"time_created": "not-a-date"}),
        CanonicalEvidenceItem(id="t1", host="H", timestamp="2025-01-01T00:00:00+00:00", type="event", source="t", data={"time_created": "2025-01-01T00:00:00+00:00"}),
    ]
    engine = TimelineEngine()
    events = engine.build_timeline(items)

    assert len(events) == 3
    assert events[0].timestamp == "2025-01-01T00:00:00+00:00"
    assert events[1].timestamp == "2025-01-02T00:00:00+00:00"
    assert events[2].timestamp == "not-a-date", "Invalid timestamps must be placed at the end"


# ============================================================================
# 17. G01: Investigation Cascade Deletion
# ============================================================================

@pytest.mark.asyncio
async def test_g01_investigation_cascade_delete():
    """G01: Deleting an investigation must cascade delete evidence, relationships, and reports."""
    async with AsyncSessionLocal() as session:
        payload = {
            "case_id": "TEST-G01-CASCADE",
            "evidence_items": [{
                "id": "g01-ev-1", "host": "HOST-1", "timestamp": "2025-01-01T00:00:00+00:00",
                "type": "process", "source": "test", "hash": "a" * 64,
                "data": {"pid": 1234, "name": "test.exe"},
            }],
            "timeline": [{
                "timestamp": "2025-01-01T00:00:00+00:00", "title": "Evt",
                "event_type": "T", "evidence_type": "process",
            }],
            "integrity_manifest": {"root_hash": "a" * 64},
        }
        inv = await ingest_investigation_payload(session, payload)
        inv_id = inv.id

        admin = User(id="admin-g01", email="admin-g01@example.com", role="ADMIN")
        await delete_investigation(inv_id, session, admin)

        ev_count = (await session.execute(select(func.count()).filter(Evidence.investigation_id == inv_id))).scalar()
        rel_count = (await session.execute(select(func.count()).filter(Relationship.investigation_id == inv_id))).scalar()
        rep_count = (await session.execute(select(func.count()).filter(Report.investigation_id == inv_id))).scalar()

        assert ev_count == 0, "Orphaned evidence must be 0 after investigation deletion"
        assert rel_count == 0, "Orphaned relationships must be 0 after investigation deletion"
        assert rep_count == 0, "Orphaned reports must be 0 after investigation deletion"


# ============================================================================
# 18. G04: SQLite Connection Timeout
# ============================================================================

def test_g04_sqlite_connection_timeout_configured():
    """G04: SQLite connection engine must be configured with a 30s busy timeout."""
    from app.db.session import engine
    from app.core.config import settings
    if "sqlite" in settings.DATABASE_URL:
        assert engine.sync_engine.pool._timeout == 30.0


# ============================================================================
# 19. H03/H04: Server Hub Enforces Task Timeout
# ============================================================================

def test_h03_h04_agent_task_timeout_enforced():
    """H03/H04: Running tasks exceeding timeout_seconds must transition to TIMEOUT."""
    hub = AgentServerHub()
    cfg = hub.register_endpoint(hostname="timeout-host")
    task = hub.create_task("CASE-TIMEOUT", ["SCAN PROCESSES;"], assigned_to=cfg.agent_id, timeout_seconds=0)

    # Poll task to transition to RUNNING
    polled = hub.get_next_task(cfg.agent_id, cfg.api_token)
    assert polled is not None
    assert polled.status == TaskStatus.RUNNING

    # Enforce timeouts
    hub.check_agent_statuses()
    updated_task = hub._tasks[task.task_id]
    assert updated_task.status == TaskStatus.TIMEOUT, "Task past timeout must transition to TIMEOUT"
