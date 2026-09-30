"""
Regression test suite for JOCKY Critical Defect Remediations:
P0-1: LL-01 - Fabricated/default forensic evidence removed from production runtime
P0-2: EV-01 - Invalid evidence receiving VALID integrity status fixed
P0-3: RT-04 - Collector exceptions silently swallowed in runtime fixed
P0-4: G07 - Locked/unhashable evidence (hash=None) DB insertion crash fixed
P0-5: H09 - Failed agent task marked COMPLETED by server hub fixed
P0-6: AUTH01 - Unauthenticated operational execution on compiler/endpoint APIs fixed
"""
import os
import sys
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import select

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from runtime.forensic_runtime import ForensicRuntime, RuntimeContext
from runtime.runtime_engine import JockyRuntime, ExecutionResult
from evidence.schema import CanonicalEvidenceItem, EvidenceType, EvidenceStatus
from evidence.store import InMemoryEvidenceStore
from evidence.integrity import EvidenceIntegrityManager, VerificationStatus
from evidence.validator import EvidenceValidator
from agent.server_hub import AgentServerHub, TaskStatus, TaskResult
from app.main import app
from app.db.migrations import init_database
from app.models.evidence import Evidence
from app.models.investigation import Investigation
from app.services.investigation_ingestion import ingest_investigation_payload
from app.core.security import create_access_token


# ============================================================================
# P0-1: LL-01 - Fabricated / Default Forensic Evidence
# ============================================================================

def test_p0_1_ll01_unscanned_collections_empty():
    """
    LL-01: RuntimeContext.collections must NOT be pre-seeded with fake records.
    Unscanned collections must be empty, and reset() must clear collections to {}.
    """
    ctx = RuntimeContext()
    assert ctx.collections == {}, "RuntimeContext.collections must default to an empty dict"

    rt = ForensicRuntime()
    assert rt.context.collections == {}, "Fresh ForensicRuntime must have empty collections"
    assert rt.context.executed_scans == [], "No scans executed on fresh runtime"

    # Resetting runtime must keep collections empty
    rt.reset()
    assert rt.context.collections == {}, "Reset must maintain empty collections, never seed fake data"

    # Querying an unknown collection source ID must return empty list, never fabricated records
    unknown_items = rt.get_collection(9999)
    assert unknown_items == [], "Querying unknown collection must return empty list"

    # Querying a known collection triggers live scan (or returns empty on failure), never fake seed
    items = rt.get_collection(1)  # PROCESSES
    assert isinstance(items, list)
    assert rt.context.executed_scans == ["PROCESSES"], "Executed scan must be tracked"
    # Verify no fake hardcoded names:
    fake_names = {"System", "svchost.exe", "powershell.exe"}
    names = [p.get("name") for p in items]
    if len(items) == 3:
        assert set(names) != fake_names, "Collection must not be the static 3-item fabricated seed"


# ============================================================================
# P0-2: EV-01 - Invalid Evidence Receiving VALID Integrity Status
# ============================================================================

def test_p0_2_ev01_invalid_evidence_integrity_status():
    """
    EV-01: Schema-failing evidence must NEVER receive a VALID integrity status.
    InMemoryEvidenceStore.add must mark invalid items as 'failed'.
    EvidenceIntegrityManager.verify_item must return INVALID.
    create_manifest must mark status 'invalid'.
    verify_manifest must return VerificationStatus.INVALID.
    """
    store = InMemoryEvidenceStore()
    bad_item = CanonicalEvidenceItem(
        id="bad-evidence-01",
        host="HOST-1",
        timestamp="invalid-timestamp-format",
        type="invalid_type",
        source="unit_test",
        data={"pid": "not-an-int", "name": ""},
    )

    # 1. Validation check
    val_res = EvidenceValidator.validate(bad_item)
    assert not val_res.is_valid, "Item must fail validation"

    # 2. Add to store -> status must be 'failed'
    store.add(bad_item)
    stored = store.get("bad-evidence-01")
    assert stored is not None
    assert stored.status == "failed", "Invalid item in store must have status 'failed'"
    assert len(stored.errors) > 0, "Item must retain validation errors"

    # 3. verify_item must return INVALID
    item_status = EvidenceIntegrityManager.verify_item(bad_item)
    assert item_status == VerificationStatus.INVALID, "Invalid item must verify as INVALID, not VALID"

    # 4. Manifest creation on invalid items must reflect invalid status
    manifest = store.create_manifest(case_id="CASE-BAD")
    assert manifest.status == "invalid", "Manifest with invalid items must have status 'invalid'"

    # 5. Manifest verification must yield VerificationStatus.INVALID
    report = store.verify_integrity(manifest)
    assert report.status == VerificationStatus.INVALID, "Report must be INVALID"
    assert report.invalid_count >= 1, "Report must count invalid items"
    assert not report.is_valid, "is_valid property must be False"

    # 6. Empty manifest must return UNVALIDATED, not VALID
    empty_store = InMemoryEvidenceStore()
    empty_m = empty_store.create_manifest()
    assert empty_m.status == "unvalidated", "Empty manifest must have status 'unvalidated'"
    empty_rep = empty_store.verify_integrity(empty_m)
    assert empty_rep.status == VerificationStatus.UNVALIDATED, "Empty store must verify as UNVALIDATED"


# ============================================================================
# P0-3: RT-04 - Collector Exceptions Silently Swallowed in Runtime
# ============================================================================

def test_p0_3_rt04_collector_exception_surfaced():
    """
    RT-04: When a collector raises an exception during script execution,
    the error must be surfaced in result.errors, and result.success must be False.
    """
    rt = JockyRuntime()

    # Fault injection: simulate collector crash
    def failing_scan():
        raise OSError("InjectedHardwareFaultDiskUnreadable")

    rt._scan_processes = failing_scan

    script = "TARGET SYSTEM;\nSCAN PROCESSES;\n"
    res = rt.execute_script(script)

    assert res.success is False, "Script execution must report success=False when collector fails"
    assert len(res.errors) > 0, "Errors list must contain the collector failure"
    assert any("InjectedHardwareFaultDiskUnreadable" in err for err in res.errors), (
        f"Expected exception message in errors, got: {res.errors}"
    )

    # Test unknown scan target directly on _handle_scan
    from compiler.ast_nodes import ScanStmt
    rt2 = JockyRuntime()
    rt2._handle_scan(ScanStmt(scan_target="INVALID_TARGET"))
    assert rt2.result.success is False
    assert any("Unknown scan target" in err for err in rt2.result.errors)


# ============================================================================
# P0-4: G07 - Locked/Unhashable Evidence (hash=None) DB Ingestion Crash
# ============================================================================

@pytest.mark.asyncio
async def test_p0_4_g07_locked_unhashable_evidence_ingestion():
    """
    G07: Ingestion of evidence items with hash=None (e.g. locked or unreadable files)
    must NOT fail with sqlite3.IntegrityError NOT NULL constraint.
    It must be accepted, marked with limitations, and persisted.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    await init_database(engine)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as db:
        # Create investigation
        inv = Investigation(
            id="INV-G07-TEST",
            case_number="CASE-G07",
            title="Unhashed Evidence Ingestion Test",
            status="ACTIVE",
        )
        db.add(inv)
        await db.commit()

        # Ingestion payload with hash=None
        payload = {
            "case_id": "INV-G07-TEST",
            "evidence_items": [
                {
                    "id": "unhashed-locked-file-01",
                    "host": "ENDPOINT-SEC-01",
                    "timestamp": "2026-09-12T00:00:00Z",
                    "type": "file",
                    "source": "filesystem",
                    "collector": "FileCollector",
                    "status": "VALID",
                    "hash": None,  # Locked file: collector could not compute hash
                    "data": {"path": "C:\\Windows\\System32\\config\\SAM", "size": 65536},
                    "limitations": ["File locked by exclusive OS handle"],
                }
            ]
        }

        # Must execute without IntegrityError
        inv_res = await ingest_investigation_payload(db, payload)
        assert inv_res is not None

        # Verify evidence record in DB
        ev_query = await db.execute(select(Evidence).filter(Evidence.id == "unhashed-locked-file-01"))
        ev = ev_query.scalars().first()
        assert ev is not None
        assert ev.hash is None, "Evidence hash column must store NULL"
        assert ev.status in ("PARTIAL", "VALID")
        assert any("Hash unavailable" in lim for lim in ev.limitations_json)

    await engine.dispose()


# ============================================================================
# P0-5: H09 - Failed Agent Task Marked COMPLETED by Server Hub
# ============================================================================

def test_p0_5_h09_failed_agent_task_retains_failed_status():
    """
    H09: When an endpoint agent submits a TaskResult with status=FAILED,
    the server hub must preserve TaskStatus.FAILED (NEVER mark COMPLETED).
    """
    hub = AgentServerHub()
    endpoint = hub.register_endpoint(hostname="agent-test-host")

    # Create task assigned to agent
    task = hub.create_task(
        investigation_id="CASE-FAILED-TASK",
        commands=["SCAN PROCESSES;"],
        assigned_to=endpoint.agent_id,
    )
    # Move task to RUNNING via get_next_task
    next_task = hub.get_next_task(endpoint.agent_id, endpoint.api_token)
    assert next_task is not None
    assert hub._tasks[task.task_id].status == TaskStatus.RUNNING

    # Submit failure result
    failed_result = TaskResult(
        task_id=task.task_id,
        status=TaskStatus.FAILED,
        evidence_items=[],
        integrity_manifest=None,
        errors=["Collector crash: Access Denied to memory address"],
    )

    response = hub.submit_task_result(endpoint.agent_id, endpoint.api_token, failed_result)

    assert response.get("status") == "ACCEPTED"
    assert response.get("task_status") == "FAILED"

    # Server hub must record task status as FAILED, not COMPLETED
    stored_task = hub._tasks[task.task_id]
    assert stored_task.status == TaskStatus.FAILED, (
        f"Expected task status to be TaskStatus.FAILED, got: {stored_task.status}"
    )
    assert "Collector crash" in stored_task.error_message


# ============================================================================
# P0-6: AUTH01 - Unauthenticated Operational Execution on Compiler/Endpoint APIs
# ============================================================================

@pytest.mark.asyncio
async def test_p0_6_auth01_compiler_and_endpoint_apis_require_auth():
    """
    AUTH01: Standalone compile/execute and investigation compiler/endpoint routes
    must require authentication (HTTP 401 Unauthorized for unauthenticated requests).
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Standalone compile without auth
        resp1 = await client.post("/api/v1/compiler/compile", json={"source": "TARGET SYSTEM;"})
        assert resp1.status_code == 401, f"Expected 401 for standalone compile, got {resp1.status_code}"

        # 2. Standalone execute without auth
        resp2 = await client.post("/api/v1/compiler/execute", json={"source": "TARGET SYSTEM;"})
        assert resp2.status_code == 401, f"Expected 401 for standalone execute, got {resp2.status_code}"

        # 3. Investigation compile without auth
        resp3 = await client.post("/api/v1/investigations/any-inv/compile", json={"source": "TARGET SYSTEM;"})
        assert resp3.status_code == 401, f"Expected 401 for inv compile, got {resp3.status_code}"

        # 4. Investigation execute without auth
        resp4 = await client.post("/api/v1/investigations/any-inv/execute", json={"source": "TARGET SYSTEM;"})
        assert resp4.status_code == 401, f"Expected 401 for inv execute, got {resp4.status_code}"

        # 5. Investigation report without auth
        resp5 = await client.get("/api/v1/investigations/any-inv/report")
        assert resp5.status_code == 401, f"Expected 401 for inv report, got {resp5.status_code}"

        # 6. Investigation export-report without auth
        resp6 = await client.get("/api/v1/investigations/any-inv/export-report")
        assert resp6.status_code == 401, f"Expected 401 for inv export-report, got {resp6.status_code}"

        # 7. Create endpoint without auth
        resp7 = await client.post(
            "/api/v1/investigations/any-inv/endpoints",
            json={"hostname": "ep-unauth", "ip_address": "10.0.0.1", "os_type": "Windows"}
        )
        assert resp7.status_code == 401, f"Expected 401 for create endpoint, got {resp7.status_code}"

        # 8. With valid auth, authenticated requests should pass auth gate
        from app.api.deps import get_current_user
        from app.models.user import User
        mock_user = User(id="test-admin-id", email="admin@example.com", role="ADMIN")
        app.dependency_overrides[get_current_user] = lambda: mock_user

        try:
            resp_auth = await client.post("/api/v1/compiler/compile", json={"source": "TARGET SYSTEM;"})
            assert resp_auth.status_code == 200, f"Expected 200 for authenticated compile, got {resp_auth.status_code}"
        finally:
            app.dependency_overrides.pop(get_current_user, None)
