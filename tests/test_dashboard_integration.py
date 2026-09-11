"""
JOCKY Final Dashboard Integration Tests (Phases 1-14)
Verifies:
- All core API endpoints: /investigations, /evidence, /endpoints, /iocs, /relationships, /timeline, /reports, /stats
- Unauthorized response (401) without authentication token
- Successful authenticated responses (populated and empty states)
- Investigation result ingestion bridge
- Standalone HTML and JSON report export endpoints
"""
import os
import sys
import pytest
from httpx import AsyncClient, ASGITransport

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app
from app.core.security import create_access_token


@pytest.fixture
def auth_headers():
    token = create_access_token(data={"sub": "admin@jocky.org", "role": "ADMIN"})
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_unauthorized_endpoints_return_401():
    """Verify that protected API resources return 401 without token."""
    transport = ASGITransport(app=app)
    endpoints = [
        "/api/v1/investigations",
        "/api/v1/evidence",
        "/api/v1/endpoints",
        "/api/v1/iocs",
        "/api/v1/relationships",
        "/api/v1/timeline",
        "/api/v1/reports",
        "/api/v1/stats",
    ]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for ep in endpoints:
            res = await client.get(ep)
            assert res.status_code == 401, f"{ep} did not enforce authentication"


@pytest.mark.asyncio
async def test_authenticated_core_endpoints(auth_headers):
    """Verify that all core endpoints return 200 with valid JWT."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Investigations
        res_inv = await client.get("/api/v1/investigations", headers=auth_headers)
        assert res_inv.status_code == 200
        assert isinstance(res_inv.json(), list)

        # 2. Evidence
        res_ev = await client.get("/api/v1/evidence", headers=auth_headers)
        assert res_ev.status_code == 200
        assert isinstance(res_ev.json(), list)

        # 3. Endpoints
        res_ep = await client.get("/api/v1/endpoints", headers=auth_headers)
        assert res_ep.status_code == 200
        assert isinstance(res_ep.json(), list)

        # 4. IOCs
        res_ioc = await client.get("/api/v1/iocs", headers=auth_headers)
        assert res_ioc.status_code == 200
        assert isinstance(res_ioc.json(), list)

        # 5. Relationships
        res_rel = await client.get("/api/v1/relationships", headers=auth_headers)
        assert res_rel.status_code == 200
        assert isinstance(res_rel.json(), list)

        # 6. Timeline
        res_tl = await client.get("/api/v1/timeline", headers=auth_headers)
        assert res_tl.status_code == 200
        assert isinstance(res_tl.json(), list)

        # 7. Reports
        res_rep = await client.get("/api/v1/reports", headers=auth_headers)
        assert res_rep.status_code == 200
        assert isinstance(res_rep.json(), list)

        # 8. Stats
        res_stats = await client.get("/api/v1/stats", headers=auth_headers)
        assert res_stats.status_code == 200
        stats = res_stats.json()
        assert "activeInvestigations" in stats
        assert "endpoints" in stats
        assert "totalEvidence" in stats
        assert "criticalAlerts" in stats
        assert "iocs" in stats
        assert "statusDistribution" in stats


@pytest.mark.asyncio
async def test_investigation_ingestion_bridge(auth_headers):
    """Verify that analysis payload can be ingested into database via API."""
    transport = ASGITransport(app=app)
    sample_payload = {
        "case_id": "TEST-INGEST-001",
        "evidence_items": [
            {
                "id": "test-ev-001",
                "host": "test-host",
                "timestamp": "2026-09-04T00:00:00+00:00",
                "type": "process",
                "source": "psutil",
                "collector": "ProcessCollector",
                "status": "VALID",
                "hash": "abc123hash",
                "data": {"pid": 9999, "name": "suspicious.exe"},
            }
        ],
        "findings": [
            {
                "rule_id": "TEST_RULE_001",
                "rule_name": "Test Detection",
                "severity": "CRITICAL",
                "reason": "Test finding for integration verification",
                "evidence_ids": ["test-ev-001"],
            }
        ],
        "relationships": [
            {
                "source_evidence_id": "test-ev-001",
                "target_evidence_id": "test-ev-002",
                "relationship_type": "SPAWNED",
                "confidence": 0.95,
                "reason": "Process child creation",
            }
        ],
        "timeline": [
            {
                "timestamp": "2026-09-04T00:00:00+00:00",
                "evidence_type": "process",
                "event_type": "PROCESS_START",
                "title": "suspicious.exe execution",
                "description": "Executed PID 9999",
                "severity": "CRITICAL",
                "evidence_id": "test-ev-001",
            }
        ],
    }

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/investigations/ingest", json=sample_payload, headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["case_number"] == "TEST-INGEST-001"
        inv_id = data["id"]

        # Verify ingested evidence via query
        ev_res = await client.get(f"/api/v1/evidence?investigation_id={inv_id}", headers=auth_headers)
        assert ev_res.status_code == 200
        ev_list = ev_res.json()
        assert len(ev_list) >= 1
        assert ev_list[0]["host"] == "test-host"

        # Verify ingested IOC
        ioc_res = await client.get(f"/api/v1/iocs?investigation_id={inv_id}", headers=auth_headers)
        assert ioc_res.status_code == 200
        ioc_list = ioc_res.json()
        assert len(ioc_list) >= 1

        # Verify ingested Relationship
        rel_res = await client.get(f"/api/v1/relationships?investigation_id={inv_id}", headers=auth_headers)
        assert rel_res.status_code == 200
        rel_list = rel_res.json()
        assert len(rel_list) >= 1

        # Verify export report endpoint
        export_html = await client.get(f"/api/v1/investigations/{inv_id}/export-report?format=html", headers=auth_headers)
        assert export_html.status_code == 200
        assert "<html" in export_html.text.lower()

        export_json = await client.get(f"/api/v1/investigations/{inv_id}/export-report?format=json", headers=auth_headers)
        assert export_json.status_code == 200
        assert "meta" in export_json.json() or "summary" in export_json.json()

