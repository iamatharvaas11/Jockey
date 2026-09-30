"""
Tests for JOCKY System Health & Subsystem Diagnostics API and HUD templates.
Verifies real-time telemetry, psutil host metrics, database probes, LLVM compiler readiness,
and automated 6-point sanity diagnostics test runner.
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


@pytest.mark.asyncio
async def test_get_system_health_telemetry():
    """Verify GET /api/v1/health returns healthy telemetry across all 6 core forensic subsystems."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/api/v1/health")
        assert res.status_code == 200
        data = res.json()
        
        # Top-level contract
        assert "status" in data
        assert data["status"] in ["HEALTHY", "DEGRADED"]
        assert "timestamp" in data
        assert "uptime" in data
        assert "seconds" in data["uptime"]
        assert "formatted" in data["uptime"]
        
        # Subsystems verification
        assert "subsystems" in data
        subs = data["subsystems"]
        
        # 1. Database Subsystem
        assert "database" in subs
        db = subs["database"]
        assert db["status"] == "OPERATIONAL"
        assert db["connected"] is True
        assert isinstance(db["latency_ms"], (int, float))
        assert "SQLite" in db["engine"]
        assert "tables_count" in db
        
        # 2. LLVM Compiler Pipeline
        assert "compiler" in subs
        comp = subs["compiler"]
        assert comp["status"] == "OPERATIONAL"
        assert comp["pipeline"] == "LLVM READY"
        assert "target_machine" in comp
        
        # 3. Cryptographic Integrity
        assert "integrity" in subs
        integ = subs["integrity"]
        assert integ["status"] == "ENFORCED"
        assert "SHA-256" in integ["algorithm"]
        assert integ["tampered_items"] == 0
        assert integ["chain_of_custody"] == "UNBROKEN"
        
        # 4. Telemetry Collectors
        assert "collectors" in subs
        cols = subs["collectors"]
        assert "process_collector" in cols
        assert "network_collector" in cols
        assert "integrity_manager" in cols
        assert cols["process_collector"]["status"] == "OPERATIONAL"
        assert cols["network_collector"]["status"] == "OPERATIONAL"
        assert cols["integrity_manager"]["status"] == "OPERATIONAL"
        
        # 5. Storage Volume
        assert "storage" in subs
        storage = subs["storage"]
        assert "percent_used" in storage
        assert "total_gb" in storage
        assert "free_gb" in storage
        
        # 6. Host Resources
        assert "resources" in subs
        res_info = subs["resources"]
        assert "cpu_percent" in res_info
        assert "cpu_cores" in res_info
        assert res_info["cpu_cores"] >= 1
        assert "memory_percent" in res_info
        assert "process_memory_mb" in res_info


@pytest.mark.asyncio
async def test_run_diagnostics_probe_suite():
    """Verify POST /api/v1/health/run-diagnostics executes the 6-point automated sanity probe suite."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post("/api/v1/health/run-diagnostics")
        assert res.status_code == 200
        data = res.json()
        
        assert data["status"] == "ALL_PROBES_PASSED"
        assert data["total_probes"] == 6
        assert data["passed_count"] == 6
        assert data["failed_count"] == 0
        assert "timestamp" in data
        assert len(data["probes"]) == 6
        
        probe_ids = [p["id"] for p in data["probes"]]
        expected_ids = [
            "PROBE-DB-01",
            "PROBE-LLVM-02",
            "PROBE-CRYPTO-03",
            "PROBE-TELEMETRY-04",
            "PROBE-STORAGE-05",
            "PROBE-AUDIT-06"
        ]
        assert probe_ids == expected_ids
        
        for probe in data["probes"]:
            assert probe["status"] == "PASS"
            assert isinstance(probe["latency_ms"], (int, float))
            assert len(probe["details"]) > 0
            assert probe["subsystem"] in ["DATABASE", "COMPILER", "INTEGRITY", "COLLECTORS", "STORAGE", "AUDIT"]


@pytest.mark.asyncio
async def test_health_html_template_renders():
    """Verify GET /health renders the interactive HUD diagnostic command center page."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/health")
        assert res.status_code == 200
        assert "SUBSYSTEM STATUS & DIAGNOSTIC COMMAND CENTER" in res.text
        assert "AUTOMATED SUBSYSTEM SANITY DIAGNOSTICS" in res.text
        assert "CONTINUOUS FORENSIC TELEMETRY COLLECTORS" in res.text
        assert "SUBSYSTEM TELEMETRY STREAM & DIAGNOSTIC CONSOLE" in res.text
        assert "healthData()" in res.text

