"""
Test suite for Forensic Investigation Summary Report feature.
Verifies service aggregation, API endpoints, HTML rendering,
empty states, and integrity verification.
"""
import os
import sys
import pytest

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.session import AsyncSessionLocal
from app.models.investigation import Investigation
from app.models.evidence import Evidence
from app.models.ioc import IOC
from app.models.relationship import Relationship
from app.models.timeline_event import TimelineEvent
from app.services.investigation_summary_service import get_investigation_summary_data
from sqlalchemy import select


@pytest.mark.asyncio
async def test_summary_report_service_with_real_case():
    """Verify service aggregates real case data without errors."""
    async with AsyncSessionLocal() as db:
        # Check if any case exists
        inv_res = await db.execute(select(Investigation).limit(1))
        inv = inv_res.scalars().first()
        if not inv:
            pytest.skip("No investigations in DB to test")

        data = await get_investigation_summary_data(db, inv.id)
        assert data is not None
        assert "header" in data
        assert "executive_status" in data
        assert "key_metrics" in data
        assert "artifact_distribution" in data
        assert "severity_distribution" in data
        assert "ioc_findings" in data
        assert "process_analysis" in data
        assert "network_analysis" in data
        assert "event_analysis" in data
        assert "file_analysis" in data
        assert "registry_analysis" in data
        assert "correlation_analysis" in data
        assert "timeline_summary" in data
        assert "integrity" in data
        assert "collection_limitations" in data
        assert "executive_conclusion" in data

        # Validate headers
        assert data["header"]["case_id"] == inv.case_number
        assert data["header"]["title"] == inv.title
        assert data["key_metrics"]["evidence_items"] >= 0
        assert data["key_metrics"]["ioc_findings"] >= 0
        assert len(data["integrity"]["root_hash"]) == 64


@pytest.mark.asyncio
async def test_summary_report_api_endpoint():
    """Verify the /api/v1/investigations/{id}/summary-report endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Get list of investigations
        res = await client.get("/api/v1/investigations")
        assert res.status_code in (200, 401, 307)
        
        # Test direct case query on known case
        async with AsyncSessionLocal() as db:
            inv_res = await db.execute(select(Investigation).limit(1))
            inv = inv_res.scalars().first()
            if not inv:
                pytest.skip("No investigations to test")
            case_id = inv.id

        rep_res = await client.get(f"/api/v1/investigations/{case_id}/summary-report")
        assert rep_res.status_code == 200
        payload = rep_res.json()
        assert "header" in payload
        assert payload["header"]["case_id"] == inv.case_number
        assert "key_metrics" in payload
        assert "executive_conclusion" in payload


@pytest.mark.asyncio
async def test_summary_report_page_route():
    """Verify the frontend HTML route /investigations/{id}/report."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with AsyncSessionLocal() as db:
            inv_res = await db.execute(select(Investigation).limit(1))
            inv = inv_res.scalars().first()
            if not inv:
                pytest.skip("No investigations to test")
            case_id = inv.id

        html_res = await client.get(f"/investigations/{case_id}/report")
        assert html_res.status_code == 200
        assert "JOCKY FORENSIC INVESTIGATION SUMMARY" in html_res.text
        assert "ARTIFACT DISTRIBUTION" in html_res.text
        assert "EVIDENCE INTEGRITY VERIFICATION" in html_res.text


@pytest.mark.asyncio
async def test_summary_report_empty_case_handling():
    """Verify that cases with 0 artifacts handle empty state gracefully without errors."""
    async with AsyncSessionLocal() as db:
        # Create a temporary empty investigation
        empty_inv = Investigation(
            case_number="TEST-EMPTY-CASE-001",
            title="Empty Test Case",
            description="Testing empty states",
            status="OPEN",
            severity="LOW"
        )
        db.add(empty_inv)
        await db.commit()
        await db.refresh(empty_inv)

        try:
            data = await get_investigation_summary_data(db, empty_inv.id)
            assert data is not None
            assert data["key_metrics"]["evidence_items"] == 0
            assert data["key_metrics"]["ioc_findings"] == 0
            assert data["key_metrics"]["relationships"] == 0
            assert data["process_analysis"]["total_processes"] == 0
            assert data["network_analysis"]["available"] is False
            assert data["file_analysis"]["available"] is False
            assert data["registry_analysis"]["available"] is False
            assert "0 canonical forensic evidence items" in data["executive_conclusion"]
        finally:
            await db.delete(empty_inv)
            await db.commit()
