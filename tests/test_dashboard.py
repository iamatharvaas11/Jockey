"""
Tests for JOCKY Stage 10 Dashboard
Verifies that all 11 core dashboard pages are properly routed, render with HTTP 200,
and include their required security, telemetry, and forensic views.
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
@pytest.mark.parametrize(
    "path,expected_fragment",
    [
        ("/dashboard", "COMMAND CENTER"),
        ("/investigations", "INCIDENT"),
        ("/endpoints", "ENDPOINTS"),
        ("/evidence", "EVIDENCE"),
        ("/iocs", "IOC"),
        ("/relationships", "RELATIONSHIP"),
        ("/timeline", "TIMELINE"),
        ("/reports", "REPORT"),
        ("/audit", "AUDIT"),
        ("/health", "SUBSYSTEM"),
        ("/settings", "CONFIGURATION"),
    ],
)
async def test_dashboard_pages_render_successfully(path, expected_fragment):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(path)
        assert response.status_code == 200
        assert expected_fragment in response.text.upper()


@pytest.mark.asyncio
async def test_root_redirects_to_dashboard():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/", follow_redirects=False)
        assert response.status_code in (302, 307)
        assert response.headers["location"] == "/dashboard"

