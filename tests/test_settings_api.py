import os
import sys
import pytest
from httpx import AsyncClient, ASGITransport

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app
from app.api.v1.endpoints.settings_api import DEFAULT_SETTINGS


@pytest.mark.asyncio
async def test_get_settings():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        assert "cryptographic_policy" in data
        assert "collection_policy" in data
        assert "ioc_policy" in data
        assert "report_defaults" in data
        assert "rbac_security" in data
        assert "system_diagnostics" in data
        assert "alerts_siem" in data
        assert data["cryptographic_policy"]["sha256_enforcement"] in ["STRICT", "PERMISSIVE"]


@pytest.mark.asyncio
async def test_update_settings():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        update_payload = {
            "cryptographic_policy": {
                "sha256_enforcement": "STRICT",
                "merkle_tree_strategy": "RFC6962"
            },
            "collection_policy": {
                "polling_interval_sec": 15
            }
        }
        res = await ac.post("/api/v1/settings", json=update_payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert data["settings"]["collection_policy"]["polling_interval_sec"] == 15


@pytest.mark.asyncio
async def test_reset_settings_defaults():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post("/api/v1/settings/reset")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert data["settings"]["collection_policy"]["polling_interval_sec"] == DEFAULT_SETTINGS["collection_policy"]["polling_interval_sec"]


@pytest.mark.asyncio
async def test_reverify_integrity_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post("/api/v1/settings/reverify-integrity")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "VERIFIED"
        assert "total_artifacts_checked" in data


@pytest.mark.asyncio
async def test_vacuum_db_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post("/api/v1/settings/vacuum-db")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_api_key_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create key
        res = await ac.post("/api/v1/settings/api-keys", json={"name": "UnitTest Node", "scope": "AGENT_INGEST"})
        assert res.status_code == 200
        key_data = res.json()["key"]
        key_id = key_data["key_id"]
        assert "token_full" in key_data

        # Delete key
        del_res = await ac.delete(f"/api/v1/settings/api-keys/{key_id}")
        assert del_res.status_code == 200
        assert del_res.json()["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_webhook_validation():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Invalid URL
        bad_res = await ac.post("/api/v1/settings/test-webhook", json={"webhook_url": "ftp://bad-url"})
        assert bad_res.status_code == 400

        # Valid URL
        good_res = await ac.post("/api/v1/settings/test-webhook", json={"webhook_url": "https://hooks.slack.com/test"})
        assert good_res.status_code == 200
        assert good_res.json()["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_settings_page_html():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/settings")
        assert res.status_code == 200
        assert "FRAMEWORK CONFIGURATION & SECURITY POLICIES" in res.text
        assert "01 Cryptographic" in res.text
        assert "02 Telemetry" in res.text
        assert "03 IOC & Threat Rules" in res.text
        assert "04 Report Defaults" in res.text
        assert "05 Access Control (RBAC)" in res.text
        assert "06 Storage & DB" in res.text
        assert "07 SIEM & Alerts" in res.text
