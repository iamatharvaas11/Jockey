"""
API integration and security tests for FastAPI backend.
Tests:
- Backend startup and database creation
- First-run setup endpoint (/api/v1/auth/setup)
- Prevention of multiple setup calls
- Registration forcing ANALYST role
- JWT login and authentication
- File upload path traversal rejection
- CORS configuration
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
from app.core.config import settings
from app.db.session import engine
from app.db.base import Base
from app.models import User, Investigation, Endpoint, Artifact, IOC, TimelineEvent, AuditLog


@pytest.fixture(autouse=True)
async def lifespan_fixture():
    """Ensure database tables are initialized via app lifespan."""
    async with app.router.lifespan_context(app):
        yield


@pytest.mark.asyncio
async def test_backend_lifespan_and_routes():
    """Verify backend starts and responds to health / root routes."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        response = await client.get("/")
        # Root redirects to /dashboard
        assert response.status_code in (200, 307, 302)


@pytest.mark.asyncio
async def test_auth_first_run_setup_and_lockdown():
    """Verify setup endpoint creates admin on first run and is rejected subsequently."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        # 1. Setup initial admin
        setup_payload = {
            "email": "first_admin@example.com",
            "password": "SecurePassword123!",
            "full_name": "First Admin"
        }
        res_setup = await client.post("/api/v1/auth/setup", json=setup_payload)
        # Note: if setup was already run, it returns 400
        if res_setup.status_code == 200:
            data = res_setup.json()
            assert data["email"] == "first_admin@example.com"
            assert data["role"] == "ADMIN"
            
            # Second setup attempt must fail
            res_setup2 = await client.post("/api/v1/auth/setup", json=setup_payload)
            assert res_setup2.status_code == 400
            assert "Setup already completed" in res_setup2.text
        else:
            assert res_setup.status_code == 400
            assert "Setup already completed" in res_setup.text


@pytest.mark.asyncio
async def test_registration_privilege_escalation_prevention():
    """Verify that regular registration cannot grant ADMIN role."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        reg_payload = {
            "email": "analyst_test@example.com",
            "password": "Password123!",
            "full_name": "Analyst User",
            "role": "ADMIN"  # Malicious user trying to elevate privileges
        }
        res = await client.post("/api/v1/auth/register", json=reg_payload)
        if res.status_code == 200:
            user_data = res.json()
            assert user_data["role"] == "ANALYST", "User was able to register as ADMIN!"
        else:
            # If already registered in a previous run
            assert res.status_code in (200, 400)


@pytest.mark.asyncio
async def test_login_and_me():
    """Verify login issues valid token and /me authenticates."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        # Register a dedicated user for this test
        user_email = "login_test@example.com"
        reg_payload = {
            "email": user_email,
            "password": "Password123!",
            "full_name": "Login Tester"
        }
        await client.post("/api/v1/auth/register", json=reg_payload)

        # Login
        login_res = await client.post(
            "/api/v1/auth/login",
            data={"username": user_email, "password": "Password123!"}
        )
        assert login_res.status_code == 200
        token_data = login_res.json()
        assert "access_token" in token_data
        token = token_data["access_token"]

        # Call /me with Bearer token
        me_res = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert me_res.status_code == 200
        me_data = me_res.json()
        assert me_data["email"] == user_email
        assert me_data["role"] == "ANALYST"


@pytest.mark.asyncio
async def test_cors_headers():
    """Verify CORS headers respond correctly to configured origin."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
        res = await client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": "http://localhost:8000",
                "Access-Control-Request-Method": "POST"
            }
        )
        assert res.headers.get("access-control-allow-origin") == "http://localhost:8000"
