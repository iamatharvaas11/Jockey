"""
Tests for JOCKY Stage 8 Backend Architecture, Authentication, RBAC,
Database Repositories, Migrations, and Security Controls.
"""
import os
import sys
import tempfile
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.security import create_access_token, get_password_hash
from app.db.base import Base
from app.db.migrations import init_database
from app.main import app
from app.models.user import User
from app.models.investigation import Investigation
from app.models.evidence import Evidence
from app.models.endpoint import Endpoint
from app.repositories.user_repository import UserRepository
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.evidence_repository import EvidenceRepository
from app.repositories.endpoint_repository import EndpointRepository


@pytest.fixture
async def test_db_session():
    """Create an isolated in-memory SQLite database for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    await init_database(engine)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


# ============================================================================
# 1. Repository Tests
# ============================================================================

class TestRepositories:
    @pytest.mark.asyncio
    async def test_user_repository_crud(self, test_db_session):
        repo = UserRepository(test_db_session)
        assert await repo.count_users() == 0

        user = User(
            email="analyst@example.com",
            hashed_password=get_password_hash("Secret123"),
            full_name="Alice Analyst",
            role="ANALYST",
        )
        created = await repo.create(user)
        assert created.id is not None
        assert await repo.count_users() == 1

        fetched = await repo.get_by_email("analyst@example.com")
        assert fetched is not None
        assert fetched.role == "ANALYST"

    @pytest.mark.asyncio
    async def test_investigation_repository(self, test_db_session):
        repo = InvestigationRepository(test_db_session)
        inv = Investigation(
            case_number="CAS-TEST-001",
            title="Suspicious Beacon Activity",
            status="OPEN",
            severity="HIGH",
        )
        await repo.create(inv)

        found = await repo.get_by_case_number("CAS-TEST-001")
        assert found is not None
        assert found.title == "Suspicious Beacon Activity"

        active = await repo.list_by_status("OPEN")
        assert len(active) == 1

    @pytest.mark.asyncio
    async def test_evidence_repository(self, test_db_session):
        repo = EvidenceRepository(test_db_session)
        ev = Evidence(
            host="HOST-1",
            timestamp="2026-09-03T12:00:00Z",
            type="process",
            source="win32",
            hash="a" * 64,
            data_json={"pid": 1234, "name": "test.exe"},
        )
        await repo.create(ev)

        items = await repo.list_by_investigation(evidence_type="process")
        assert len(items) == 1
        assert items[0].data_json["pid"] == 1234

    @pytest.mark.asyncio
    async def test_endpoint_repository_heartbeat(self, test_db_session):
        repo = EndpointRepository(test_db_session)
        ep = Endpoint(
            hostname="DESKTOP-FINANCE-01",
            ip_address="192.168.1.100",
            os_type="Windows",
            agent_status="OFFLINE",
        )
        created = await repo.create(ep)
        assert created.agent_status == "OFFLINE"

        updated = await repo.update_heartbeat(created.id, status="ONLINE")
        assert updated.agent_status == "ONLINE"


# ============================================================================
# 2. RBAC & API Authorization Tests
# ============================================================================

class TestRoleBasedAccessControl:
    @pytest.mark.asyncio
    async def test_viewer_cannot_create_investigation(self):
        """Users with VIEWER role must receive HTTP 403 Forbidden when creating investigations."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = create_access_token(data={"sub": "viewer@example.com", "role": "VIEWER"})
            headers = {"Authorization": f"Bearer {token}"}

            # We override get_current_user in app dependency for isolated unit check
            from app.api.deps import get_current_user
            viewer_user = User(id="v1", email="viewer@example.com", role="VIEWER")
            app.dependency_overrides[get_current_user] = lambda: viewer_user

            try:
                resp = await client.post(
                    "/api/v1/investigations",
                    json={"title": "Unauthorized Case", "status": "OPEN"},
                    headers=headers,
                )
                assert resp.status_code == 403
                assert "Not enough permissions" in resp.json()["detail"]
            finally:
                app.dependency_overrides.pop(get_current_user, None)

    @pytest.mark.asyncio
    async def test_analyst_cannot_delete_investigation(self):
        """Users with ANALYST role must receive HTTP 403 Forbidden when attempting to delete."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            token = create_access_token(data={"sub": "analyst@example.com", "role": "ANALYST"})
            headers = {"Authorization": f"Bearer {token}"}

            from app.api.deps import get_current_user
            analyst_user = User(id="a1", email="analyst@example.com", role="ANALYST")
            app.dependency_overrides[get_current_user] = lambda: analyst_user

            try:
                resp = await client.delete("/api/v1/investigations/any-id", headers=headers)
                assert resp.status_code == 403
                assert "Not enough permissions" in resp.json()["detail"]
            finally:
                app.dependency_overrides.pop(get_current_user, None)


# ============================================================================
# 3. Security Controls: Path Traversal & Self-Admin Prevention Tests
# ============================================================================

class TestSecurityControls:
    @pytest.mark.asyncio
    async def test_path_traversal_file_upload_sanitization(self):
        from app.services.artifact_storage import sanitize_filename
        # Traversal attacks must be neutralized
        assert ".." not in sanitize_filename("../../etc/passwd")
        assert "/" not in sanitize_filename("../../etc/passwd")
        assert "\\" not in sanitize_filename("..\\..\\windows\\system32\\cmd.exe")
        assert sanitize_filename("") != ""  # Generates safe UUID fallback
