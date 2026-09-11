"""
Security regression tests for the JOCKY backend.
Verifies that the Stage 1 security fixes are working correctly.

These tests verify:
1. No hard-coded admin credentials
2. Registration cannot escalate to ADMIN role
3. File upload path traversal is prevented
4. CORS is not wildcard
5. JWT SECRET_KEY handling is correct
6. First-run setup endpoint works correctly
"""
import pytest
import os
import sys


class TestNoHardcodedCredentials:
    """Verify no hard-coded credentials exist in the codebase."""

    def _read_file(self, filepath):
        """Read a file and return its contents."""
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()

    def _get_project_root(self):
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_main_py_no_admin_password(self):
        """main.py must not contain hard-coded admin passwords."""
        root = self._get_project_root()
        content = self._read_file(os.path.join(root, "backend", "app", "main.py"))
        assert "admin123" not in content, "Hard-coded admin password found in main.py"
        assert 'hash_password("' not in content, "Hard-coded password hashing found in main.py"

    def test_main_py_no_admin_email_seeding(self):
        """main.py must not seed a default admin user."""
        root = self._get_project_root()
        content = self._read_file(os.path.join(root, "backend", "app", "main.py"))
        assert "admin@jocky.org" not in content, "Hard-coded admin email found in main.py"

    def test_config_no_static_secret(self):
        """config.py must not have a static SECRET_KEY default."""
        root = self._get_project_root()
        content = self._read_file(os.path.join(root, "backend", "app", "core", "config.py"))
        # Should not have a hard-coded string as default SECRET_KEY
        # It should be None or loaded from environment
        assert 'SECRET_KEY: str = "' not in content, \
            "Static SECRET_KEY string found in config.py"


class TestRegistrationSecurity:
    """Verify registration endpoint prevents privilege escalation."""

    def test_register_forces_analyst_role(self):
        """The register endpoint must force role to ANALYST regardless of input."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        content = open(os.path.join(root, "backend", "app", "api", "v1", "endpoints", "auth.py"),
                      'r', encoding='utf-8').read()
        # The register function should set role="ANALYST" explicitly
        assert 'role="ANALYST"' in content, \
            "Register endpoint must force role to ANALYST"

    def test_user_create_schema_no_role(self):
        """UserCreate schema must not accept a role field."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        content = open(os.path.join(root, "backend", "app", "schemas", "user.py"),
                      'r', encoding='utf-8').read()
        # UserCreate should inherit from UserBase which should NOT have role
        # Find the UserBase class and check it doesn't have role
        lines = content.split('\n')
        in_user_base = False
        in_user_create = False
        for line in lines:
            if 'class UserBase' in line:
                in_user_base = True
                in_user_create = False
                continue
            if 'class UserCreate' in line:
                in_user_create = True
                in_user_base = False
                continue
            if 'class ' in line:
                in_user_base = False
                in_user_create = False
            if in_user_base and 'role' in line:
                pytest.fail("UserBase should not contain a 'role' field")
            if in_user_create and 'role' in line:
                pytest.fail("UserCreate should not contain a 'role' field")


class TestSetupEndpoint:
    """Verify the first-run setup endpoint exists."""

    def test_setup_endpoint_exists(self):
        """A /setup endpoint should exist for first-run admin creation."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        content = open(os.path.join(root, "backend", "app", "api", "v1", "endpoints", "auth.py"),
                      'r', encoding='utf-8').read()
        assert "/setup" in content, "Setup endpoint not found in auth.py"
        assert "AdminSetup" in content, "AdminSetup schema not used in auth.py"

    def test_setup_checks_existing_users(self):
        """Setup endpoint must check for existing users before creating admin."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        content = open(os.path.join(root, "backend", "app", "api", "v1", "endpoints", "auth.py"),
                      'r', encoding='utf-8').read()
        assert "Setup already completed" in content, \
            "Setup endpoint must reject if users already exist"


class TestPathTraversalPrevention:
    """Verify file upload path traversal is prevented."""

    def test_artifact_storage_sanitizes_filename(self):
        """artifact_storage.py must sanitize filenames."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        content = open(os.path.join(root, "backend", "app", "services", "artifact_storage.py"),
                      'r', encoding='utf-8').read()
        assert "secure_filename" in content or "basename" in content, \
            "Filename sanitization not found in artifact_storage.py"

    def test_secure_filename_strips_traversal(self):
        """The secure_filename function must strip path traversal attempts."""
        # Add project root to path for import
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        backend_dir = os.path.join(root, "backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        if root not in sys.path:
            sys.path.insert(0, root)

        from app.services.artifact_storage import secure_filename

        # Test path traversal attempts
        result = secure_filename("../../../../etc/passwd")
        assert ".." not in result
        assert "/" not in result
        assert "\\" not in result

    def test_secure_filename_handles_dotfiles(self):
        """The secure_filename function must reject dotfiles."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        backend_dir = os.path.join(root, "backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        if root not in sys.path:
            sys.path.insert(0, root)

        from app.services.artifact_storage import secure_filename

        result = secure_filename(".htaccess")
        assert not result.startswith(".")

    def test_secure_filename_handles_empty(self):
        """The secure_filename function must handle empty filenames."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        backend_dir = os.path.join(root, "backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        if root not in sys.path:
            sys.path.insert(0, root)

        from app.services.artifact_storage import secure_filename

        result = secure_filename("")
        assert len(result) > 0, "Empty filename should produce a UUID fallback"

    def test_secure_filename_handles_none(self):
        """The secure_filename function must handle None filenames."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        backend_dir = os.path.join(root, "backend")
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        if root not in sys.path:
            sys.path.insert(0, root)

        from app.services.artifact_storage import secure_filename

        result = secure_filename(None)
        assert len(result) > 0, "None filename should produce a UUID fallback"

    def test_realpath_verification_exists(self):
        """artifact_storage.py must verify resolved path stays within dest_dir."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        content = open(os.path.join(root, "backend", "app", "services", "artifact_storage.py"),
                      'r', encoding='utf-8').read()
        assert "realpath" in content, \
            "Path resolution verification not found in artifact_storage.py"
        assert "startswith" in content, \
            "Path containment check not found in artifact_storage.py"


class TestCORSConfiguration:
    """Verify CORS is not permissively configured."""

    def test_cors_not_wildcard(self):
        """CORS origins must not default to wildcard."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        content = open(os.path.join(root, "backend", "app", "core", "config.py"),
                      'r', encoding='utf-8').read()
        assert '["*"]' not in content, \
            "CORS origins should not default to wildcard ['*']"

    def test_cors_uses_settings(self):
        """CORS middleware must use settings, not hard-coded values."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        content = open(os.path.join(root, "backend", "app", "main.py"),
                      'r', encoding='utf-8').read()
        assert "settings.CORS_ORIGINS" in content, \
            "CORS middleware must reference settings.CORS_ORIGINS"


class TestTokenURLFix:
    """Verify the OAuth2 tokenUrl is correctly configured."""

    def test_token_url_is_string(self):
        """tokenUrl must be a string path, not an interpolated list."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        content = open(os.path.join(root, "backend", "app", "api", "deps.py"),
                      'r', encoding='utf-8').read()
        assert 'tokenUrl="/api/v1/auth/login"' in content, \
            "tokenUrl should be a simple string path"
        assert "CORS_ORIGINS" not in content, \
            "tokenUrl should not reference CORS_ORIGINS"
