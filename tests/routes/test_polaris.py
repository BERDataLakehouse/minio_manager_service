"""Tests for the routes.polaris module."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes.polaris import router
from credentials.polaris_store import PolarisCredentialRecord
from polaris.managers.group_manager import PolarisGroupManager
from polaris.managers.user_manager import PolarisUserManager
from service import app_state
from service.dependencies import auth
from service.exception_handlers import universal_error_handler
from service.exceptions import PolarisOperationError
from service.kb_auth import AdminPermission, KBaseUser


# === FIXTURES ===


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Ensure MC_PATH is set for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


@pytest.fixture
def mock_polaris_service():
    """Create a mock PolarisService with the methods exercised by the route."""
    polaris = AsyncMock()
    polaris.minio_endpoint = "http://minio:9002"
    polaris.create_catalog = AsyncMock(return_value={})
    polaris.create_principal = AsyncMock(return_value={})
    polaris.create_catalog_role = AsyncMock(return_value={})
    polaris.grant_catalog_privilege = AsyncMock(return_value={})
    polaris.create_principal_role = AsyncMock(return_value={})
    polaris.grant_catalog_role_to_principal_role = AsyncMock(return_value={})
    polaris.grant_principal_role_to_principal = AsyncMock(return_value={})
    polaris.ensure_tenant_catalog = AsyncMock(return_value=None)
    return polaris


@pytest.fixture
def mock_app_state_obj(mock_polaris_service):
    """Create a mock application state with Polaris service.

    The PolarisUserManager / PolarisGroupManager are *real* instances wired
    to the mocked PolarisService so the existing assertions on
    ``mock_polaris_service.*`` calls still verify the full route → helper →
    manager → service chain.
    """
    state = MagicMock()

    # Pre-built warehouse base URLs (mirrors AppState.build_app()).
    state.users_sql_warehouse_base = "s3a://cdm-lake/users-sql-warehouse"
    state.tenant_sql_warehouse_base = "s3a://cdm-lake/tenant-sql-warehouse"

    # Group manager
    state.group_manager = AsyncMock()
    state.group_manager.get_user_groups = AsyncMock(return_value=[])

    # Polaris service + real managers pointing at it.
    state.polaris_service = mock_polaris_service
    state.polaris_user_manager = PolarisUserManager(
        polaris_service=mock_polaris_service,
        users_sql_warehouse_base=state.users_sql_warehouse_base,
    )
    state.polaris_group_manager = PolarisGroupManager(
        polaris_service=mock_polaris_service,
        tenant_sql_warehouse_base=state.tenant_sql_warehouse_base,
    )
    state.polaris_credential_service = AsyncMock()
    state.polaris_credential_service.get_or_create = AsyncMock(
        return_value=PolarisCredentialRecord(
            client_id="test-client-id",
            client_secret="test-client-secret",
            personal_catalog="user_testuser",
        )
    )
    state.polaris_credential_service.rotate = AsyncMock(
        return_value=PolarisCredentialRecord(
            client_id="rotated-client-id",
            client_secret="rotated-client-secret",
            personal_catalog="user_testuser",
        )
    )

    return state


@pytest.fixture
def regular_user():
    """Create a regular (non-admin) user."""
    return KBaseUser(user="testuser", admin_perm=AdminPermission.NONE)


@pytest.fixture
def admin_user():
    """Create an admin user."""
    return KBaseUser(user="admin", admin_perm=AdminPermission.FULL)


def _create_test_app(mock_state, authenticated_user):
    """Helper to create a test FastAPI app with dependency overrides."""
    test_app = FastAPI()
    test_app.include_router(router)
    test_app.add_exception_handler(Exception, universal_error_handler)

    # Override only `auth` — `require_admin` chains through the real `auth`
    # dependency, so overriding `auth` is enough to drive both code paths.
    test_app.dependency_overrides[auth] = lambda: authenticated_user
    test_app.dependency_overrides[app_state.get_app_state] = lambda: mock_state

    return test_app


# === PROVISION POLARIS USER TESTS ===


class TestProvisionPolarisUser:
    """Tests for POST /polaris/user_provision/{username}."""

    def test_provision_own_catalog_success(self, mock_app_state_obj, regular_user):
        """Test user can provision their own catalog."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/testuser")

        assert response.status_code == 200
        data = response.json()
        assert data["client_id"] == "test-client-id"
        assert data["client_secret"] == "test-client-secret"
        assert data["personal_catalog"] == "user_testuser"
        assert data["tenant_catalogs"] == []

    def test_provision_catalog_correct_storage_location(
        self, mock_app_state_obj, regular_user
    ):
        """Test catalog is created with correct SQL warehouse + iceberg path."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        client.post("/polaris/user_provision/testuser")

        mock_app_state_obj.polaris_service.create_catalog.assert_called_once_with(
            name="user_testuser",
            storage_location="s3a://cdm-lake/users-sql-warehouse/testuser/iceberg/",
        )

    def test_provision_catalog_creates_all_polaris_resources(
        self, mock_app_state_obj, regular_user
    ):
        """Test the full provisioning flow creates all required Polaris resources."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        polaris = mock_app_state_obj.polaris_service

        client = TestClient(app, raise_server_exceptions=False)
        client.post("/polaris/user_provision/testuser")

        # Verify all provisioning steps executed
        polaris.create_catalog.assert_called_once()
        polaris.create_principal.assert_called_once_with(name="testuser")
        polaris.create_catalog_role.assert_called_once_with(
            catalog="user_testuser", role_name="catalog_admin"
        )
        polaris.grant_catalog_privilege.assert_called_once_with(
            catalog="user_testuser",
            role_name="catalog_admin",
            privilege="CATALOG_MANAGE_CONTENT",
        )
        polaris.create_principal_role.assert_called_once_with(role_name="testuser_role")
        polaris.grant_catalog_role_to_principal_role.assert_called_once_with(
            catalog="user_testuser",
            catalog_role="catalog_admin",
            principal_role="testuser_role",
        )
        polaris.grant_principal_role_to_principal.assert_called_once_with(
            principal="testuser", principal_role="testuser_role"
        )
        mock_app_state_obj.polaris_credential_service.get_or_create.assert_called_once_with(
            username="testuser",
            personal_catalog="user_testuser",
        )

    def test_provision_other_user_catalog_forbidden(
        self, mock_app_state_obj, regular_user
    ):
        """Test non-admin user cannot provision another user's catalog."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/otheruser")

        assert response.status_code == 403

    def test_admin_provision_other_user_catalog(self, mock_app_state_obj, admin_user):
        """Test admin can provision any user's catalog."""
        app = _create_test_app(mock_app_state_obj, admin_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/otheruser")

        assert response.status_code == 200
        assert response.json()["personal_catalog"] == "user_otheruser"

    def test_provision_catalog_polaris_error_returns_structured_500(
        self, mock_app_state_obj, regular_user
    ):
        """Test PolarisOperationError surfaces through the universal error handler."""
        mock_app_state_obj.polaris_service.create_catalog.side_effect = (
            PolarisOperationError("Polaris is unhappy", status=500)
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/testuser")

        assert response.status_code == 500
        body = response.json()
        # Universal handler maps PolarisOperationError → POLARIS_OPERATION_ERROR.
        assert body["error_type"] == "Polaris catalog operation error"
        assert "Polaris is unhappy" in body["message"]

    def test_provision_catalog_unexpected_error_does_not_leak_internals(
        self, mock_app_state_obj, regular_user
    ):
        """Test generic exceptions are sanitized to 'An unexpected error occurred'."""
        mock_app_state_obj.polaris_service.create_catalog.side_effect = RuntimeError(
            "internal segfault details"
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/testuser")

        assert response.status_code == 500
        body = response.json()
        assert body["message"] == "An unexpected error occurred"
        # Internal RuntimeError details must not leak.
        assert "segfault" not in str(body).lower()

    def test_provision_catalog_with_group_memberships(
        self, mock_app_state_obj, regular_user
    ):
        """Test tenant catalogs are included from group memberships."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["teamA", "teamBro"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/testuser")

        data = response.json()
        assert "tenant_teamA" in data["tenant_catalogs"]
        # "teamBro" ends with "ro" so strips suffix
        assert "tenant_teamB" in data["tenant_catalogs"]

    def test_provision_ensures_tenant_catalogs_for_groups(
        self, mock_app_state_obj, regular_user
    ):
        """Test ensure_tenant_catalog is called once per base group."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["teamA", "teamBro"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/testuser")

        assert response.status_code == 200

        polaris = mock_app_state_obj.polaris_service
        # Should call ensure_tenant_catalog for both groups
        # "teamA" (non-ro) and "teamB" (base of "teamBro")
        calls = polaris.ensure_tenant_catalog.call_args_list
        call_group_names = [c[0][0] for c in calls]
        assert "teamA" in call_group_names
        assert "teamB" in call_group_names

    def test_provision_ensures_tenant_catalog_uses_tenant_warehouse_base(
        self, mock_app_state_obj, regular_user
    ):
        """Test ensure_tenant_catalog is called with the tenant warehouse path."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["teamA"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        client.post("/polaris/user_provision/testuser")

        mock_app_state_obj.polaris_service.ensure_tenant_catalog.assert_called_once_with(
            "teamA",
            "s3a://cdm-lake/tenant-sql-warehouse/teamA/iceberg/",
        )

    def test_provision_catalog_with_globalusers_group(
        self, mock_app_state_obj, regular_user
    ):
        """Test tenant_globalusers is added for globalusers group members."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["globalusers"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/testuser")

        data = response.json()
        assert "tenant_globalusers" in data["tenant_catalogs"]

    def test_provision_catalog_with_globalusersro_group(
        self, mock_app_state_obj, regular_user
    ):
        """Test tenant_globalusers is added for globalusersro group members."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["globalusersro"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/testuser")

        data = response.json()
        assert "tenant_globalusers" in data["tenant_catalogs"]

    def test_provision_dedups_when_user_in_both_write_and_read_variants(
        self, mock_app_state_obj, regular_user
    ):
        """Test the same base tenant appears once and only the writer role is bound."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["teamA", "teamAro"]  # both variants of the same base
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/testuser")

        # Tenant appears exactly once in the response.
        assert response.json()["tenant_catalogs"] == ["tenant_teamA"]

        # ensure_tenant_catalog called once per base group (not once per variant).
        polaris = mock_app_state_obj.polaris_service
        assert polaris.ensure_tenant_catalog.call_count == 1
        polaris.ensure_tenant_catalog.assert_called_once_with(
            "teamA", "s3a://cdm-lake/tenant-sql-warehouse/teamA/iceberg/"
        )

        # Only the WRITER principal role binding is granted (write supersedes read).
        tenant_grant_calls = [
            call
            for call in polaris.grant_principal_role_to_principal.call_args_list
            if call.kwargs.get("principal_role", "").startswith("teamA")
            or (len(call.args) >= 2 and call.args[1].startswith("teamA"))
        ]
        assert len(tenant_grant_calls) == 1
        # Positional call: grant_principal_role_to_principal(username, role)
        granted_role = tenant_grant_calls[0].args[1]
        assert granted_role == "teamA_member"  # writer, not "teamAro_member"

    def test_provision_skips_empty_base_group_defensively(
        self, mock_app_state_obj, regular_user
    ):
        """Test a group named exactly 'ro' (normalises to '') is skipped."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["ro", "teamA"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/user_provision/testuser")

        data = response.json()
        # No "tenant_" entry from the empty base.
        assert "tenant_" not in data["tenant_catalogs"]
        assert data["tenant_catalogs"] == ["tenant_teamA"]
        polaris = mock_app_state_obj.polaris_service
        polaris.ensure_tenant_catalog.assert_called_once_with(
            "teamA", "s3a://cdm-lake/tenant-sql-warehouse/teamA/iceberg/"
        )


class TestRotatePolarisCredentials:
    """Tests for POST /polaris/credentials/rotate/{username}."""

    def test_rotate_own_credentials_success(self, mock_app_state_obj, regular_user):
        """Test users can explicitly rotate their own Polaris credentials."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/credentials/rotate/testuser")

        assert response.status_code == 200
        data = response.json()
        assert data["client_id"] == "rotated-client-id"
        assert data["client_secret"] == "rotated-client-secret"
        assert data["personal_catalog"] == "user_testuser"
        mock_app_state_obj.polaris_credential_service.rotate.assert_called_once_with(
            username="testuser",
            personal_catalog="user_testuser",
        )

    def test_rotate_other_user_forbidden(self, mock_app_state_obj, regular_user):
        """Test non-admin users cannot rotate another user's Polaris credentials."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/credentials/rotate/otheruser")

        assert response.status_code == 403

    def test_admin_rotate_other_user_credentials(self, mock_app_state_obj, admin_user):
        """Test admins can rotate another user's Polaris credentials."""
        app = _create_test_app(mock_app_state_obj, admin_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/polaris/credentials/rotate/otheruser")

        assert response.status_code == 200
        mock_app_state_obj.polaris_credential_service.rotate.assert_called_once_with(
            username="otheruser",
            personal_catalog="user_otheruser",
        )

    def test_rotate_credentials_unexpected_error_sanitised(
        self,
        mock_app_state_obj,
        regular_user,
    ):
        """Test rotation errors return a clean 500 via the universal handler."""
        mock_app_state_obj.polaris_credential_service.rotate.side_effect = RuntimeError(
            "rotation failed internals"
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post("/polaris/credentials/rotate/testuser")

        assert response.status_code == 500
        body = response.json()
        assert body["message"] == "An unexpected error occurred"
        assert "rotation failed internals" not in str(body)


class TestEffectiveAccess:
    """Tests for GET /polaris/effective-access endpoints."""

    def test_get_my_effective_access(
        self,
        mock_app_state_obj,
        regular_user,
    ):
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["teamA", "teamBro"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/polaris/effective-access/me")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["personal_catalog"] == "user_testuser"
        assert data["group_tenants"] == [
            {
                "tenant_name": "teamA",
                "catalog_name": "tenant_teamA",
                "access_level": "read_write",
            },
            {
                "tenant_name": "teamB",
                "catalog_name": "tenant_teamB",
                "access_level": "read_only",
            },
        ]

    def test_admin_gets_effective_access_for_user(
        self,
        mock_app_state_obj,
        admin_user,
    ):
        app = _create_test_app(mock_app_state_obj, admin_user)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/polaris/effective-access/alice")

        assert response.status_code == 200
        assert response.json()["username"] == "alice"
        mock_app_state_obj.group_manager.get_user_groups.assert_called_with("alice")

    def test_regular_user_cannot_get_other_user_effective_access(
        self, mock_app_state_obj, regular_user
    ):
        """Test regular users get 403 when querying another user's access."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/polaris/effective-access/otheruser")

        assert response.status_code == 403
        # group_manager must NOT have been queried — auth fired first.
        mock_app_state_obj.group_manager.get_user_groups.assert_not_called()

    def test_effective_access_skips_empty_group_and_prefers_read_write(
        self,
        mock_app_state_obj,
        regular_user,
    ):
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["", "teamA", "teamAro"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/polaris/effective-access/me")

        assert response.status_code == 200
        assert response.json()["group_tenants"] == [
            {
                "tenant_name": "teamA",
                "catalog_name": "tenant_teamA",
                "access_level": "read_write",
            }
        ]

    def test_effective_access_prefers_read_write_regardless_of_iteration_order(
        self,
        mock_app_state_obj,
        regular_user,
    ):
        """Test RW preference holds when read variant comes first in input."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["teamAro", "teamA"]  # read variant first
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/polaris/effective-access/me")

        assert response.status_code == 200
        assert response.json()["group_tenants"] == [
            {
                "tenant_name": "teamA",
                "catalog_name": "tenant_teamA",
                "access_level": "read_write",
            }
        ]
