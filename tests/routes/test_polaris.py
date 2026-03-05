"""Tests for the routes.polaris module."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.routes.polaris import router
from src.service import app_state
from src.service.dependencies import auth
from src.service.exception_handlers import universal_error_handler
from src.service.kb_auth import AdminPermission, KBaseUser


# === FIXTURES ===


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Ensure MC_PATH is set for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


@pytest.fixture
def mock_polaris_service():
    """Create a mock PolarisService."""
    polaris = AsyncMock()
    polaris.minio_endpoint = "http://minio:9002"
    polaris.create_catalog = AsyncMock(return_value={})
    polaris.create_principal = AsyncMock(return_value={})
    polaris.create_catalog_role = AsyncMock(return_value={})
    polaris.grant_catalog_privilege = AsyncMock(return_value={})
    polaris.create_principal_role = AsyncMock(return_value={})
    polaris.grant_catalog_role_to_principal_role = AsyncMock(return_value={})
    polaris.grant_principal_role_to_principal = AsyncMock(return_value={})
    polaris.rotate_principal_credentials = AsyncMock(
        return_value={
            "credentials": {
                "clientId": "test-client-id",
                "clientSecret": "test-client-secret",
            }
        }
    )
    return polaris


@pytest.fixture
def mock_app_state_obj(mock_polaris_service):
    """Create a mock application state with Polaris service."""
    state = MagicMock()

    # Mock user manager config
    state.user_manager = MagicMock()
    state.user_manager.config = MagicMock()
    state.user_manager.config.default_bucket = "cdm-lake"
    state.user_manager.config.users_sql_warehouse_prefix = "users-sql-warehouse"

    # Mock group manager
    state.group_manager = AsyncMock()
    state.group_manager.get_user_groups = AsyncMock(return_value=[])

    # Polaris service
    state.polaris_service = mock_polaris_service

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

    # Override dependencies
    test_app.dependency_overrides[auth] = lambda: authenticated_user
    test_app.dependency_overrides[app_state.get_app_state] = lambda: mock_state

    return test_app


# === PROVISION POLARIS USER TESTS ===


class TestProvisionPolarisUser:
    """Tests for POST /v1/polaris/user_provision/{username}."""

    def test_provision_own_catalog_success(self, mock_app_state_obj, regular_user):
        """Test user can provision their own catalog."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/v1/polaris/user_provision/testuser")

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
        client.post("/v1/polaris/user_provision/testuser")

        mock_app_state_obj.polaris_service.create_catalog.assert_called_once_with(
            name="user_testuser",
            storage_location="s3://cdm-lake/users-sql-warehouse/testuser/iceberg/",
        )

    def test_provision_catalog_creates_all_polaris_resources(
        self, mock_app_state_obj, regular_user
    ):
        """Test the full provisioning flow creates all required Polaris resources."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        polaris = mock_app_state_obj.polaris_service

        client = TestClient(app, raise_server_exceptions=False)
        client.post("/v1/polaris/user_provision/testuser")

        # Verify all 8 steps executed
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
        polaris.rotate_principal_credentials.assert_called_once_with(name="testuser")

    def test_provision_other_user_catalog_forbidden(
        self, mock_app_state_obj, regular_user
    ):
        """Test non-admin user cannot provision another user's catalog."""
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/v1/polaris/user_provision/otheruser")

        assert response.status_code == 403

    def test_admin_provision_other_user_catalog(self, mock_app_state_obj, admin_user):
        """Test admin can provision any user's catalog."""
        app = _create_test_app(mock_app_state_obj, admin_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/v1/polaris/user_provision/otheruser")

        assert response.status_code == 200
        assert response.json()["personal_catalog"] == "user_otheruser"

    def test_provision_catalog_polaris_not_configured(
        self, mock_app_state_obj, regular_user
    ):
        """Test 501 when Polaris service is not configured."""
        mock_app_state_obj.polaris_service = None
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/v1/polaris/user_provision/testuser")

        assert response.status_code == 501

    def test_provision_catalog_polaris_error(self, mock_app_state_obj, regular_user):
        """Test 500 when Polaris operations fail."""
        mock_app_state_obj.polaris_service.create_catalog.side_effect = Exception(
            "Connection refused"
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/v1/polaris/user_provision/testuser")

        assert response.status_code == 500
        assert "Failed to provision Polaris catalog" in response.json()["detail"]

    def test_provision_catalog_with_group_memberships(
        self, mock_app_state_obj, regular_user
    ):
        """Test tenant catalogs are included from group memberships."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["teamA", "teamBro"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/v1/polaris/user_provision/testuser")

        data = response.json()
        assert "tenant_teamA" in data["tenant_catalogs"]
        # "teamBro" ends with "ro" so strips suffix
        assert "tenant_teamB" in data["tenant_catalogs"]

    def test_provision_catalog_with_globalusers_group(
        self, mock_app_state_obj, regular_user
    ):
        """Test tenant_globalusers is added for globalusers group members."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["globalusers"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/v1/polaris/user_provision/testuser")

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
        response = client.post("/v1/polaris/user_provision/testuser")

        data = response.json()
        assert "tenant_globalusers" in data["tenant_catalogs"]

    def test_provision_catalog_deduplicates_tenant_catalogs(
        self, mock_app_state_obj, regular_user
    ):
        """Test duplicate tenant catalogs are removed."""
        mock_app_state_obj.group_manager.get_user_groups = AsyncMock(
            return_value=["globalusers"]
        )
        app = _create_test_app(mock_app_state_obj, regular_user)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/v1/polaris/user_provision/testuser")

        data = response.json()
        assert data["tenant_catalogs"].count("tenant_globalusers") == 1
