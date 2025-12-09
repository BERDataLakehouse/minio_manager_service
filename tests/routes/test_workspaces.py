"""Comprehensive tests for the routes.workspaces module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.minio.models.policy import (
    PolicyDocument,
    PolicyModel,
    PolicyStatement,
    PolicyEffect,
    PolicyAction,
)
from src.minio.models.user import UserModel
from src.minio.models.group import GroupModel
from src.routes.workspaces import router
from src.service.app_state import AppState
from src.service.exception_handlers import universal_error_handler
from src.service.kb_auth import AdminPermission, KBaseUser


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def app():
    """Create a FastAPI app with the workspaces router and exception handlers."""
    test_app = FastAPI()
    test_app.include_router(router)
    test_app.add_exception_handler(Exception, universal_error_handler)
    return test_app


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def mock_app_state():
    """Create a mock AppState."""
    state = MagicMock(spec=AppState)
    state.user_manager = MagicMock()
    state.group_manager = MagicMock()
    state.policy_manager = MagicMock()

    # Set config attributes
    state.user_manager.config = MagicMock()
    state.user_manager.config.default_bucket = "test-bucket"
    state.user_manager.users_sql_warehouse_prefix = "users-sql-warehouse"

    state.group_manager.config = MagicMock()
    state.group_manager.config.default_bucket = "test-bucket"
    state.group_manager.tenant_sql_warehouse_prefix = "tenant-sql-warehouse"

    return state


@pytest.fixture
def mock_authenticated_user():
    """Create a mock authenticated KBase user."""
    return KBaseUser(
        user="testuser",
        admin_perm=AdminPermission.NONE,
    )


@pytest.fixture
def sample_user_model():
    """Create a sample UserModel."""
    return UserModel(
        username="testuser",
        access_key="TESTKEY",
        secret_key="TESTSECRET",
        home_paths=["s3a://test-bucket/users-sql-warehouse/testuser/"],
        groups=["group1", "group2"],
        user_policies=[],
        group_policies=[],
        total_policies=0,
        accessible_paths=["s3a://test-bucket/users-sql-warehouse/testuser/"],
    )


@pytest.fixture
def sample_policy_model():
    """Create a sample PolicyModel."""
    return PolicyModel(
        policy_name="user-home-policy-testuser",
        policy_document=PolicyDocument(
            statement=[
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.GET_OBJECT,
                    resource=[
                        "arn:aws:s3:::test-bucket/users-sql-warehouse/testuser/*"
                    ],
                )
            ]
        ),
    )


@pytest.fixture
def sample_group_info():
    """Create a sample GroupModel."""
    return GroupModel(group_name="testgroup", members=["testuser", "user2"])


# =============================================================================
# Test /workspaces/me - Get My Workspace
# =============================================================================


class TestGetMyWorkspace:
    """Tests for GET /workspaces/me endpoint."""

    def test_get_my_workspace_success(
        self, client, mock_app_state, mock_authenticated_user, sample_user_model
    ):
        """Test successfully getting workspace for authenticated user."""
        mock_app_state.user_manager.get_user = AsyncMock(return_value=sample_user_model)

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["access_key"] == "TESTKEY"

    def test_get_my_workspace_user_not_found(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test getting workspace when user doesn't exist."""
        mock_app_state.user_manager.get_user = AsyncMock(
            side_effect=Exception("User not found")
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me")

        assert response.status_code == 500


# =============================================================================
# Test /workspaces/me/groups - Get My Groups
# =============================================================================


class TestGetMyGroups:
    """Tests for GET /workspaces/me/groups endpoint."""

    def test_get_my_groups_success(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test successfully getting user's groups."""
        mock_app_state.group_manager.get_user_groups = AsyncMock(
            return_value=["group1", "group2", "group3"]
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/groups")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["groups"] == ["group1", "group2", "group3"]
        assert data["group_count"] == 3

    def test_get_my_groups_empty(self, client, mock_app_state, mock_authenticated_user):
        """Test getting groups when user has no groups."""
        mock_app_state.group_manager.get_user_groups = AsyncMock(return_value=[])

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/groups")

        assert response.status_code == 200
        data = response.json()
        assert data["groups"] == []
        assert data["group_count"] == 0


# =============================================================================
# Test /workspaces/me/policies - Get My Policies
# =============================================================================


class TestGetMyPolicies:
    """Tests for GET /workspaces/me/policies endpoint."""

    def test_get_my_policies_success(
        self, client, mock_app_state, mock_authenticated_user, sample_policy_model
    ):
        """Test successfully getting user's policies."""
        policies_data = {
            "user_home_policy": sample_policy_model,
            "user_system_policy": sample_policy_model,
            "group_policies": [sample_policy_model],
        }
        mock_app_state.user_manager.get_user_policies = AsyncMock(
            return_value=policies_data
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/policies")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["total_policies"] == 3  # 2 user policies + 1 group policy

    def test_get_my_policies_no_group_policies(
        self, client, mock_app_state, mock_authenticated_user, sample_policy_model
    ):
        """Test getting policies when user has no group policies."""
        policies_data = {
            "user_home_policy": sample_policy_model,
            "user_system_policy": sample_policy_model,
            "group_policies": [],
        }
        mock_app_state.user_manager.get_user_policies = AsyncMock(
            return_value=policies_data
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/policies")

        assert response.status_code == 200
        data = response.json()
        assert data["total_policies"] == 2


# =============================================================================
# Test /workspaces/me/accessible-paths - Get My Accessible Paths
# =============================================================================


class TestGetMyAccessiblePaths:
    """Tests for GET /workspaces/me/accessible-paths endpoint."""

    def test_get_my_accessible_paths_success(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test successfully getting accessible paths."""
        paths = [
            "s3a://test-bucket/users-sql-warehouse/testuser/",
            "s3a://test-bucket/users-general-warehouse/testuser/",
            "s3a://test-bucket/tenant-sql-warehouse/group1/",
        ]
        mock_app_state.user_manager.get_user_accessible_paths = AsyncMock(
            return_value=paths
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/accessible-paths")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["accessible_paths"] == paths
        assert data["total_paths"] == 3

    def test_get_my_accessible_paths_empty(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test getting accessible paths when user has no access."""
        mock_app_state.user_manager.get_user_accessible_paths = AsyncMock(
            return_value=[]
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/accessible-paths")

        assert response.status_code == 200
        data = response.json()
        assert data["accessible_paths"] == []
        assert data["total_paths"] == 0


# =============================================================================
# Test /workspaces/me/groups/{group_name} - Get Group Workspace
# =============================================================================


class TestGetGroupWorkspace:
    """Tests for GET /workspaces/me/groups/{group_name} endpoint."""

    def test_get_group_workspace_success(
        self,
        client,
        mock_app_state,
        mock_authenticated_user,
        sample_group_info,
        sample_policy_model,
    ):
        """Test successfully getting group workspace info."""
        mock_app_state.group_manager.is_user_in_group = AsyncMock(return_value=True)
        mock_app_state.group_manager.get_group_info = AsyncMock(
            return_value=sample_group_info
        )
        mock_app_state.policy_manager.get_group_policy = AsyncMock(
            return_value=sample_policy_model
        )
        mock_app_state.policy_manager.get_accessible_paths_from_policy = MagicMock(
            return_value=["s3a://test-bucket/tenant-sql-warehouse/testgroup/"]
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/groups/testgroup")

        assert response.status_code == 200
        data = response.json()
        assert data["group_name"] == "testgroup"
        assert data["member_count"] == 2
        assert len(data["accessible_paths"]) == 1

    def test_get_group_workspace_not_member(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test getting group workspace when user is not a member."""
        mock_app_state.group_manager.is_user_in_group = AsyncMock(return_value=False)

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/groups/testgroup")

        assert response.status_code == 403  # DataGovernanceError maps to 403

    def test_get_group_workspace_ro_member(
        self,
        client,
        mock_app_state,
        mock_authenticated_user,
        sample_group_info,
        sample_policy_model,
    ):
        """Test getting group workspace when user is RO member."""
        # Not a regular member, but is RO member
        mock_app_state.group_manager.is_user_in_group = AsyncMock(
            side_effect=[False, True]
        )
        mock_app_state.group_manager.get_group_info = AsyncMock(
            return_value=sample_group_info
        )
        mock_app_state.policy_manager.get_group_policy = AsyncMock(
            return_value=sample_policy_model
        )
        mock_app_state.policy_manager.get_accessible_paths_from_policy = MagicMock(
            return_value=["s3a://test-bucket/tenant-sql-warehouse/testgroup/"]
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/groups/testgroup")

        assert response.status_code == 200


# =============================================================================
# Test /workspaces/me/sql-warehouse-prefix - Get My SQL Warehouse Prefix
# =============================================================================


class TestGetMySqlWarehousePrefix:
    """Tests for GET /workspaces/me/sql-warehouse-prefix endpoint."""

    def test_get_my_sql_warehouse_prefix_success(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test successfully getting SQL warehouse prefix."""
        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/sql-warehouse-prefix")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert "users-sql-warehouse/testuser" in data["sql_warehouse_prefix"]


# =============================================================================
# Test /workspaces/me/groups/{group_name}/sql-warehouse-prefix
# =============================================================================


class TestGetGroupSqlWarehousePrefix:
    """Tests for GET /workspaces/me/groups/{group_name}/sql-warehouse-prefix endpoint."""

    def test_get_group_sql_warehouse_prefix_success(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test successfully getting group SQL warehouse prefix."""
        mock_app_state.group_manager.is_user_in_group = AsyncMock(return_value=True)

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get(
                    "/workspaces/me/groups/testgroup/sql-warehouse-prefix"
                )

        assert response.status_code == 200
        data = response.json()
        assert data["group_name"] == "testgroup"
        assert "tenant-sql-warehouse/testgroup" in data["sql_warehouse_prefix"]

    def test_get_group_sql_warehouse_prefix_not_member(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test getting group SQL warehouse prefix when not a member."""
        mock_app_state.group_manager.is_user_in_group = AsyncMock(return_value=False)

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get(
                    "/workspaces/me/groups/testgroup/sql-warehouse-prefix"
                )

        assert response.status_code == 403  # DataGovernanceError maps to 403

    def test_get_group_sql_warehouse_prefix_ro_member(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test getting group SQL warehouse prefix as RO member."""
        mock_app_state.group_manager.is_user_in_group = AsyncMock(
            side_effect=[False, True]
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get(
                    "/workspaces/me/groups/testgroup/sql-warehouse-prefix"
                )

        assert response.status_code == 200


# =============================================================================
# Test /workspaces/me/namespace-prefix - Get Namespace Prefix
# =============================================================================


class TestGetNamespacePrefix:
    """Tests for GET /workspaces/me/namespace-prefix endpoint."""

    def test_get_namespace_prefix_user_only(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test getting namespace prefix for user only (no tenant)."""
        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get("/workspaces/me/namespace-prefix")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["user_namespace_prefix"] == "u_testuser__"
        assert data["tenant"] is None
        assert data["tenant_namespace_prefix"] is None

    def test_get_namespace_prefix_with_tenant(
        self, client, mock_app_state, mock_authenticated_user, sample_group_info
    ):
        """Test getting namespace prefix with tenant."""
        mock_app_state.group_manager.get_group_info = AsyncMock(
            return_value=sample_group_info
        )
        mock_app_state.group_manager.is_user_in_group = AsyncMock(return_value=True)

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get(
                    "/workspaces/me/namespace-prefix?tenant=testgroup"
                )

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["user_namespace_prefix"] == "u_testuser__"
        assert data["tenant"] == "testgroup"
        assert data["tenant_namespace_prefix"] == "testgroup_"

    def test_get_namespace_prefix_tenant_not_found(
        self, client, mock_app_state, mock_authenticated_user
    ):
        """Test getting namespace prefix when tenant doesn't exist."""
        mock_app_state.group_manager.get_group_info = AsyncMock(return_value=None)

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get(
                    "/workspaces/me/namespace-prefix?tenant=nonexistent"
                )

        assert response.status_code == 403  # DataGovernanceError maps to 403

    def test_get_namespace_prefix_not_member_of_tenant(
        self, client, mock_app_state, mock_authenticated_user, sample_group_info
    ):
        """Test getting namespace prefix when user is not a member of tenant."""
        mock_app_state.group_manager.get_group_info = AsyncMock(
            return_value=sample_group_info
        )
        mock_app_state.group_manager.is_user_in_group = AsyncMock(return_value=False)

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get(
                    "/workspaces/me/namespace-prefix?tenant=testgroup"
                )

        assert response.status_code == 403  # DataGovernanceError maps to 403

    def test_get_namespace_prefix_ro_member_of_tenant(
        self, client, mock_app_state, mock_authenticated_user, sample_group_info
    ):
        """Test getting namespace prefix as RO member of tenant."""
        mock_app_state.group_manager.get_group_info = AsyncMock(
            return_value=sample_group_info
        )
        mock_app_state.group_manager.is_user_in_group = AsyncMock(
            side_effect=[False, True]
        )

        with patch("src.routes.workspaces.get_app_state", return_value=mock_app_state):
            with patch(
                "src.service.app_state.get_request_user",
                return_value=mock_authenticated_user,
            ):
                response = client.get(
                    "/workspaces/me/namespace-prefix?tenant=testgroup"
                )

        assert response.status_code == 200
        data = response.json()
        assert data["tenant_namespace_prefix"] == "testgroup_"


# =============================================================================
# Test Authentication
# =============================================================================


class TestAuthentication:
    """Tests for authentication requirements."""

    def test_endpoints_require_authentication(self, client):
        """Test that all endpoints require authentication."""
        endpoints = [
            "/workspaces/me",
            "/workspaces/me/groups",
            "/workspaces/me/policies",
            "/workspaces/me/accessible-paths",
            "/workspaces/me/sql-warehouse-prefix",
            "/workspaces/me/namespace-prefix",
            "/workspaces/me/groups/testgroup",
            "/workspaces/me/groups/testgroup/sql-warehouse-prefix",
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            # Should fail without authentication (403 or 401)
            assert response.status_code in [401, 403]
