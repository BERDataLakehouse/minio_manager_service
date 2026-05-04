"""
Comprehensive tests for the routes.management module.

Tests cover:
- User management endpoints (list, create, rotate, delete)
- Group management endpoints (list, create, add/remove member, delete)
- Pagination
- Response model validation
- Error handling and admin authorization
"""

import os
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from s3.models.policy import PolicyDocument, PolicyModel, PolicyTarget

from credentials.polaris_store import PolarisCredentialRecord
from s3.models.user import UserModel
from routes.management import (
    EnsurePolarisResponse,
    GroupManagementResponse,
    GroupNamesResponse,
    MigrationError,
    RegeneratePoliciesResponse,
    ResourceDeleteResponse,
    RotateAllCredentialsResponse,
    UserListResponse,
    UserManagementResponse,
    UserNamesResponse,
    create_user,
    list_group_names,
    list_user_names,
    list_users,
    router,
)
from service.dependencies import auth, require_admin
from service.exception_handlers import universal_error_handler
from service.exceptions import TenantNotFoundError
from service.kb_auth import AdminPermission, KBaseUser


# === FIXTURES ===


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Ensure MC_PATH is set for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


@pytest.fixture
def mock_app_state():
    """Create a mock application state."""
    app_state = MagicMock()

    # Mock user manager
    app_state.user_manager = AsyncMock()
    app_state.user_manager.list_resources = AsyncMock(return_value=["user1", "user2"])
    app_state.user_manager.get_user = AsyncMock(
        return_value=UserModel(
            username="user1",
            access_key="user1",
            secret_key=None,
            home_paths=["s3a://bucket/users/user1/"],
            groups=[],
            total_policies=2,
        )
    )
    mock_created_user = MagicMock()
    mock_created_user.username = "newuser"
    mock_created_user.access_key = "newuser"
    mock_created_user.secret_key = "secret-key-123"
    mock_created_user.home_paths = ["s3a://bucket/users/newuser/"]
    mock_created_user.groups = []
    mock_created_user.total_policies = 2
    app_state.user_manager.create_user = AsyncMock(return_value=mock_created_user)
    app_state.user_manager.get_or_rotate_user_credentials = AsyncMock(
        return_value=("user1", "new-secret-key")
    )
    app_state.user_manager.delete_resource = AsyncMock(return_value=True)

    # Mock group manager
    app_state.group_manager = AsyncMock()
    app_state.group_manager.list_resources = AsyncMock(return_value=["group1"])
    mock_group_info = MagicMock()
    mock_group_info.group_name = "group1"
    mock_group_info.members = ["user1"]
    app_state.group_manager.get_group_info = AsyncMock(return_value=mock_group_info)
    mock_created_group = MagicMock()
    mock_created_group.group_name = "newgroup"
    mock_created_group.members = []
    mock_created_ro_group = MagicMock()
    mock_created_ro_group.group_name = "newgroupro"
    mock_created_ro_group.members = []
    app_state.group_manager.create_group = AsyncMock(
        return_value=(mock_created_group, mock_created_ro_group)
    )
    app_state.group_manager.add_user_to_group = AsyncMock()
    app_state.group_manager.remove_user_from_group = AsyncMock()
    app_state.group_manager.delete_resource = AsyncMock(return_value=True)

    # Mock credential service
    app_state.s3_credential_service = AsyncMock()
    app_state.s3_credential_service.rotate = AsyncMock(
        return_value=("user1", "new-secret-key")
    )
    app_state.polaris_credential_service = AsyncMock()
    app_state.polaris_credential_service.delete_credentials = AsyncMock()
    # create_user / rotate-credentials populate the response with the
    # Polaris half too, so the credential service must return a valid
    # record on get_or_create AND rotate.
    _polaris_record = PolarisCredentialRecord(
        client_id="polaris-cid",
        client_secret="polaris-secret",
        personal_catalog="user_user1",
    )
    app_state.polaris_credential_service.get_or_create = AsyncMock(
        return_value=_polaris_record
    )
    app_state.polaris_credential_service.rotate = AsyncMock(
        return_value=_polaris_record
    )

    # Mock policy manager
    app_state.policy_manager = AsyncMock()
    mock_policy = PolicyModel(
        policy_name="user-home-user1",
        policy_document=PolicyDocument(
            version="2012-10-17",
            statement=[],
        ),
    )
    app_state.policy_manager.list_all_policies = AsyncMock(return_value=[mock_policy])
    app_state.policy_manager.resource_exists = AsyncMock(return_value=True)
    app_state.policy_manager._get_policy_attached_entities = AsyncMock(
        return_value={PolicyTarget.USER: [], PolicyTarget.GROUP: []}
    )
    app_state.policy_manager.detach_policy_from_user = AsyncMock()
    app_state.policy_manager.detach_policy_from_group = AsyncMock()
    app_state.policy_manager.delete_resource = AsyncMock(return_value=True)

    # Mock Polaris stack — managers are the orchestration layer the routes
    # call directly. The raw PolarisService is teardown-only and not on
    # AppState, so it is not mocked here.
    app_state.polaris_user_manager = AsyncMock()
    app_state.polaris_user_manager.create_user = AsyncMock()
    app_state.polaris_user_manager.delete_user = AsyncMock()
    app_state.polaris_group_manager = AsyncMock()
    app_state.polaris_group_manager.ensure_catalog = AsyncMock()
    app_state.polaris_group_manager.create_group = AsyncMock()
    app_state.polaris_group_manager.delete_group = AsyncMock()
    app_state.polaris_group_manager.add_user_to_group = AsyncMock()
    app_state.polaris_group_manager.remove_user_from_group = AsyncMock()

    # Mock tenant manager
    app_state.tenant_manager = AsyncMock()
    app_state.tenant_manager.ensure_metadata = AsyncMock(
        return_value={
            "tenant_name": "newgroup",
            "display_name": "newgroup",
            "created_by": "admin",
        }
    )

    return app_state


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user."""
    return KBaseUser(user="admin", admin_perm=AdminPermission.FULL)


@pytest.fixture
def test_app(mock_admin_user):
    """Create a test FastAPI application with mocked dependencies."""

    app = FastAPI()
    app.include_router(router)

    # Add exception handler (same as main app)
    app.add_exception_handler(Exception, universal_error_handler)

    # Override admin auth dependency
    app.dependency_overrides[require_admin] = lambda: mock_admin_user

    return app


@pytest.fixture
def client(test_app, mock_app_state):
    """Create a test client with get_app_state patched."""
    with patch("routes.management.get_app_state", return_value=mock_app_state):
        yield TestClient(test_app, raise_server_exceptions=False)


# === RESPONSE MODEL TESTS ===


class TestUserListResponse:
    """Tests for UserListResponse model."""

    def test_user_list_response_valid(self):
        """Test creating a valid UserListResponse."""
        response = UserListResponse(
            users=[],
            total_count=0,
            retrieved_count=0,
            page=1,
            page_size=50,
            total_pages=1,
            has_next=False,
            has_prev=False,
        )
        assert response.total_count == 0
        assert response.page == 1


class TestUserManagementResponse:
    """Tests for UserManagementResponse model."""

    def test_user_management_response_valid(self):
        """Test creating a valid UserManagementResponse."""
        response = UserManagementResponse(
            username="testuser",
            s3_access_key="testuser",
            s3_secret_key="secret-key",
            polaris_client_id="polaris-cid",
            polaris_client_secret="polaris-secret",
            home_paths=["s3a://bucket/users/testuser/"],
            groups=[],
            total_policies=2,
            operation="create",
            performed_by="admin",
            timestamp=datetime.now(),
        )
        assert response.username == "testuser"
        assert response.operation == "create"
        assert response.s3_access_key == "testuser"
        assert response.s3_secret_key == "secret-key"
        assert response.polaris_client_id == "polaris-cid"
        assert response.polaris_client_secret == "polaris-secret"


class TestGroupManagementResponse:
    """Tests for GroupManagementResponse model."""

    def test_group_management_response_valid(self):
        """Test creating a valid GroupManagementResponse."""
        response = GroupManagementResponse(
            group_name="testgroup",
            members=["user1", "user2"],
            member_count=2,
            operation="create",
            performed_by="admin",
            timestamp=datetime.now(),
        )
        assert response.group_name == "testgroup"
        assert response.member_count == 2


class TestResourceDeleteResponse:
    """Tests for ResourceDeleteResponse model."""

    def test_resource_delete_response_valid(self):
        """Test creating a valid ResourceDeleteResponse."""
        response = ResourceDeleteResponse(
            resource_type="user",
            resource_name="testuser",
            message="User deleted successfully",
        )
        assert response.resource_type == "user"


# === USER MANAGEMENT ENDPOINT TESTS ===


class TestListUsersEndpoint:
    """Tests for list_users endpoint."""

    def test_list_users_success(self, client, mock_app_state):
        """Test listing users successfully."""
        response = client.get("/management/users")

        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert "total_count" in data
        assert data["total_count"] == 2

    def test_list_users_pagination(self, client, mock_app_state):
        """Test listing users with pagination."""
        response = client.get("/management/users?page=1&page_size=10")

        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 10

    def test_list_users_empty(self, client, mock_app_state):
        """Test listing users when none exist."""
        mock_app_state.user_manager.list_resources.return_value = []

        response = client.get("/management/users")

        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0

    def test_list_users_user_info_error(self, client, mock_app_state):
        """Test handling user info retrieval errors gracefully."""
        mock_app_state.user_manager.get_user.side_effect = Exception("User error")

        response = client.get("/management/users")

        # Should still succeed, just with empty/partial user list
        assert response.status_code == 200


class TestCreateUserEndpoint:
    """Tests for create_user endpoint."""

    def test_create_user_success(self, client, mock_app_state):
        """Test creating a user successfully."""
        response = client.post("/management/users/newuser")

        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["operation"] == "create"

    def test_create_user_includes_secret_key(self, client, mock_app_state):
        """Test that create returns the full S3 + Polaris credential bundle."""
        response = client.post("/management/users/newuser")

        assert response.status_code == 201
        data = response.json()
        # S3 IAM half
        assert data["s3_secret_key"] == "secret-key-123"
        assert data["s3_access_key"] == "newuser"
        # Polaris OAuth half — fixture returns a fixed record
        assert data["polaris_client_id"] == "polaris-cid"
        assert data["polaris_client_secret"] == "polaris-secret"


class TestRotateUserCredentialsEndpoint:
    """Tests for rotate_user_credentials endpoint."""

    def test_rotate_credentials_success(self, client, mock_app_state):
        """Test rotating credentials returns the rotated S3 + Polaris bundle."""
        response = client.post("/management/users/user1/rotate-credentials")

        assert response.status_code == 200
        data = response.json()
        assert data["operation"] == "rotate"
        # S3 IAM half (fixture returns ('user1', 'new-secret-key') on rotate)
        assert data["s3_secret_key"] == "new-secret-key"
        # Polaris half (fixture returns the shared PolarisCredentialRecord)
        assert data["polaris_client_id"] == "polaris-cid"
        assert data["polaris_client_secret"] == "polaris-secret"

    def test_rotate_credentials_rotates_both_backends(self, client, mock_app_state):
        """Both S3 and Polaris rotate calls fire — admin rotation must be full-bundle."""
        client.post("/management/users/user1/rotate-credentials")

        mock_app_state.s3_credential_service.rotate.assert_called_once_with("user1")
        mock_app_state.polaris_credential_service.rotate.assert_called_once_with(
            "user1"
        )


class TestDeleteUserEndpoint:
    """Tests for delete_user endpoint."""

    def test_delete_user_success(self, client, mock_app_state):
        """Test deleting a user successfully."""
        response = client.delete("/management/users/user1")

        assert response.status_code == 200
        data = response.json()
        assert data["resource_type"] == "user"
        assert data["resource_name"] == "user1"

    def test_delete_user_cleans_up_credential_db(self, client, mock_app_state):
        """Test deleting a user also deletes their credential DB records."""
        response = client.delete("/management/users/user1")

        assert response.status_code == 200
        mock_app_state.s3_credential_service.delete_credentials.assert_called_once_with(
            "user1"
        )
        mock_app_state.polaris_credential_service.delete_credentials.assert_called_once_with(
            "user1"
        )

    def test_delete_user_failure(self, client, mock_app_state):
        """Test handling delete failure."""
        mock_app_state.user_manager.delete_resource.return_value = False

        response = client.delete("/management/users/user1")

        assert response.status_code == 400  # UserOperationError maps to 400

    def test_delete_user_credential_cleanup_failure_propagates(
        self, client, mock_app_state
    ):
        """Test that credential cleanup failure propagates as a server error."""
        mock_app_state.s3_credential_service.delete_credentials.side_effect = Exception(
            "DB error"
        )

        response = client.delete("/management/users/user1")

        assert response.status_code == 500
        # MinIO user should NOT be deleted if credential cleanup failed first
        mock_app_state.user_manager.delete_resource.assert_not_called()

    def test_delete_user_polaris_credential_cleanup_failure_propagates(
        self, client, mock_app_state
    ):
        """Test Polaris credential cleanup failure propagates as a server error."""
        mock_app_state.polaris_credential_service.delete_credentials.side_effect = (
            Exception("DB error")
        )

        response = client.delete("/management/users/user1")

        assert response.status_code == 500
        mock_app_state.user_manager.delete_resource.assert_not_called()


# === GROUP MANAGEMENT ENDPOINT TESTS ===


class TestListGroupsEndpoint:
    """Tests for list_groups endpoint."""

    def test_list_groups_success(self, client, mock_app_state):
        """Test listing groups successfully."""
        response = client.get("/management/groups")

        assert response.status_code == 200
        data = response.json()
        assert "groups" in data
        assert data["total_count"] == 1

    def test_list_groups_empty(self, client, mock_app_state):
        """Test listing groups when none exist."""
        mock_app_state.group_manager.list_resources.return_value = []

        response = client.get("/management/groups")

        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0


class TestListGroupNamesEndpoint:
    """Tests for list_group_names endpoint (authenticated users, not admin-only)."""

    @pytest.fixture
    def mock_regular_user(self):
        """Create a mock regular (non-admin) user."""
        return KBaseUser(user="regularuser", admin_perm=AdminPermission.NONE)

    @pytest.fixture
    def test_app_with_regular_auth(self, mock_regular_user):
        """Create a test app with regular user auth override (not admin)."""
        app = FastAPI()
        app.include_router(router)
        app.add_exception_handler(Exception, universal_error_handler)

        # Override auth dependency (for regular authenticated user, not admin)
        app.dependency_overrides[auth] = lambda: mock_regular_user
        # Also override require_admin for other endpoints to work in the same app
        app.dependency_overrides[require_admin] = lambda: mock_regular_user

        return app

    @pytest.fixture
    def client_regular_user(self, test_app_with_regular_auth, mock_app_state):
        """Create a test client authenticated as regular user."""
        with patch("routes.management.get_app_state", return_value=mock_app_state):
            yield TestClient(test_app_with_regular_auth, raise_server_exceptions=False)

    def test_list_group_names_success(self, client_regular_user, mock_app_state):
        """Test listing group names successfully as regular user."""
        mock_app_state.group_manager.list_resources.return_value = [
            "group1",
            "group2",
            "myteam",
        ]

        response = client_regular_user.get("/management/groups/names")

        assert response.status_code == 200
        data = response.json()
        assert "group_names" in data
        assert "total_count" in data
        assert data["total_count"] == 3
        assert data["group_names"] == ["group1", "group2", "myteam"]

    def test_list_group_names_empty(self, client_regular_user, mock_app_state):
        """Test listing group names when none exist."""
        mock_app_state.group_manager.list_resources.return_value = []

        response = client_regular_user.get("/management/groups/names")

        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0
        assert data["group_names"] == []

    def test_list_group_names_response_model_validation(
        self, client_regular_user, mock_app_state
    ):
        """Test that response matches GroupNamesResponse model."""
        mock_app_state.group_manager.list_resources.return_value = ["testgroup"]

        response = client_regular_user.get("/management/groups/names")

        assert response.status_code == 200
        data = response.json()

        # Validate response can be parsed as GroupNamesResponse
        parsed = GroupNamesResponse(**data)
        assert parsed.group_names == ["testgroup"]
        assert parsed.total_count == 1

    def test_list_group_names_only_returns_names(
        self, client_regular_user, mock_app_state
    ):
        """Test that only group names are returned, not detailed info."""
        mock_app_state.group_manager.list_resources.return_value = ["group1"]

        response = client_regular_user.get("/management/groups/names")

        assert response.status_code == 200
        data = response.json()

        # Should NOT contain sensitive fields from admin endpoint
        assert "members" not in data
        assert "groups" not in data  # The detailed groups list
        assert "policy_name" not in data

        # Should only have group_names and total_count
        assert set(data.keys()) == {"group_names", "total_count"}

    @pytest.mark.asyncio
    async def test_list_group_names_async(self, mock_app_state):
        """Test list_group_names function directly."""
        mock_request = MagicMock()
        mock_user = KBaseUser(user="testuser", admin_perm=AdminPermission.NONE)

        mock_app_state.group_manager.list_resources.return_value = ["g1", "g2"]

        with patch("routes.management.get_app_state", return_value=mock_app_state):
            response = await list_group_names(mock_request, mock_user)

            assert response.group_names == ["g1", "g2"]
            assert response.total_count == 2


class TestListUserNamesEndpoint:
    """Tests for list_user_names endpoint (admin-only, lightweight)."""

    def test_list_user_names_success(self, client, mock_app_state):
        """Test listing usernames successfully."""
        mock_app_state.user_manager.list_resources.return_value = [
            "user1",
            "user2",
            "user3",
        ]

        response = client.get("/management/users/names")

        assert response.status_code == 200
        data = response.json()
        assert data["usernames"] == ["user1", "user2", "user3"]
        assert data["total_count"] == 3

    def test_list_user_names_empty(self, client, mock_app_state):
        """Test listing usernames when none exist."""
        mock_app_state.user_manager.list_resources.return_value = []

        response = client.get("/management/users/names")

        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0
        assert data["usernames"] == []

    def test_list_user_names_response_model_validation(self, client, mock_app_state):
        """Test that response matches UserNamesResponse model."""
        mock_app_state.user_manager.list_resources.return_value = ["testuser"]

        response = client.get("/management/users/names")

        assert response.status_code == 200
        parsed = UserNamesResponse(**response.json())
        assert parsed.usernames == ["testuser"]
        assert parsed.total_count == 1

    def test_list_user_names_does_not_call_get_user(self, client, mock_app_state):
        """Test that the lightweight endpoint does NOT call get_user for each user."""
        mock_app_state.user_manager.list_resources.return_value = ["u1", "u2"]

        response = client.get("/management/users/names")

        assert response.status_code == 200
        mock_app_state.user_manager.get_user.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_user_names_async(self, mock_app_state):
        """Test list_user_names function directly."""
        mock_request = MagicMock()
        mock_user = KBaseUser(user="admin", admin_perm=AdminPermission.FULL)

        mock_app_state.user_manager.list_resources.return_value = ["a", "b"]

        with patch("routes.management.get_app_state", return_value=mock_app_state):
            response = await list_user_names(mock_request, mock_user)

            assert response.usernames == ["a", "b"]
            assert response.total_count == 2


class TestCreateGroupEndpoint:
    """Tests for create_group endpoint."""

    def test_create_group_success(self, client, mock_app_state):
        """Test creating a group successfully."""
        response = client.post("/management/groups/newgroup")

        assert response.status_code == 201
        data = response.json()
        assert data["group_name"] == "newgroup"
        assert data["operation"] == "create"


class TestAddGroupMemberEndpoint:
    """Tests for add_group_member endpoint."""

    def test_add_member_success(self, client, mock_app_state):
        """Test adding a member to group successfully."""
        response = client.post("/management/groups/group1/members/user2")

        assert response.status_code == 200
        data = response.json()
        assert data["operation"] == "add_member"


class TestRemoveGroupMemberEndpoint:
    """Tests for remove_group_member endpoint."""

    def test_remove_member_success(self, client, mock_app_state):
        """Test removing a member from group successfully."""
        response = client.delete("/management/groups/group1/members/user1")

        assert response.status_code == 200
        data = response.json()
        assert data["operation"] == "remove_member"


class TestDeleteGroupEndpoint:
    """Tests for delete_group endpoint."""

    def test_delete_group_success(self, client, mock_app_state):
        """Test deleting a group successfully."""
        response = client.delete("/management/groups/group1")

        assert response.status_code == 200
        data = response.json()
        assert data["resource_type"] == "group"
        mock_app_state.tenant_manager.delete_metadata.assert_called_once_with("group1")

    def test_delete_group_no_metadata(self, client, mock_app_state):
        """Deleting a group with no tenant metadata still succeeds."""
        mock_app_state.tenant_manager.delete_metadata.side_effect = TenantNotFoundError(
            "not found"
        )
        response = client.delete("/management/groups/group1")

        assert response.status_code == 200
        mock_app_state.tenant_manager.delete_metadata.assert_called_once_with("group1")

    def test_delete_group_failure(self, client, mock_app_state):
        """Test handling delete failure."""
        mock_app_state.group_manager.delete_resource.return_value = False

        response = client.delete("/management/groups/group1")

        assert response.status_code == 400  # GroupOperationError maps to 400


# === ASYNC FUNCTION TESTS ===


class TestManagementFunctionsAsync:
    """Async tests for management functions."""

    @pytest.mark.asyncio
    async def test_list_users_async(self, mock_app_state, mock_admin_user):
        """Test list_users function directly."""

        mock_request = MagicMock()

        with patch("routes.management.get_app_state", return_value=mock_app_state):
            response = await list_users(
                mock_request, mock_admin_user, page=1, page_size=50
            )

            assert response.total_count == 2

    @pytest.mark.asyncio
    async def test_create_user_async(self, mock_app_state, mock_admin_user):
        """Test create_user function directly."""

        mock_request = MagicMock()

        with patch("routes.management.get_app_state", return_value=mock_app_state):
            response = await create_user("newuser", mock_request, mock_admin_user)

            assert response.username == "newuser"
            assert response.operation == "create"


# === PAGINATION TESTS ===


class TestPagination:
    """Tests for pagination logic."""

    def test_pagination_first_page(self, client, mock_app_state):
        """Test first page of results."""
        mock_app_state.user_manager.list_resources.return_value = [
            f"user{i}" for i in range(100)
        ]

        response = client.get("/management/users?page=1&page_size=10")

        data = response.json()
        assert data["page"] == 1
        assert data["has_prev"] is False
        assert data["has_next"] is True

    def test_pagination_middle_page(self, client, mock_app_state):
        """Test middle page of results."""
        mock_app_state.user_manager.list_resources.return_value = [
            f"user{i}" for i in range(100)
        ]

        response = client.get("/management/users?page=5&page_size=10")

        data = response.json()
        assert data["page"] == 5
        assert data["has_prev"] is True
        assert data["has_next"] is True

    def test_pagination_last_page(self, client, mock_app_state):
        """Test last page of results."""
        mock_app_state.user_manager.list_resources.return_value = [
            f"user{i}" for i in range(25)
        ]

        response = client.get("/management/users?page=3&page_size=10")

        data = response.json()
        assert data["page"] == 3
        assert data["has_prev"] is True
        assert data["has_next"] is False

    def test_pagination_single_page(self, client, mock_app_state):
        """Test when all results fit on one page."""
        mock_app_state.user_manager.list_resources.return_value = ["user1", "user2"]

        response = client.get("/management/users?page=1&page_size=50")

        data = response.json()
        assert data["total_pages"] == 1
        assert data["has_prev"] is False
        assert data["has_next"] is False

    def test_pagination_empty_results(self, client, mock_app_state):
        """Test pagination with no results."""
        mock_app_state.user_manager.list_resources.return_value = []

        response = client.get("/management/users?page=1&page_size=50")

        data = response.json()
        assert data["total_pages"] == 1  # Minimum 1 page
        assert data["total_count"] == 0


# === INTEGRATION TESTS ===


class TestManagementIntegration:
    """Integration-like tests for management workflows."""

    def test_user_lifecycle(self, client, mock_app_state):
        """Test complete user lifecycle."""
        # Create user
        create_response = client.post("/management/users/testuser")
        assert create_response.status_code == 201

        # Rotate credentials
        rotate_response = client.post("/management/users/testuser/rotate-credentials")
        assert rotate_response.status_code == 200

        # Delete user
        delete_response = client.delete("/management/users/testuser")
        assert delete_response.status_code == 200

    def test_group_membership_workflow(self, client, mock_app_state):
        """Test group membership workflow."""
        # Add member
        add_response = client.post("/management/groups/group1/members/user1")
        assert add_response.status_code == 200

        # Remove member
        remove_response = client.delete("/management/groups/group1/members/user1")
        assert remove_response.status_code == 200

    def test_admin_performed_by_tracking(self, client, mock_app_state):
        """Test that performed_by is tracked correctly."""
        response = client.post("/management/users/newuser")
        data = response.json()

        assert data["performed_by"] == "admin"


# === POLARIS INTEGRATION TESTS ===


class TestPolarisOrchestration:
    """Tests asserting management routes delegate to the Polaris managers.

    The actual Polaris orchestration (catalog ensure, principal create,
    role bind/revoke) lives in PolarisUserManager and PolarisGroupManager
    and is unit-tested in tests/polaris/managers/. These tests only verify
    that route handlers call the right manager methods at the right time.
    """

    def test_create_user_delegates_to_polaris_user_manager(
        self, client, mock_app_state
    ):
        """Test create_user runs MinIO create then mirrors into Polaris.

        The Polaris mirror queries the user's *actual* MinIO group memberships
        via group_manager.get_user_groups (not user_info.groups, which
        UserManager.create_user hardcodes to []), so default groups joined
        by create_user are picked up correctly.
        """
        # Have the MinIO group manager report the groups the user just joined.
        mock_app_state.group_manager.get_user_groups = AsyncMock(
            return_value=["globalusers", "refdataro"]
        )

        response = client.post("/management/users/newuser")

        assert response.status_code == 201
        mock_app_state.polaris_user_manager.create_user.assert_called_once_with(
            "newuser"
        )
        # Both default groups mirrored.
        mock_app_state.polaris_group_manager.add_user_to_group.assert_any_call(
            "newuser", "globalusers"
        )
        mock_app_state.polaris_group_manager.add_user_to_group.assert_any_call(
            "newuser", "refdataro"
        )

    def test_create_user_skips_polaris_mirror_for_groups_not_joined(
        self, client, mock_app_state
    ):
        """If MinIO didn't add the user to refdataro (group missing), skip Polaris mirror."""
        mock_app_state.group_manager.get_user_groups = AsyncMock(
            return_value=["globalusers"]  # only globalusers, no refdataro
        )

        response = client.post("/management/users/newuser")

        assert response.status_code == 201
        mock_app_state.polaris_group_manager.add_user_to_group.assert_called_once_with(
            "newuser", "globalusers"
        )

    def test_delete_user_polaris_first_then_minio(self, client, mock_app_state):
        """Test delete_user tears down Polaris before MinIO."""
        response = client.delete("/management/users/user1")

        assert response.status_code == 200
        mock_app_state.polaris_user_manager.delete_user.assert_called_once_with("user1")
        mock_app_state.user_manager.delete_resource.assert_called_once_with("user1")

    def test_create_group_delegates_to_polaris_group_manager(
        self, client, mock_app_state
    ):
        """Test create_group runs MinIO create then PolarisGroupManager.create_group."""
        response = client.post("/management/groups/newgroup")

        assert response.status_code == 201
        mock_app_state.polaris_group_manager.create_group.assert_called_once_with(
            group_name="newgroup", creator="admin"
        )

    def test_add_member_delegates_to_polaris_group_manager(
        self, client, mock_app_state
    ):
        """Test add_group_member mirrors the MinIO add into Polaris."""
        response = client.post("/management/groups/group1/members/user2")

        assert response.status_code == 200
        mock_app_state.polaris_group_manager.add_user_to_group.assert_called_once_with(
            "user2", "group1"
        )

    def test_add_ro_member_passes_ro_group_name_to_polaris(
        self, client, mock_app_state
    ):
        """The ``{group}ro`` suffix is preserved; PolarisGroupManager normalises it."""
        response = client.post("/management/groups/group1ro/members/user2")

        assert response.status_code == 200
        mock_app_state.polaris_group_manager.add_user_to_group.assert_called_once_with(
            "user2", "group1ro"
        )

    def test_remove_member_delegates_to_polaris_group_manager(
        self, client, mock_app_state
    ):
        """Test remove_group_member mirrors the MinIO remove into Polaris."""
        response = client.delete("/management/groups/group1/members/user1")

        assert response.status_code == 200
        mock_app_state.polaris_group_manager.remove_user_from_group.assert_called_once_with(
            "user1", "group1"
        )

    def test_delete_group_polaris_first_then_minio(self, client, mock_app_state):
        """Test delete_group tears down Polaris before MinIO."""
        response = client.delete("/management/groups/group1")

        assert response.status_code == 200
        mock_app_state.polaris_group_manager.delete_group.assert_called_once_with(
            "group1"
        )
        mock_app_state.group_manager.delete_resource.assert_called_once_with("group1")

    def test_polaris_error_propagates_on_create_group(self, client, mock_app_state):
        """Test PolarisGroupManager errors propagate and cause group creation to fail."""
        mock_app_state.polaris_group_manager.create_group.side_effect = Exception(
            "Polaris unavailable"
        )
        response = client.post("/management/groups/newgroup")
        assert response.status_code == 500

    def test_polaris_error_propagates_on_add_member(self, client, mock_app_state):
        """Test PolarisGroupManager errors propagate and cause add member to fail."""
        mock_app_state.polaris_group_manager.add_user_to_group.side_effect = Exception(
            "Polaris unavailable"
        )
        response = client.post("/management/groups/group1/members/user2")
        assert response.status_code == 500

    def test_polaris_error_propagates_on_remove_member(self, client, mock_app_state):
        """Test PolarisGroupManager errors propagate and cause remove member to fail."""
        mock_app_state.polaris_group_manager.remove_user_from_group.side_effect = (
            Exception("Polaris unavailable")
        )
        response = client.delete("/management/groups/group1/members/user1")
        assert response.status_code == 500


# === MIGRATION ENDPOINT TESTS ===


class TestRegeneratePoliciesEndpoint:
    """Tests for regenerate_all_policies migration endpoint."""

    @pytest.fixture
    def migration_app_state(self, mock_app_state):
        """App state configured for migration endpoints."""
        mock_app_state.user_manager.list_resources = AsyncMock(
            return_value=["alice", "bob"]
        )
        mock_app_state.group_manager.list_resources = AsyncMock(
            return_value=["team1", "team1ro", "team2", "team2ro"]
        )
        mock_app_state.policy_manager.regenerate_user_home_policy = AsyncMock()
        mock_app_state.policy_manager.regenerate_group_home_policy = AsyncMock()
        return mock_app_state

    @pytest.fixture
    def migration_client(self, test_app, migration_app_state):
        with patch("routes.management.get_app_state", return_value=migration_app_state):
            yield TestClient(test_app, raise_server_exceptions=False)

    def test_regenerate_policies_success(self, migration_client, migration_app_state):
        """Test successful regeneration of all policies."""
        response = migration_client.post("/management/migrate/regenerate-policies")

        assert response.status_code == 200
        data = response.json()
        assert data["users_updated"] == 2
        # 2 base groups × 2 (RW + RO) = 4
        assert data["groups_updated"] == 4
        assert data["errors"] == []
        assert data["performed_by"] == "admin"

    def test_regenerate_policies_calls_user_regenerate(
        self, migration_client, migration_app_state
    ):
        """Test that regenerate is called for each user."""
        migration_client.post("/management/migrate/regenerate-policies")

        calls = migration_app_state.policy_manager.regenerate_user_home_policy.call_args_list
        assert len(calls) == 2
        assert calls[0].args == ("alice",)
        assert calls[1].args == ("bob",)

    def test_regenerate_policies_calls_group_rw_and_ro(
        self, migration_client, migration_app_state
    ):
        """Test that both RW and RO policies are regenerated for each base group."""
        migration_client.post("/management/migrate/regenerate-policies")

        calls = migration_app_state.policy_manager.regenerate_group_home_policy.call_args_list
        # team1 RW, team1ro RO, team2 RW, team2ro RO
        assert len(calls) == 4

        # team1 RW
        assert calls[0].kwargs == {"group_name": "team1", "read_only": False}
        # team1 RO
        assert calls[1].kwargs == {
            "group_name": "team1ro",
            "read_only": True,
            "path_target": "team1",
        }
        # team2 RW
        assert calls[2].kwargs == {"group_name": "team2", "read_only": False}
        # team2 RO
        assert calls[3].kwargs == {
            "group_name": "team2ro",
            "read_only": True,
            "path_target": "team2",
        }

    def test_regenerate_policies_user_error_continues(
        self, migration_client, migration_app_state
    ):
        """Test that a user error does not block other users."""
        migration_app_state.policy_manager.regenerate_user_home_policy.side_effect = [
            Exception("alice policy failed"),
            AsyncMock(),  # bob succeeds
        ]

        response = migration_client.post("/management/migrate/regenerate-policies")

        data = response.json()
        assert data["users_updated"] == 1
        assert len(data["errors"]) == 1
        assert data["errors"][0]["resource_name"] == "alice"
        assert "alice policy failed" in data["errors"][0]["error"]

    def test_regenerate_policies_group_error_continues(
        self, migration_client, migration_app_state
    ):
        """Test that a group error does not block other groups."""
        migration_app_state.policy_manager.regenerate_group_home_policy.side_effect = [
            Exception("team1 RW failed"),  # team1 RW fails
            AsyncMock(),  # team1 RO succeeds
            AsyncMock(),  # team2 RW succeeds
            AsyncMock(),  # team2 RO succeeds
        ]

        response = migration_client.post("/management/migrate/regenerate-policies")

        data = response.json()
        assert data["groups_updated"] == 3
        assert len(data["errors"]) == 1
        assert data["errors"][0]["resource_name"] == "team1"

    def test_regenerate_policies_ro_group_error_continues(
        self, migration_client, migration_app_state
    ):
        """Test that an RO group error does not block the next base group."""
        migration_app_state.policy_manager.regenerate_group_home_policy.side_effect = [
            AsyncMock(),  # team1 RW succeeds
            Exception("team1 RO failed"),  # team1 RO fails
            AsyncMock(),  # team2 RW succeeds
            AsyncMock(),  # team2 RO succeeds
        ]

        response = migration_client.post("/management/migrate/regenerate-policies")

        data = response.json()
        assert data["groups_updated"] == 3
        assert len(data["errors"]) == 1
        assert data["errors"][0]["resource_name"] == "team1ro"
        assert data["errors"][0]["resource_type"] == "group"

    def test_regenerate_policies_no_users_no_groups(
        self, migration_client, migration_app_state
    ):
        """Test with empty user and group lists."""
        migration_app_state.user_manager.list_resources.return_value = []
        migration_app_state.group_manager.list_resources.return_value = []

        response = migration_client.post("/management/migrate/regenerate-policies")

        data = response.json()
        assert data["users_updated"] == 0
        assert data["groups_updated"] == 0
        assert data["users_skipped"] == []
        assert data["groups_skipped"] == []
        assert data["errors"] == []

    def test_regenerate_policies_empty_body_behaves_like_no_body(
        self, migration_client, migration_app_state
    ):
        """Posting an empty JSON object should behave the same as no body."""
        response = migration_client.post(
            "/management/migrate/regenerate-policies", json={}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["users_updated"] == 2
        assert data["groups_updated"] == 4
        assert data["users_skipped"] == []
        assert data["groups_skipped"] == []
        assert data["errors"] == []

    def test_regenerate_policies_excludes_users(
        self, migration_client, migration_app_state
    ):
        """exclude_users skips matching users and reports them in users_skipped."""
        response = migration_client.post(
            "/management/migrate/regenerate-policies",
            json={"exclude_users": ["alice"]},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["users_updated"] == 1
        assert data["users_skipped"] == ["alice"]

        calls = migration_app_state.policy_manager.regenerate_user_home_policy.call_args_list
        assert len(calls) == 1
        assert calls[0].args == ("bob",)

    def test_regenerate_policies_excludes_unknown_users_silently(
        self, migration_client, migration_app_state
    ):
        """Unknown excluded usernames are silently ignored and not echoed back."""
        response = migration_client.post(
            "/management/migrate/regenerate-policies",
            json={"exclude_users": ["ghost", "nobody"]},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["users_updated"] == 2
        assert data["users_skipped"] == []

    def test_regenerate_policies_excludes_groups_skips_rw_and_ro(
        self, migration_client, migration_app_state
    ):
        """Excluding a base group skips both its RW and RO policies."""
        response = migration_client.post(
            "/management/migrate/regenerate-policies",
            json={"exclude_groups": ["team1"]},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["groups_updated"] == 2
        assert data["groups_skipped"] == ["team1"]

        calls = migration_app_state.policy_manager.regenerate_group_home_policy.call_args_list
        assert len(calls) == 2
        assert calls[0].kwargs == {"group_name": "team2", "read_only": False}
        assert calls[1].kwargs == {
            "group_name": "team2ro",
            "read_only": True,
            "path_target": "team2",
        }

    def test_regenerate_policies_excludes_users_and_groups_combined(
        self, migration_client, migration_app_state
    ):
        """exclude_users and exclude_groups can be combined in one request."""
        response = migration_client.post(
            "/management/migrate/regenerate-policies",
            json={
                "exclude_users": ["alice", "ghost"],
                "exclude_groups": ["team2", "missing-group"],
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["users_updated"] == 1
        assert data["groups_updated"] == 2
        assert data["users_skipped"] == ["alice"]
        assert data["groups_skipped"] == ["team2"]


class TestEnsurePolarisResourcesEndpoint:
    """Tests for ensure_all_polaris_resources migration endpoint.

    The endpoint delegates to PolarisGroupManager.ensure_catalog,
    PolarisUserManager.create_user, and PolarisGroupManager.add_user_to_group.
    Those methods' internals are unit-tested in tests/polaris/managers/.
    """

    @pytest.fixture
    def polaris_migration_state(self, mock_app_state):
        """App state with two users in one base group + RO sibling."""
        mock_app_state.user_manager.list_resources = AsyncMock(
            return_value=["alice", "bob"]
        )
        mock_app_state.group_manager.list_resources = AsyncMock(
            return_value=["team1", "team1ro"]
        )
        mock_app_state.group_manager.get_user_groups = AsyncMock(return_value=["team1"])
        return mock_app_state

    @pytest.fixture
    def polaris_migration_client(self, test_app, polaris_migration_state):
        with patch(
            "routes.management.get_app_state",
            return_value=polaris_migration_state,
        ):
            yield TestClient(test_app, raise_server_exceptions=False)

    def test_ensure_polaris_success(
        self, polaris_migration_client, polaris_migration_state
    ):
        """Test successful Polaris resource provisioning."""
        response = polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources"
        )

        assert response.status_code == 200
        data = response.json()
        assert data["users_provisioned"] == 2
        assert data["groups_provisioned"] == 1  # only base group team1
        # Per-resource lists let operators verify exactly which resources
        # completed (counts alone don't say which).
        assert data["provisioned_users"] == ["alice", "bob"]
        assert data["provisioned_groups"] == ["team1"]
        assert data["errors"] == []

    def test_ensure_polaris_calls_ensure_catalog_for_base_groups_only(
        self, polaris_migration_client, polaris_migration_state
    ):
        """RO siblings are skipped; only base groups get ensure_catalog."""
        polaris_migration_client.post("/management/migrate/ensure-polaris-resources")

        polaris_group_manager = polaris_migration_state.polaris_group_manager
        polaris_group_manager.ensure_catalog.assert_called_once_with("team1")

    def test_ensure_polaris_creates_user_via_polaris_user_manager(
        self, polaris_migration_client, polaris_migration_state
    ):
        """Each user gets PolarisUserManager.create_user called once."""
        polaris_migration_client.post("/management/migrate/ensure-polaris-resources")

        polaris_user_manager = polaris_migration_state.polaris_user_manager
        create_calls = polaris_user_manager.create_user.call_args_list
        assert [c.args[0] for c in create_calls] == ["alice", "bob"]

    def test_ensure_polaris_mirrors_existing_group_memberships(
        self, polaris_migration_client, polaris_migration_state
    ):
        """Each user's existing MinIO group memberships get mirrored into Polaris."""
        polaris_migration_client.post("/management/migrate/ensure-polaris-resources")

        polaris_group_manager = polaris_migration_state.polaris_group_manager
        # Both users are in team1, so each gets one add_user_to_group call.
        polaris_group_manager.add_user_to_group.assert_any_call("alice", "team1")
        polaris_group_manager.add_user_to_group.assert_any_call("bob", "team1")
        assert polaris_group_manager.add_user_to_group.call_count == 2

    def test_ensure_polaris_user_error_continues_to_remaining_users(
        self, polaris_migration_client, polaris_migration_state
    ):
        """A failure on one user is recorded and the next user is still processed."""
        polaris_migration_state.polaris_user_manager.create_user.side_effect = [
            Exception("Polaris down for alice"),
            None,  # bob succeeds
        ]

        response = polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources"
        )

        data = response.json()
        assert data["users_provisioned"] == 1
        assert any(e["resource_name"] == "alice" for e in data["errors"])

    def test_ensure_polaris_group_error_continues_to_remaining_groups(
        self, polaris_migration_client, polaris_migration_state
    ):
        """A failure on one group is recorded and the next group is still processed."""
        polaris_migration_state.group_manager.list_resources.return_value = [
            "team1",
            "team1ro",
            "team2",
            "team2ro",
        ]
        polaris_migration_state.polaris_group_manager.ensure_catalog.side_effect = [
            Exception("team1 failed"),
            None,  # team2 succeeds
        ]

        response = polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources"
        )

        data = response.json()
        assert data["groups_provisioned"] == 1
        # The successful group surfaces in provisioned_groups; the failed one
        # surfaces in errors. Operators can diff these to see exactly which
        # backfilled.
        assert data["provisioned_groups"] == ["team2"]
        assert any(
            e["resource_type"] == "group" and e["resource_name"] == "team1"
            for e in data["errors"]
        )

    def test_ensure_polaris_empty_system(
        self, polaris_migration_client, polaris_migration_state
    ):
        """No users or groups → all-zero response with no errors."""
        polaris_migration_state.user_manager.list_resources.return_value = []
        polaris_migration_state.group_manager.list_resources.return_value = []

        response = polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources"
        )

        data = response.json()
        assert data["users_provisioned"] == 0
        assert data["groups_provisioned"] == 0
        assert data["errors"] == []

    # ── exclusion semantics (mirror regenerate-policies) ──────────────────

    def test_ensure_polaris_empty_body_behaves_like_no_body(
        self, polaris_migration_client, polaris_migration_state
    ):
        """Posting an empty JSON body works the same as posting no body at all."""
        response = polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources",
            json={"exclude_users": [], "exclude_groups": []},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["users_provisioned"] == 2
        assert data["groups_provisioned"] == 1
        assert data["users_skipped"] == []
        assert data["groups_skipped"] == []

    def test_ensure_polaris_excludes_users(
        self, polaris_migration_client, polaris_migration_state
    ):
        """exclude_users skips matching users entirely (no Polaris user calls)."""
        polaris_user_manager = polaris_migration_state.polaris_user_manager
        response = polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources",
            json={"exclude_users": ["alice"]},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["users_provisioned"] == 1  # only bob
        assert data["users_skipped"] == ["alice"]
        # alice was never sent to PolarisUserManager.create_user
        create_calls = polaris_user_manager.create_user.call_args_list
        assert [c.args[0] for c in create_calls] == ["bob"]

    def test_ensure_polaris_excludes_unknown_users_silently(
        self, polaris_migration_client, polaris_migration_state
    ):
        """Excluding a non-existent user is silent — only present users surface in users_skipped."""
        response = polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources",
            json={"exclude_users": ["nobody", "alice"]},
        )

        data = response.json()
        # "nobody" doesn't exist; only "alice" is reported as actually skipped.
        assert data["users_skipped"] == ["alice"]
        assert data["users_provisioned"] == 1

    def test_ensure_polaris_excludes_groups_skips_catalog_and_role_bindings(
        self, polaris_migration_client, polaris_migration_state
    ):
        """exclude_groups skips both ensure_catalog AND per-user role bindings on that base."""
        polaris_group_manager = polaris_migration_state.polaris_group_manager
        # Add a second base group so we can verify only team1 is skipped.
        polaris_migration_state.group_manager.list_resources.return_value = [
            "team1",
            "team1ro",
            "team2",
            "team2ro",
        ]
        # Both users belong to team1 (the excluded one) AND team2.
        polaris_migration_state.group_manager.get_user_groups.return_value = [
            "team1",
            "team2",
        ]

        response = polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources",
            json={"exclude_groups": ["team1"]},
        )

        data = response.json()
        assert data["groups_skipped"] == ["team1"]
        assert data["groups_provisioned"] == 1  # only team2

        # ensure_catalog called only for team2.
        ensure_calls = polaris_group_manager.ensure_catalog.call_args_list
        assert [c.args[0] for c in ensure_calls] == ["team2"]

        # No add_user_to_group call targeted team1 (or team1ro by extension —
        # iteration only sees team1 here per the mock, but the base-group
        # filter would catch team1ro too in real data).
        add_calls = polaris_group_manager.add_user_to_group.call_args_list
        assert all(c.args[1] != "team1" for c in add_calls)
        # Each user still got the team2 binding mirrored.
        assert any(c.args == ("alice", "team2") for c in add_calls)
        assert any(c.args == ("bob", "team2") for c in add_calls)

    def test_ensure_polaris_excludes_groups_skips_ro_sibling_bindings(
        self, polaris_migration_client, polaris_migration_state
    ):
        """A user who's only in team1ro doesn't get the reader binding when team1 is excluded."""
        polaris_group_manager = polaris_migration_state.polaris_group_manager
        polaris_migration_state.group_manager.get_user_groups.return_value = ["team1ro"]

        polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources",
            json={"exclude_groups": ["team1"]},
        )

        # No add_user_to_group calls at all — team1ro normalises to base team1
        # which is excluded.
        polaris_group_manager.add_user_to_group.assert_not_called()

    def test_ensure_polaris_excludes_users_and_groups_combined(
        self, polaris_migration_client, polaris_migration_state
    ):
        """Combining exclude_users and exclude_groups behaves as the union of both filters."""
        response = polaris_migration_client.post(
            "/management/migrate/ensure-polaris-resources",
            json={"exclude_users": ["alice"], "exclude_groups": ["team1"]},
        )

        data = response.json()
        assert data["users_skipped"] == ["alice"]
        assert data["groups_skipped"] == ["team1"]
        assert data["users_provisioned"] == 1  # only bob
        assert data["groups_provisioned"] == 0  # team1 was the only base group

    def test_ensure_polaris_dedups_writer_and_reader_variants(
        self, polaris_migration_client, polaris_migration_state
    ):
        """A user in both team1 AND team1ro gets only the writer binding once.

        Mirrors the dedup-preferring-write semantics that the live
        /polaris/user_provision endpoint uses, so backfill produces the
        same end-state as a fresh provision.
        """
        polaris_migration_state.group_manager.get_user_groups.return_value = [
            "team1",
            "team1ro",
        ]
        polaris_group_manager = polaris_migration_state.polaris_group_manager

        polaris_migration_client.post("/management/migrate/ensure-polaris-resources")

        # Each user gets exactly one binding (writer "team1"), not two.
        add_calls = polaris_group_manager.add_user_to_group.call_args_list
        per_user_groups = {
            user: [c.args[1] for c in add_calls if c.args[0] == user]
            for user in ("alice", "bob")
        }
        assert per_user_groups == {"alice": ["team1"], "bob": ["team1"]}


class TestMigrationResponseModels:
    """Tests for migration response model validation."""

    def test_migration_error_model(self):
        error = MigrationError(
            resource_type="user", resource_name="alice", error="Something broke"
        )
        assert error.resource_type == "user"
        assert error.resource_name == "alice"

    def test_regenerate_policies_response_model(self):
        response = RegeneratePoliciesResponse(
            users_updated=5,
            groups_updated=3,
            errors=[],
            performed_by="admin",
            timestamp=datetime.now(),
        )
        assert response.users_updated == 5
        assert response.groups_updated == 3

    def test_ensure_polaris_response_model(self):
        response = EnsurePolarisResponse(
            users_provisioned=10,
            groups_provisioned=4,
            provisioned_users=["alice", "bob"],
            provisioned_groups=["team1", "team2"],
            users_skipped=["sysuser"],
            groups_skipped=["legacy"],
            errors=[
                MigrationError(
                    resource_type="user", resource_name="bob", error="timeout"
                )
            ],
            performed_by="admin",
            timestamp=datetime.now(),
        )
        assert response.users_provisioned == 10
        assert response.provisioned_users == ["alice", "bob"]
        assert response.provisioned_groups == ["team1", "team2"]
        assert response.users_skipped == ["sysuser"]
        assert response.groups_skipped == ["legacy"]
        assert len(response.errors) == 1


class TestRotateAllCredentialsEndpoint:
    """Tests for rotate_all_credentials endpoint."""

    @pytest.fixture
    def rotate_app_state(self, mock_app_state):
        mock_app_state.user_manager.list_resources = AsyncMock(
            return_value=["alice", "bob"]
        )
        mock_app_state.s3_credential_service.rotate = AsyncMock(
            return_value=("alice", "new-secret")
        )
        # Polaris rotate is exercised per-user alongside S3 rotate. Default
        # success — individual tests override side_effect for failure cases.
        mock_app_state.polaris_credential_service.rotate = AsyncMock(
            return_value=PolarisCredentialRecord(
                client_id="polaris-cid",
                client_secret="polaris-secret",
                personal_catalog="user_alice",
            )
        )
        return mock_app_state

    @pytest.fixture
    def rotate_client(self, test_app, rotate_app_state):
        with patch("routes.management.get_app_state", return_value=rotate_app_state):
            yield TestClient(test_app, raise_server_exceptions=False)

    def test_rotate_all_success(self, rotate_client, rotate_app_state):
        response = rotate_client.post("/management/credentials/rotate-all-credentials")

        assert response.status_code == 200
        data = response.json()
        assert data["users_rotated"] == 2
        assert data["users_failed"] == 0
        assert data["errors"] == []
        assert data["performed_by"] == "admin"

    def test_rotate_all_calls_rotate_for_each_user(
        self, rotate_client, rotate_app_state
    ):
        rotate_client.post("/management/credentials/rotate-all-credentials")

        s3_calls = rotate_app_state.s3_credential_service.rotate.call_args_list
        assert len(s3_calls) == 2
        assert s3_calls[0].args == ("alice",)
        assert s3_calls[1].args == ("bob",)

        # Polaris rotates alongside S3 — both backends every user.
        polaris_calls = (
            rotate_app_state.polaris_credential_service.rotate.call_args_list
        )
        assert len(polaris_calls) == 2
        assert polaris_calls[0].args == ("alice",)
        assert polaris_calls[1].args == ("bob",)

    def test_rotate_all_s3_error_continues(self, rotate_client, rotate_app_state):
        """S3 failure on one user doesn't block Polaris on that user or other users.

        ``users_rotated`` only counts users where BOTH backends succeeded;
        the alice S3 failure → alice counts as failed even though her
        Polaris rotation succeeded.
        """
        rotate_app_state.s3_credential_service.rotate.side_effect = [
            Exception("alice rotate failed"),
            ("bob", "new-secret"),
        ]

        response = rotate_client.post("/management/credentials/rotate-all-credentials")

        assert response.status_code == 200
        data = response.json()
        assert data["users_rotated"] == 1  # only bob fully succeeded
        assert data["users_failed"] == 1  # alice partial failure
        assert len(data["errors"]) == 1
        assert data["errors"][0]["resource_name"] == "alice"
        assert data["errors"][0]["resource_type"] == "user_s3"
        assert "alice rotate failed" in data["errors"][0]["error"]

    def test_rotate_all_polaris_error_continues(self, rotate_client, rotate_app_state):
        """Polaris failure is reported with resource_type ``user_polaris``."""
        rotate_app_state.polaris_credential_service.rotate.side_effect = [
            Exception("alice polaris failed"),
            PolarisCredentialRecord(
                client_id="polaris-cid",
                client_secret="polaris-secret",
                personal_catalog="user_bob",
            ),
        ]

        response = rotate_client.post("/management/credentials/rotate-all-credentials")

        assert response.status_code == 200
        data = response.json()
        assert data["users_rotated"] == 1
        assert data["users_failed"] == 1
        assert len(data["errors"]) == 1
        assert data["errors"][0]["resource_name"] == "alice"
        assert data["errors"][0]["resource_type"] == "user_polaris"

    def test_rotate_all_both_backends_fail_for_same_user(
        self, rotate_client, rotate_app_state
    ):
        """A single user with both backends failing produces two error rows.

        Counted once in ``users_failed`` (it's still one user), but each
        backend's error is preserved so operators can retry just the
        failing backend.
        """
        rotate_app_state.s3_credential_service.rotate.side_effect = [
            Exception("alice s3 failed"),
            ("bob", "new-secret"),
        ]
        rotate_app_state.polaris_credential_service.rotate.side_effect = [
            Exception("alice polaris failed"),
            PolarisCredentialRecord(
                client_id="polaris-cid",
                client_secret="polaris-secret",
                personal_catalog="user_bob",
            ),
        ]

        response = rotate_client.post("/management/credentials/rotate-all-credentials")

        assert response.status_code == 200
        data = response.json()
        assert data["users_rotated"] == 1  # bob ok
        assert data["users_failed"] == 1  # alice (both halves failed but one user)
        assert len(data["errors"]) == 2
        types = {e["resource_type"] for e in data["errors"]}
        assert types == {"user_s3", "user_polaris"}

    def test_rotate_all_all_fail(self, rotate_client, rotate_app_state):
        """All users, all backends fail → 2 users × 2 backends = 4 error rows."""
        rotate_app_state.s3_credential_service.rotate.side_effect = Exception(
            "s3 rotate failed"
        )
        rotate_app_state.polaris_credential_service.rotate.side_effect = Exception(
            "polaris rotate failed"
        )

        response = rotate_client.post("/management/credentials/rotate-all-credentials")

        assert response.status_code == 200
        data = response.json()
        assert data["users_rotated"] == 0
        assert data["users_failed"] == 2
        assert len(data["errors"]) == 4
        # Half S3, half Polaris.
        s3_errs = [e for e in data["errors"] if e["resource_type"] == "user_s3"]
        polaris_errs = [
            e for e in data["errors"] if e["resource_type"] == "user_polaris"
        ]
        assert len(s3_errs) == 2
        assert len(polaris_errs) == 2

    def test_rotate_all_no_users(self, rotate_client, rotate_app_state):
        rotate_app_state.user_manager.list_resources.return_value = []

        response = rotate_client.post("/management/credentials/rotate-all-credentials")

        assert response.status_code == 200
        data = response.json()
        assert data["users_rotated"] == 0
        assert data["users_failed"] == 0
        assert data["errors"] == []

    def test_rotate_all_response_model_valid(self, rotate_client, rotate_app_state):
        response = rotate_client.post("/management/credentials/rotate-all-credentials")

        assert response.status_code == 200
        parsed = RotateAllCredentialsResponse(**response.json())
        assert parsed.users_rotated == 2
        assert parsed.users_failed == 0
