"""
Comprehensive tests for the routes.management module.

Tests cover:
- User management endpoints (list, create, rotate, delete)
- Group management endpoints (list, create, add/remove member, delete)
- Policy management endpoints (list, delete)
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

from src.minio.models.policy import PolicyDocument, PolicyModel, PolicyTarget
from src.minio.models.user import UserModel
from src.routes.management import (
    GroupManagementResponse,
    GroupNamesResponse,
    ResourceDeleteResponse,
    UserListResponse,
    UserManagementResponse,
    UserNamesResponse,
    create_user,
    delete_policy,
    list_group_names,
    list_user_names,
    list_users,
    router,
)
from src.service.dependencies import auth, require_admin
from src.service.exception_handlers import universal_error_handler
from src.service.kb_auth import AdminPermission, KBaseUser


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
    mock_group_info.policy_name = "group-policy-group1"
    app_state.group_manager.get_group_info = AsyncMock(return_value=mock_group_info)
    mock_created_group = MagicMock()
    mock_created_group.group_name = "newgroup"
    mock_created_group.members = []
    mock_created_group.policy_name = "group-policy-newgroup"
    mock_created_ro_group = MagicMock()
    mock_created_ro_group.group_name = "newgroupro"
    mock_created_ro_group.members = []
    mock_created_ro_group.policy_name = "group-policy-newgroupro"
    app_state.group_manager.create_group = AsyncMock(
        return_value=(mock_created_group, mock_created_ro_group)
    )
    app_state.group_manager.add_user_to_group = AsyncMock()
    app_state.group_manager.remove_user_from_group = AsyncMock()
    app_state.group_manager.delete_resource = AsyncMock(return_value=True)

    # Mock credential service
    app_state.credential_service = AsyncMock()
    app_state.credential_service.rotate = AsyncMock(
        return_value=("user1", "new-secret-key")
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

    return app_state


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user."""
    return KBaseUser(user="admin", admin_perm=AdminPermission.FULL)


@pytest.fixture
def test_app(mock_app_state, mock_admin_user):
    """Create a test FastAPI application with mocked dependencies."""

    app = FastAPI()
    app.include_router(router)

    # Add exception handler (same as main app)
    app.add_exception_handler(Exception, universal_error_handler)

    # Store app state
    app.state.minio_client = MagicMock()
    app.state.minio_config = MagicMock()
    app.state.policy_manager = mock_app_state.policy_manager
    app.state.user_manager = mock_app_state.user_manager
    app.state.group_manager = mock_app_state.group_manager
    app.state.sharing_manager = MagicMock()

    # Override admin auth dependency
    app.dependency_overrides[require_admin] = lambda: mock_admin_user

    return app


@pytest.fixture
def client(test_app, mock_app_state):
    """Create a test client with get_app_state patched."""
    with patch("src.routes.management.get_app_state", return_value=mock_app_state):
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
            access_key="testuser",
            secret_key="secret-key",
            home_paths=["s3a://bucket/users/testuser/"],
            groups=[],
            total_policies=2,
            operation="create",
            performed_by="admin",
            timestamp=datetime.now(),
        )
        assert response.username == "testuser"
        assert response.operation == "create"


class TestGroupManagementResponse:
    """Tests for GroupManagementResponse model."""

    def test_group_management_response_valid(self):
        """Test creating a valid GroupManagementResponse."""
        response = GroupManagementResponse(
            group_name="testgroup",
            members=["user1", "user2"],
            member_count=2,
            policy_name="group-policy-testgroup",
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
        """Test that create returns secret key."""
        response = client.post("/management/users/newuser")

        assert response.status_code == 201
        data = response.json()
        assert "secret_key" in data
        assert data["secret_key"] == "secret-key-123"


class TestRotateUserCredentialsEndpoint:
    """Tests for rotate_user_credentials endpoint."""

    def test_rotate_credentials_success(self, client, mock_app_state):
        """Test rotating credentials successfully."""
        response = client.post("/management/users/user1/rotate-credentials")

        assert response.status_code == 200
        data = response.json()
        assert data["operation"] == "rotate"
        assert data["secret_key"] == "new-secret-key"


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
        """Test deleting a user also deletes their credential DB record."""
        response = client.delete("/management/users/user1")

        assert response.status_code == 200
        mock_app_state.credential_service.delete_credentials.assert_called_once_with(
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
        mock_app_state.credential_service.delete_credentials.side_effect = Exception(
            "DB error"
        )

        response = client.delete("/management/users/user1")

        assert response.status_code == 500
        # MinIO user should NOT be deleted if credential cleanup failed first
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
    def test_app_with_regular_auth(self, mock_app_state, mock_regular_user):
        """Create a test app with regular user auth override (not admin)."""
        app = FastAPI()
        app.include_router(router)
        app.add_exception_handler(Exception, universal_error_handler)

        # Store app state
        app.state.minio_client = MagicMock()
        app.state.minio_config = MagicMock()
        app.state.policy_manager = mock_app_state.policy_manager
        app.state.user_manager = mock_app_state.user_manager
        app.state.group_manager = mock_app_state.group_manager
        app.state.sharing_manager = MagicMock()

        # Override auth dependency (for regular authenticated user, not admin)
        app.dependency_overrides[auth] = lambda: mock_regular_user
        # Also override require_admin for other endpoints to work in the same app
        app.dependency_overrides[require_admin] = lambda: mock_regular_user

        return app

    @pytest.fixture
    def client_regular_user(self, test_app_with_regular_auth, mock_app_state):
        """Create a test client authenticated as regular user."""
        with patch("src.routes.management.get_app_state", return_value=mock_app_state):
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

        with patch("src.routes.management.get_app_state", return_value=mock_app_state):
            response = await list_group_names(mock_request, mock_user)

            assert response.group_names == ["g1", "g2"]
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

    def test_delete_group_failure(self, client, mock_app_state):
        """Test handling delete failure."""
        mock_app_state.group_manager.delete_resource.return_value = False

        response = client.delete("/management/groups/group1")

        assert response.status_code == 400  # GroupOperationError maps to 400


# === POLICY MANAGEMENT ENDPOINT TESTS ===


class TestListPoliciesEndpoint:
    """Tests for list_policies endpoint."""

    def test_list_policies_success(self, client, mock_app_state):
        """Test listing policies successfully."""
        response = client.get("/management/policies")

        assert response.status_code == 200
        data = response.json()
        assert "policies" in data
        assert data["total_count"] == 1

    def test_list_policies_pagination(self, client, mock_app_state):
        """Test listing policies with pagination."""
        response = client.get("/management/policies?page=1&page_size=25")

        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 25


class TestDeletePolicyEndpoint:
    """Tests for delete_policy endpoint."""

    def test_delete_policy_success(self, client, mock_app_state):
        """Test deleting a policy successfully."""
        response = client.delete("/management/policies/user-home-user1")

        assert response.status_code == 200
        data = response.json()
        assert data["resource_type"] == "policy"
        assert data["resource_name"] == "user-home-user1"

    def test_delete_policy_not_found(self, client, mock_app_state):
        """Test deleting non-existent policy (idempotent)."""
        mock_app_state.policy_manager.resource_exists.return_value = False

        response = client.delete("/management/policies/nonexistent")

        assert response.status_code == 200
        data = response.json()
        assert (
            "already deleted" in data["message"] or "does not exist" in data["message"]
        )

    def test_delete_policy_with_attached_users(self, client, mock_app_state):
        """Test deleting policy detaches from users first."""
        mock_app_state.policy_manager._get_policy_attached_entities.return_value = {
            PolicyTarget.USER: ["user1", "user2"],
            PolicyTarget.GROUP: [],
        }

        response = client.delete("/management/policies/user-home-user1")

        assert response.status_code == 200
        assert mock_app_state.policy_manager.detach_policy_from_user.call_count == 2

    def test_delete_policy_with_attached_groups(self, client, mock_app_state):
        """Test deleting policy detaches from groups first."""
        mock_app_state.policy_manager._get_policy_attached_entities.return_value = {
            PolicyTarget.USER: [],
            PolicyTarget.GROUP: ["group1"],
        }

        response = client.delete("/management/policies/user-home-user1")

        assert response.status_code == 200
        mock_app_state.policy_manager.detach_policy_from_group.assert_called_once()

    def test_delete_policy_failure(self, client, mock_app_state):
        """Test handling policy delete failure."""
        mock_app_state.policy_manager.delete_resource.return_value = False

        response = client.delete("/management/policies/user-home-user1")

        assert response.status_code == 500  # PolicyOperationError


# === ASYNC FUNCTION TESTS ===


class TestManagementFunctionsAsync:
    """Async tests for management functions."""

    @pytest.mark.asyncio
    async def test_list_users_async(self, mock_app_state, mock_admin_user):
        """Test list_users function directly."""

        mock_request = MagicMock()

        with patch("src.routes.management.get_app_state", return_value=mock_app_state):
            response = await list_users(
                mock_request, mock_admin_user, page=1, page_size=50
            )

            assert response.total_count == 2

    @pytest.mark.asyncio
    async def test_create_user_async(self, mock_app_state, mock_admin_user):
        """Test create_user function directly."""

        mock_request = MagicMock()

        with patch("src.routes.management.get_app_state", return_value=mock_app_state):
            response = await create_user("newuser", mock_request, mock_admin_user)

            assert response.username == "newuser"
            assert response.operation == "create"

    @pytest.mark.asyncio
    async def test_delete_policy_detach_error_handling(
        self, mock_app_state, mock_admin_user
    ):
        """Test that detach errors don't stop policy deletion."""

        mock_request = MagicMock()

        mock_app_state.policy_manager._get_policy_attached_entities.return_value = {
            PolicyTarget.USER: ["user1"],
            PolicyTarget.GROUP: [],
        }
        mock_app_state.policy_manager.detach_policy_from_user.side_effect = Exception(
            "Detach error"
        )

        with patch("src.routes.management.get_app_state", return_value=mock_app_state):
            # Should not raise, just log warning
            response = await delete_policy("test-policy", mock_request, mock_admin_user)

            assert response.resource_type == "policy"


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

        with patch("src.routes.management.get_app_state", return_value=mock_app_state):
            response = await list_user_names(mock_request, mock_user)

            assert response.usernames == ["a", "b"]
            assert response.total_count == 2


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
        with patch(
            "src.routes.management.get_app_state", return_value=migration_app_state
        ):
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
        assert data["errors"] == []
