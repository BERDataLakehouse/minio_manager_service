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
    ResourceDeleteResponse,
    UserListResponse,
    UserManagementResponse,
    create_user,
    delete_policy,
    list_users,
    router,
)
from src.service.dependencies import require_admin
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
    mock_created_ro_group.policy_name = "group-policy-newgroup"
    app_state.group_manager.create_group = AsyncMock(
        return_value=(mock_created_group, mock_created_ro_group)
    )
    app_state.group_manager.add_user_to_group = AsyncMock()
    app_state.group_manager.remove_user_from_group = AsyncMock()
    app_state.group_manager.delete_resource = AsyncMock(return_value=True)

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

    def test_delete_user_failure(self, client, mock_app_state):
        """Test handling delete failure."""
        mock_app_state.user_manager.delete_resource.return_value = False

        response = client.delete("/management/users/user1")

        assert response.status_code == 400  # UserOperationError maps to 400


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
