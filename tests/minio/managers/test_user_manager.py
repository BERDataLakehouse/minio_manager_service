"""
Comprehensive tests for the minio.managers.user_manager module.

This module provides thorough test coverage for UserManager including:
- User creation with complete setup
- User retrieval and information gathering
- Credential generation and rotation
- Policy and group management
- Directory structure creation
- Error handling and edge cases
"""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.minio.managers.user_manager import UserManager, GLOBAL_USER_GROUP
from src.minio.core.minio_client import MinIOClient
from src.minio.models.minio_config import MinIOConfig
from src.minio.models.policy import (
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyStatement,
    PolicyAction,
)
from src.service.exceptions import UserOperationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Mock MC_PATH environment variable for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


@pytest.fixture
def mock_minio_config() -> MinIOConfig:
    """Create a mock MinIOConfig for testing."""
    return MinIOConfig(
        endpoint="http://localhost:9002",
        access_key="test_access_key",
        secret_key="test_secret_key",
        secure=False,
        default_bucket="test-bucket",
        users_sql_warehouse_prefix="users-sql-warehouse",
        users_general_warehouse_prefix="users-general-warehouse",
        tenant_general_warehouse_prefix="tenant-general-warehouse",
        tenant_sql_warehouse_prefix="tenant-sql-warehouse",
    )


@pytest.fixture
def mock_minio_client(mock_minio_config):
    """Create a mock MinIOClient."""
    client = MagicMock(spec=MinIOClient)
    client.config = mock_minio_config
    client.bucket_exists = AsyncMock(return_value=True)
    client.create_bucket = AsyncMock()
    client.put_object = AsyncMock()
    client.list_objects = AsyncMock(return_value=[])
    client.delete_object = AsyncMock()
    return client


@pytest.fixture
def mock_executor():
    """Create a mock BaseMinIOExecutor."""
    executor = MagicMock()
    executor.setup = AsyncMock()
    executor._execute_command = AsyncMock()
    return executor


@pytest.fixture
def mock_policy_manager():
    """Create a mock PolicyManager."""
    manager = MagicMock()
    manager.ensure_user_policies = AsyncMock()
    manager.attach_user_policies = AsyncMock()
    manager.detach_user_policies = AsyncMock()
    manager.delete_user_policies = AsyncMock()
    manager.is_policies_attached_to_user = AsyncMock(return_value=False)
    manager.get_user_home_policy = AsyncMock()
    manager.get_user_system_policy = AsyncMock()
    manager.get_group_policy = AsyncMock()
    manager.get_accessible_paths_from_policy = MagicMock(return_value=[])
    return manager


@pytest.fixture
def mock_group_manager():
    """Create a mock GroupManager."""
    manager = MagicMock()
    manager.resource_exists = AsyncMock(return_value=True)
    manager.create_group = AsyncMock()
    manager.add_user_to_group = AsyncMock()
    manager.get_user_groups = AsyncMock(return_value=[])
    return manager


@pytest.fixture
def user_manager(
    mock_minio_client,
    mock_minio_config,
    mock_executor,
    mock_policy_manager,
    mock_group_manager,
):
    """Create a UserManager with mocked dependencies."""
    manager = UserManager(
        client=mock_minio_client,
        config=mock_minio_config,
    )
    manager._executor = mock_executor
    manager._policy_manager = mock_policy_manager
    manager._group_manager = mock_group_manager
    return manager


@pytest.fixture
def sample_user_home_policy():
    """Create a sample user home policy."""
    return PolicyModel(
        policy_name="user-home-policy-testuser",
        policy_document=PolicyDocument(
            version="2012-10-17",
            statement=[
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.GET_BUCKET_LOCATION,
                    resource=["arn:aws:s3:::test-bucket"],
                ),
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.LIST_BUCKET,
                    resource=["arn:aws:s3:::test-bucket"],
                    condition={
                        "StringLike": {"s3:prefix": ["users-sql-warehouse/testuser/*"]}
                    },
                ),
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.GET_OBJECT,
                    resource=[
                        "arn:aws:s3:::test-bucket/users-sql-warehouse/testuser/*"
                    ],
                ),
            ],
        ),
    )


@pytest.fixture
def sample_user_system_policy():
    """Create a sample user system policy."""
    return PolicyModel(
        policy_name="user-system-policy-testuser",
        policy_document=PolicyDocument(
            version="2012-10-17",
            statement=[
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.GET_OBJECT,
                    resource=["arn:aws:s3:::spark-logs/testuser/*"],
                ),
            ],
        ),
    )


@pytest.fixture
def sample_group_policy():
    """Create a sample group policy."""
    return PolicyModel(
        policy_name="group-policy-testgroup",
        policy_document=PolicyDocument(
            version="2012-10-17",
            statement=[
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.GET_OBJECT,
                    resource=["arn:aws:s3:::test-bucket/shared/*"],
                ),
            ],
        ),
    )


# =============================================================================
# Test: UserManager Initialization
# =============================================================================


class TestUserManagerInit:
    """Tests for UserManager initialization."""

    def test_init_with_dependencies(self, mock_minio_client, mock_minio_config):
        """Test UserManager initialization with all dependencies."""
        manager = UserManager(
            client=mock_minio_client,
            config=mock_minio_config,
        )

        assert manager.client == mock_minio_client
        assert manager.config == mock_minio_config
        assert manager._policy_manager is None  # Lazy init
        assert manager._group_manager is None  # Lazy init

    def test_warehouse_prefixes_set(self, mock_minio_client, mock_minio_config):
        """Test that warehouse prefixes are set correctly."""
        manager = UserManager(
            client=mock_minio_client,
            config=mock_minio_config,
        )

        assert manager.users_general_warehouse_prefix == "users-general-warehouse"
        assert manager.users_sql_warehouse_prefix == "users-sql-warehouse"


class TestResourceManagerMethods:
    """Tests for ResourceManager abstract method implementations."""

    def test_get_resource_type(self, user_manager):
        """Test _get_resource_type returns 'user'."""
        assert user_manager._get_resource_type() == "user"

    def test_validate_resource_name_valid(self, user_manager):
        """Test _validate_resource_name with valid username."""
        result = user_manager._validate_resource_name("testuser123")
        assert result == "testuser123"

    def test_validate_resource_name_invalid_chars(self, user_manager):
        """Test _validate_resource_name with invalid characters."""
        with pytest.raises(UserOperationError):  # Should raise validation error
            user_manager._validate_resource_name("user@invalid")

    def test_validate_resource_name_reserved(self, user_manager):
        """Test _validate_resource_name with reserved username."""
        with pytest.raises(UserOperationError):  # Reserved username
            user_manager._validate_resource_name("admin")

    def test_build_exists_command(self, user_manager):
        """Test _build_exists_command builds correct command."""
        cmd = user_manager._build_exists_command("testuser")
        assert "user" in cmd
        assert "info" in cmd
        assert "testuser" in cmd

    def test_build_list_command(self, user_manager):
        """Test _build_list_command builds correct command."""
        cmd = user_manager._build_list_command()
        assert "user" in cmd
        assert "list" in cmd

    def test_build_delete_command(self, user_manager):
        """Test _build_delete_command builds correct command."""
        cmd = user_manager._build_delete_command("testuser")
        assert "user" in cmd
        assert "remove" in cmd
        assert "testuser" in cmd

    def test_parse_list_output_valid(self, user_manager):
        """Test _parse_list_output with valid JSON output."""
        output = '{"accessKey": "user1"}\n{"accessKey": "user2"}'
        result = user_manager._parse_list_output(output)
        assert result == ["user1", "user2"]

    def test_parse_list_output_empty(self, user_manager):
        """Test _parse_list_output with empty output."""
        result = user_manager._parse_list_output("")
        assert result == []

    def test_parse_list_output_invalid_json(self, user_manager):
        """Test _parse_list_output with invalid JSON."""
        with pytest.raises(UserOperationError):
            user_manager._parse_list_output("not valid json")


# =============================================================================
# Test: User Creation
# =============================================================================


class TestCreateUser:
    """Tests for create_user method."""

    @pytest.mark.asyncio
    async def test_creates_new_user_successfully(
        self,
        user_manager,
        mock_executor,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test creating a new user with all components."""
        mock_executor._execute_command.return_value = MagicMock(success=True, stderr="")
        mock_policy_manager.ensure_user_policies.return_value = (
            sample_user_home_policy,
            sample_user_system_policy,
        )
        user_manager.resource_exists = AsyncMock(return_value=False)

        result = await user_manager.create_user("testuser")

        assert result.username == "testuser"
        assert result.access_key == "testuser"
        assert result.secret_key is not None  # Auto-generated
        assert len(result.home_paths) == 2
        mock_policy_manager.ensure_user_policies.assert_called_once_with("testuser")
        mock_policy_manager.attach_user_policies.assert_called_once_with("testuser")

    @pytest.mark.asyncio
    async def test_creates_user_with_provided_password(
        self,
        user_manager,
        mock_executor,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test creating user with explicit password."""
        mock_executor._execute_command.return_value = MagicMock(success=True, stderr="")
        mock_policy_manager.ensure_user_policies.return_value = (
            sample_user_home_policy,
            sample_user_system_policy,
        )
        user_manager.resource_exists = AsyncMock(return_value=False)

        result = await user_manager.create_user("testuser", password="mypassword123")

        assert result.secret_key == "mypassword123"

    @pytest.mark.asyncio
    async def test_creates_user_idempotent(
        self,
        user_manager,
        mock_executor,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test that create_user is idempotent (can be called multiple times)."""
        mock_policy_manager.ensure_user_policies.return_value = (
            sample_user_home_policy,
            sample_user_system_policy,
        )
        user_manager.resource_exists = AsyncMock(
            return_value=True
        )  # User already exists
        mock_policy_manager.is_policies_attached_to_user.return_value = (
            True  # Policies attached
        )

        result = await user_manager.create_user("testuser")

        # Should not call execute_command for user creation since user exists
        assert result.username == "testuser"

    @pytest.mark.asyncio
    async def test_creates_global_user_group_if_not_exists(
        self,
        user_manager,
        mock_executor,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test that global user group is created if it doesn't exist."""
        mock_executor._execute_command.return_value = MagicMock(success=True, stderr="")
        mock_policy_manager.ensure_user_policies.return_value = (
            sample_user_home_policy,
            sample_user_system_policy,
        )
        user_manager.resource_exists = AsyncMock(return_value=False)
        mock_group_manager.resource_exists.return_value = False  # Group doesn't exist

        await user_manager.create_user("testuser")

        mock_group_manager.create_group.assert_called_once_with(
            GLOBAL_USER_GROUP, "testuser"
        )

    @pytest.mark.asyncio
    async def test_create_user_validates_username(self, user_manager):
        """Test that create_user validates the username."""
        with pytest.raises(
            UserOperationError
        ):  # Should raise validation error for reserved
            await user_manager.create_user("admin")

    @pytest.mark.asyncio
    async def test_create_user_command_failure(
        self,
        user_manager,
        mock_executor,
        mock_policy_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test create_user handles command failure."""
        mock_executor._execute_command.return_value = MagicMock(
            success=False, stderr="Command failed"
        )
        mock_policy_manager.ensure_user_policies.return_value = (
            sample_user_home_policy,
            sample_user_system_policy,
        )
        user_manager.resource_exists = AsyncMock(return_value=False)

        with pytest.raises(UserOperationError) as exc_info:
            await user_manager.create_user("testuser")

        assert "Failed to create MinIO user" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_user_creates_directory_structure(
        self,
        user_manager,
        mock_minio_client,
        mock_executor,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test that create_user creates home directory structure."""
        mock_executor._execute_command.return_value = MagicMock(success=True, stderr="")
        mock_policy_manager.ensure_user_policies.return_value = (
            sample_user_home_policy,
            sample_user_system_policy,
        )
        user_manager.resource_exists = AsyncMock(return_value=False)

        await user_manager.create_user("testuser")

        # Should call put_object for directory markers and welcome file
        assert mock_minio_client.put_object.call_count >= 1


# =============================================================================
# Test: Get User
# =============================================================================


class TestGetUser:
    """Tests for get_user method."""

    @pytest.mark.asyncio
    async def test_gets_existing_user(
        self,
        user_manager,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test getting information for existing user."""
        user_manager.resource_exists = AsyncMock(return_value=True)
        mock_policy_manager.get_user_home_policy.return_value = sample_user_home_policy
        mock_policy_manager.get_user_system_policy.return_value = (
            sample_user_system_policy
        )
        mock_group_manager.get_user_groups.return_value = []

        result = await user_manager.get_user("testuser")

        assert result.username == "testuser"
        assert result.secret_key == "<redacted>"  # Should be redacted
        assert result.user_policies == [
            sample_user_home_policy,
            sample_user_system_policy,
        ]

    @pytest.mark.asyncio
    async def test_gets_user_with_groups(
        self,
        user_manager,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
        sample_group_policy,
    ):
        """Test getting user with group memberships."""
        user_manager.resource_exists = AsyncMock(return_value=True)
        mock_policy_manager.get_user_home_policy.return_value = sample_user_home_policy
        mock_policy_manager.get_user_system_policy.return_value = (
            sample_user_system_policy
        )
        mock_group_manager.get_user_groups.return_value = ["testgroup"]
        mock_policy_manager.get_group_policy.return_value = sample_group_policy

        result = await user_manager.get_user("testuser")

        assert "testgroup" in result.groups
        assert sample_group_policy in result.group_policies

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, user_manager):
        """Test get_user raises error for non-existent user."""
        user_manager.resource_exists = AsyncMock(return_value=False)

        with pytest.raises(UserOperationError) as exc_info:
            await user_manager.get_user("nonexistent")

        assert "not found" in str(exc_info.value)


# =============================================================================
# Test: Get or Rotate Credentials
# =============================================================================


class TestGetOrRotateCredentials:
    """Tests for get_or_rotate_user_credentials method."""

    @pytest.mark.asyncio
    async def test_rotates_credentials_successfully(self, user_manager, mock_executor):
        """Test credential rotation for existing user."""
        user_manager.resource_exists = AsyncMock(return_value=True)
        mock_executor._execute_command.return_value = MagicMock(success=True, stderr="")

        access_key, secret_key = await user_manager.get_or_rotate_user_credentials(
            "testuser"
        )

        assert access_key == "testuser"  # Access key is always username
        assert secret_key is not None
        assert len(secret_key) >= 8  # Generated password length

    @pytest.mark.asyncio
    async def test_rotate_credentials_user_not_found(self, user_manager):
        """Test credential rotation fails for non-existent user."""
        user_manager.resource_exists = AsyncMock(return_value=False)

        with pytest.raises(UserOperationError) as exc_info:
            await user_manager.get_or_rotate_user_credentials("nonexistent")

        assert "not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_rotate_credentials_command_failure(
        self, user_manager, mock_executor
    ):
        """Test credential rotation handles command failure."""
        user_manager.resource_exists = AsyncMock(return_value=True)
        mock_executor._execute_command.return_value = MagicMock(
            success=False, stderr="Update failed"
        )

        with pytest.raises(UserOperationError) as exc_info:
            await user_manager.get_or_rotate_user_credentials("testuser")

        assert "Failed to update password" in str(exc_info.value)


# =============================================================================
# Test: Get User Policies
# =============================================================================


class TestGetUserPolicies:
    """Tests for get_user_policies method."""

    @pytest.mark.asyncio
    async def test_gets_user_policies(
        self,
        user_manager,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test getting all policies for a user."""
        user_manager.resource_exists = AsyncMock(return_value=True)
        mock_policy_manager.get_user_home_policy.return_value = sample_user_home_policy
        mock_policy_manager.get_user_system_policy.return_value = (
            sample_user_system_policy
        )
        mock_group_manager.get_user_groups.return_value = []

        result = await user_manager.get_user_policies("testuser")

        assert result["user_home_policy"] == sample_user_home_policy
        assert result["user_system_policy"] == sample_user_system_policy
        assert result["group_policies"] == []

    @pytest.mark.asyncio
    async def test_gets_policies_with_groups(
        self,
        user_manager,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
        sample_group_policy,
    ):
        """Test getting policies including group policies."""
        user_manager.resource_exists = AsyncMock(return_value=True)
        mock_policy_manager.get_user_home_policy.return_value = sample_user_home_policy
        mock_policy_manager.get_user_system_policy.return_value = (
            sample_user_system_policy
        )
        mock_group_manager.get_user_groups.return_value = ["testgroup"]
        mock_policy_manager.get_group_policy.return_value = sample_group_policy

        result = await user_manager.get_user_policies("testuser")

        assert sample_group_policy in result["group_policies"]

    @pytest.mark.asyncio
    async def test_get_policies_user_not_found(self, user_manager):
        """Test get_user_policies raises error for non-existent user."""
        user_manager.resource_exists = AsyncMock(return_value=False)

        with pytest.raises(UserOperationError) as exc_info:
            await user_manager.get_user_policies("nonexistent")

        assert "not found" in str(exc_info.value)


# =============================================================================
# Test: Can User Share Path
# =============================================================================


class TestCanUserSharePath:
    """Tests for can_user_share_path method."""

    @pytest.mark.asyncio
    async def test_can_share_path_in_general_warehouse(self, user_manager):
        """Test user can share path in their general warehouse."""
        result = await user_manager.can_user_share_path(
            "s3a://test-bucket/users-general-warehouse/testuser/data/", "testuser"
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_can_share_path_in_sql_warehouse(self, user_manager):
        """Test user can share path in their SQL warehouse."""
        result = await user_manager.can_user_share_path(
            "s3a://test-bucket/users-sql-warehouse/testuser/data/", "testuser"
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_cannot_share_other_user_path(self, user_manager):
        """Test user cannot share another user's path."""
        result = await user_manager.can_user_share_path(
            "s3a://test-bucket/users-general-warehouse/otheruser/data/", "testuser"
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_cannot_share_tenant_path(self, user_manager):
        """Test user cannot share tenant paths."""
        result = await user_manager.can_user_share_path(
            "s3a://test-bucket/tenant-general-warehouse/somepath/", "testuser"
        )
        assert result is False


# =============================================================================
# Test: Get User Accessible Paths
# =============================================================================


class TestGetUserAccessiblePaths:
    """Tests for get_user_accessible_paths method."""

    @pytest.mark.asyncio
    async def test_gets_accessible_paths(
        self,
        user_manager,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test getting all accessible paths for a user."""
        user_manager.resource_exists = AsyncMock(return_value=True)
        mock_policy_manager.get_user_home_policy.return_value = sample_user_home_policy
        mock_policy_manager.get_user_system_policy.return_value = (
            sample_user_system_policy
        )
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "/path1",
            "/path2",
        ]
        mock_group_manager.get_user_groups.return_value = []

        result = await user_manager.get_user_accessible_paths("testuser")

        assert isinstance(result, list)
        mock_policy_manager.get_accessible_paths_from_policy.assert_called()

    @pytest.mark.asyncio
    async def test_accessible_paths_user_not_found(self, user_manager):
        """Test get_user_accessible_paths raises error for non-existent user."""
        user_manager.resource_exists = AsyncMock(return_value=False)

        with pytest.raises(UserOperationError) as exc_info:
            await user_manager.get_user_accessible_paths("nonexistent")

        assert "not found" in str(exc_info.value)


# =============================================================================
# Test: Pre/Post Delete Cleanup
# =============================================================================


class TestDeleteCleanup:
    """Tests for pre/post delete cleanup methods."""

    @pytest.mark.asyncio
    async def test_pre_delete_cleanup(self, user_manager, mock_policy_manager):
        """Test pre-delete cleanup detaches and deletes policies."""
        await user_manager._pre_delete_cleanup("testuser")

        mock_policy_manager.detach_user_policies.assert_called_once_with("testuser")
        mock_policy_manager.delete_user_policies.assert_called_once_with("testuser")

    @pytest.mark.asyncio
    async def test_post_delete_cleanup(self, user_manager, mock_minio_client):
        """Test post-delete cleanup removes directories."""
        mock_minio_client.list_objects.return_value = ["obj1", "obj2"]

        await user_manager._post_delete_cleanup("testuser")

        # Should list and delete objects
        assert mock_minio_client.list_objects.call_count >= 1
        assert mock_minio_client.delete_object.call_count >= 1


# =============================================================================
# Test: Lazy Manager Initialization
# =============================================================================


class TestLazyManagerInit:
    """Tests for lazy initialization of policy_manager and group_manager."""

    def test_policy_manager_lazy_init(self, mock_minio_client, mock_minio_config):
        """Test policy_manager is lazily initialized."""
        manager = UserManager(
            client=mock_minio_client,
            config=mock_minio_config,
        )
        manager._executor = MagicMock()

        assert manager._policy_manager is None
        # Access property triggers initialization
        pm = manager.policy_manager
        assert pm is not None
        # Second access returns same instance
        assert manager.policy_manager is pm

    def test_group_manager_lazy_init(self, mock_minio_client, mock_minio_config):
        """Test group_manager is lazily initialized."""
        manager = UserManager(
            client=mock_minio_client,
            config=mock_minio_config,
        )
        manager._executor = MagicMock()

        assert manager._group_manager is None
        # Access property triggers initialization
        gm = manager.group_manager
        assert gm is not None
        # Second access returns same instance
        assert manager.group_manager is gm


# =============================================================================
# Test: Private Helper Methods
# =============================================================================


class TestPrivateHelperMethods:
    """Tests for private helper methods."""

    def test_generate_secure_password(self, user_manager):
        """Test secure password generation."""
        password = user_manager._generate_secure_password()
        assert len(password) == 8
        # Should contain at least some alphanumeric chars
        assert any(c.isalnum() for c in password)

    def test_generate_secure_password_custom_length(self, user_manager):
        """Test secure password generation with custom length."""
        password = user_manager._generate_secure_password(length=16)
        assert len(password) == 16

    def test_is_path_in_user_home_general(self, user_manager):
        """Test path detection in general warehouse."""
        result = user_manager._is_path_in_user_home(
            "s3a://test-bucket/users-general-warehouse/testuser/data/", "testuser"
        )
        assert result is True

    def test_is_path_in_user_home_sql(self, user_manager):
        """Test path detection in SQL warehouse."""
        result = user_manager._is_path_in_user_home(
            "s3://test-bucket/users-sql-warehouse/testuser/data/", "testuser"
        )
        assert result is True

    def test_is_path_not_in_user_home(self, user_manager):
        """Test path detection for paths outside user home."""
        result = user_manager._is_path_in_user_home(
            "s3a://test-bucket/tenant-general-warehouse/data/", "testuser"
        )
        assert result is False

    def test_get_user_home_paths(self, user_manager):
        """Test getting user home paths."""
        paths = user_manager._get_user_home_paths("testuser")
        assert len(paths) == 2
        assert "users-general-warehouse/testuser" in paths[0]
        assert "users-sql-warehouse/testuser" in paths[1]


# =============================================================================
# Test: Directory Structure Creation
# =============================================================================


class TestDirectoryCreation:
    """Tests for directory structure creation methods."""

    @pytest.mark.asyncio
    async def test_create_user_home_directory(self, user_manager, mock_minio_client):
        """Test creating user home directory structure."""
        await user_manager._create_user_home_directory("testuser")

        # Should create bucket if needed and put directory markers
        mock_minio_client.bucket_exists.assert_called()
        assert mock_minio_client.put_object.call_count >= 1

    @pytest.mark.asyncio
    async def test_create_directory_structure(self, user_manager, mock_minio_client):
        """Test creating directory structure with markers."""
        await user_manager._create_directory_structure("testuser", "test-bucket")

        # Should create markers for each directory
        assert mock_minio_client.put_object.call_count >= 5  # Multiple directories

    @pytest.mark.asyncio
    async def test_create_welcome_file(self, user_manager, mock_minio_client):
        """Test creating welcome file for new user."""
        await user_manager._create_welcome_file("testuser", "test-bucket")

        # Should create README.txt
        mock_minio_client.put_object.assert_called_once()
        call_args = mock_minio_client.put_object.call_args
        assert "README.txt" in call_args[0][1]

    @pytest.mark.asyncio
    async def test_delete_user_home_directory(self, user_manager, mock_minio_client):
        """Test deleting user home directories."""
        mock_minio_client.list_objects.return_value = ["obj1", "obj2"]

        await user_manager._delete_user_home_directory("testuser")

        # Should list and delete objects for both warehouses
        assert mock_minio_client.list_objects.call_count == 2
        assert mock_minio_client.delete_object.call_count == 4  # 2 objects * 2 prefixes


# =============================================================================
# Test: Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_create_user_with_minimum_length_password(
        self,
        user_manager,
        mock_executor,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test creating user with minimum length password."""
        mock_executor._execute_command.return_value = MagicMock(success=True, stderr="")
        mock_policy_manager.ensure_user_policies.return_value = (
            sample_user_home_policy,
            sample_user_system_policy,
        )
        user_manager.resource_exists = AsyncMock(return_value=False)

        result = await user_manager.create_user("testuser", password="12345678")

        assert result.secret_key == "12345678"

    @pytest.mark.asyncio
    async def test_handles_empty_group_list(
        self,
        user_manager,
        mock_policy_manager,
        mock_group_manager,
        sample_user_home_policy,
        sample_user_system_policy,
    ):
        """Test handling user with no group memberships."""
        user_manager.resource_exists = AsyncMock(return_value=True)
        mock_policy_manager.get_user_home_policy.return_value = sample_user_home_policy
        mock_policy_manager.get_user_system_policy.return_value = (
            sample_user_system_policy
        )
        mock_group_manager.get_user_groups.return_value = []

        result = await user_manager.get_user("testuser")

        assert result.groups == []
        assert result.group_policies == []

    @pytest.mark.asyncio
    async def test_bucket_creation_if_not_exists(self, user_manager, mock_minio_client):
        """Test bucket is created if it doesn't exist."""
        mock_minio_client.bucket_exists.return_value = False

        await user_manager._create_user_home_directory("testuser")

        mock_minio_client.create_bucket.assert_called_once()

    def test_username_with_numbers(self, user_manager):
        """Test validation of username with numbers."""
        result = user_manager._validate_resource_name("user123")
        assert result == "user123"

    def test_username_with_underscore(self, user_manager):
        """Test validation of username with underscore."""
        result = user_manager._validate_resource_name("user_name")
        assert result == "user_name"

    def test_get_user_system_paths(self, user_manager):
        """Test getting user system paths."""
        paths = user_manager._get_user_system_paths("testuser")
        assert isinstance(paths, dict)

    def test_get_user_system_paths_user_scoped_only(self, user_manager):
        """Test getting only user-scoped system paths."""
        paths = user_manager._get_user_system_paths("testuser", user_scoped_only=True)
        assert isinstance(paths, dict)
