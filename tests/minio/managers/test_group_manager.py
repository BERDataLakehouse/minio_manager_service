"""Comprehensive tests for the minio.managers.group_manager module."""

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.minio.managers.group_manager import GroupManager, RESOURCE_TYPE
from src.minio.models.command import CommandResult
from src.minio.models.group import GroupModel
from src.minio.models.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyStatement,
)
from src.service.exceptions import GroupOperationError


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Mock MC_PATH environment variable to avoid KeyError during executor init."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


@pytest.fixture
def mock_minio_config():
    """Create a mock MinIOConfig."""
    config = MagicMock()
    config.minio_alias = "minio_api"
    config.minio_url = "http://minio:9000"
    config.minio_access_key = "admin"
    config.minio_secret_key = "password"
    config.default_bucket = "data-lake"
    config.tenant_general_warehouse_prefix = "groups-general-warehouse"
    config.tenant_sql_warehouse_prefix = "groups-sql-warehouse"
    return config


@pytest.fixture
def mock_minio_client():
    """Create a mock MinIOClient."""
    client = AsyncMock()
    client.bucket_exists = AsyncMock(return_value=True)
    client.create_bucket = AsyncMock()
    client.put_object = AsyncMock()
    client.delete_object = AsyncMock()
    client.list_objects = AsyncMock(return_value=[])
    return client


@pytest.fixture
def mock_executor():
    """Create a mock BaseMinIOExecutor."""
    executor = AsyncMock()
    executor.setup = AsyncMock()
    executor._execute_command = AsyncMock()
    return executor


@pytest.fixture
def sample_policy_document():
    """Create a valid policy document for testing."""
    return PolicyDocument(
        version="2012-10-17",
        statement=[
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                action=PolicyAction.LIST_BUCKET,
                resource="arn:aws:s3:::data-lake",
                condition={
                    "StringLike": {
                        "s3:prefix": ["groups-general-warehouse/testgroup/*"]
                    }
                },
            )
        ],
    )


@pytest.fixture
def mock_policy_manager(sample_policy_document):
    """Create a mock PolicyManager."""
    policy_manager = AsyncMock()
    policy_manager.get_policy_name = MagicMock(return_value="group-policy-testgroup")

    # get_group_policy throws for new groups (like testgroupro) to trigger ensure_group_policy
    async def get_group_policy_side_effect(group_name: str):
        if group_name == "testgroup":
            return PolicyModel(
                policy_name="group-policy-testgroup",
                policy_document=sample_policy_document,
            )
        # Throw for unknown groups to simulate policy not existing
        raise Exception(f"Policy not found for {group_name}")

    policy_manager.get_group_policy = AsyncMock(
        side_effect=get_group_policy_side_effect
    )

    # ensure_group_policy can be called with (group_name) or (group_name, read_only=True)
    # Return appropriate policy based on group_name
    async def ensure_group_policy_side_effect(group_name: str, read_only: bool = False):
        return PolicyModel(
            policy_name=f"group-policy-{group_name}",
            policy_document=sample_policy_document,
        )

    policy_manager.ensure_group_policy = AsyncMock(
        side_effect=ensure_group_policy_side_effect
    )

    policy_manager.attach_policy_to_group = AsyncMock()
    policy_manager.detach_policy_from_group = AsyncMock()
    policy_manager.delete_group_policy = AsyncMock()
    policy_manager.is_policy_attached_to_group = AsyncMock(return_value=False)
    return policy_manager


@pytest.fixture
def mock_user_manager():
    """Create a mock UserManager."""
    user_manager = AsyncMock()
    user_manager.resource_exists = AsyncMock(return_value=True)
    return user_manager


@pytest.fixture
def group_manager_instance(mock_minio_client, mock_minio_config, mock_executor):
    """Create a GroupManager instance with mocked dependencies."""
    manager = GroupManager(mock_minio_client, mock_minio_config)
    manager._executor = mock_executor
    return manager


@pytest.fixture
def sample_group_info_json():
    """Sample JSON response for group info command."""
    return json.dumps(
        {
            "status": "success",
            "groupName": "testgroup",
            "members": ["user1", "user2", "user3"],
            "groupStatus": "enabled",
            "groupPolicy": "group-policy-testgroup",
        }
    )


@pytest.fixture
def sample_group_list_json():
    """Sample JSON response for group list command."""
    return json.dumps(
        {"status": "success", "groups": ["testgroup", "devteam", "analysts"]}
    )


@pytest.fixture
def sample_empty_group_info_json():
    """Sample JSON response for group info with no members."""
    return json.dumps(
        {
            "status": "success",
            "groupName": "emptygroup",
            "groupStatus": "enabled",
            "groupPolicy": "group-policy-emptygroup",
        }
    )


# =============================================================================
# TEST INITIALIZATION
# =============================================================================


class TestGroupManagerInit:
    """Tests for GroupManager initialization."""

    def test_initialization_with_valid_config(
        self, mock_minio_client, mock_minio_config
    ):
        """Test successful initialization with valid configuration."""
        manager = GroupManager(mock_minio_client, mock_minio_config)

        assert manager.client == mock_minio_client
        assert manager.config == mock_minio_config
        assert manager.tenant_general_warehouse_prefix == "groups-general-warehouse"
        assert manager.tenant_sql_warehouse_prefix == "groups-sql-warehouse"
        assert manager._policy_manager is None
        assert manager._user_manager is None

    def test_initialization_inherits_from_resource_manager(
        self, mock_minio_client, mock_minio_config
    ):
        """Test that GroupManager properly inherits from ResourceManager."""
        manager = GroupManager(mock_minio_client, mock_minio_config)

        # Check executor and command builder are initialized
        assert manager._executor is not None
        assert manager._command_builder is not None
        assert manager.alias is not None


# =============================================================================
# TEST RESOURCE MANAGER ABSTRACT METHODS
# =============================================================================


class TestResourceManagerMethods:
    """Tests for ResourceManager abstract method implementations."""

    def test_get_resource_type(self, group_manager_instance):
        """Test _get_resource_type returns 'group'."""
        assert group_manager_instance._get_resource_type() == "group"
        assert group_manager_instance._get_resource_type() == RESOURCE_TYPE

    def test_validate_resource_name_valid(self, group_manager_instance):
        """Test _validate_resource_name with valid group names."""
        assert (
            group_manager_instance._validate_resource_name("testgroup") == "testgroup"
        )
        assert (
            group_manager_instance._validate_resource_name("devteam123") == "devteam123"
        )
        assert (
            group_manager_instance._validate_resource_name("analystsquad")
            == "analystsquad"
        )

    def test_validate_resource_name_invalid_uppercase(self, group_manager_instance):
        """Test _validate_resource_name rejects uppercase characters."""
        with pytest.raises(GroupOperationError) as exc_info:
            group_manager_instance._validate_resource_name("TestGroup")
        assert (
            "lowercase" in str(exc_info.value).lower()
            or "uppercase" in str(exc_info.value).lower()
        )

    def test_validate_resource_name_invalid_underscore(self, group_manager_instance):
        """Test _validate_resource_name rejects underscores."""
        with pytest.raises(GroupOperationError) as exc_info:
            group_manager_instance._validate_resource_name("test_group")
        assert (
            "underscore" in str(exc_info.value).lower()
            or "lowercase letters and numbers" in str(exc_info.value).lower()
        )

    def test_validate_resource_name_reserved(self, group_manager_instance):
        """Test _validate_resource_name rejects reserved group names."""
        reserved_names = [
            "admin",
            "root",
            "system",
            "all",
            "everyone",
            "public",
            "default",
        ]
        for name in reserved_names:
            with pytest.raises(GroupOperationError) as exc_info:
                group_manager_instance._validate_resource_name(name)
            assert "reserved" in str(exc_info.value).lower()

    def test_validate_resource_name_too_short(self, group_manager_instance):
        """Test _validate_resource_name rejects too short names."""
        with pytest.raises(GroupOperationError) as exc_info:
            group_manager_instance._validate_resource_name("a")
        assert "2" in str(exc_info.value) or "character" in str(exc_info.value).lower()

    def test_validate_resource_name_must_start_with_letter(
        self, group_manager_instance
    ):
        """Test _validate_resource_name requires names to start with letter."""
        with pytest.raises(GroupOperationError) as exc_info:
            group_manager_instance._validate_resource_name("123group")
        assert "start with a letter" in str(exc_info.value).lower()

    def test_build_exists_command(self, group_manager_instance):
        """Test _build_exists_command builds correct command."""
        cmd = group_manager_instance._build_exists_command("testgroup")
        assert isinstance(cmd, list)
        assert "group" in " ".join(cmd).lower()
        assert "testgroup" in cmd

    def test_build_list_command(self, group_manager_instance):
        """Test _build_list_command builds correct command."""
        cmd = group_manager_instance._build_list_command()
        assert isinstance(cmd, list)
        assert "group" in " ".join(cmd).lower()

    def test_build_delete_command(self, group_manager_instance):
        """Test _build_delete_command builds correct command."""
        cmd = group_manager_instance._build_delete_command("testgroup")
        assert isinstance(cmd, list)
        assert "testgroup" in cmd

    def test_parse_list_output_valid_json(
        self, group_manager_instance, sample_group_list_json
    ):
        """Test _parse_list_output parses valid JSON correctly."""
        result = group_manager_instance._parse_list_output(sample_group_list_json)
        assert result == ["testgroup", "devteam", "analysts"]

    def test_parse_list_output_invalid_json(self, group_manager_instance):
        """Test _parse_list_output raises error on invalid JSON."""
        # The function raises GroupOperationError when parsing fails
        with pytest.raises((GroupOperationError, json.JSONDecodeError)):
            group_manager_instance._parse_list_output("invalid json")


# =============================================================================
# TEST LAZY MANAGER INITIALIZATION
# =============================================================================


class TestLazyManagerInit:
    """Tests for lazy manager initialization properties."""

    def test_policy_manager_lazy_init(self, group_manager_instance):
        """Test that policy_manager is lazily initialized."""
        assert group_manager_instance._policy_manager is None

        # Access the property - should trigger lazy init
        # The import is done inside the property method, so we need to patch at the module level
        with patch.object(group_manager_instance, "_policy_manager", None):
            with patch(
                "src.minio.managers.policy_manager.PolicyManager"
            ) as mock_pm_class:
                mock_pm_instance = MagicMock()
                mock_pm_class.return_value = mock_pm_instance

                # Reset and trigger lazy init
                group_manager_instance._policy_manager = None
                _ = group_manager_instance.policy_manager

                # After access, _policy_manager should no longer be None
                assert group_manager_instance._policy_manager is not None

    def test_policy_manager_cached(self, group_manager_instance):
        """Test that policy_manager is cached after first access."""
        mock_pm = MagicMock()
        group_manager_instance._policy_manager = mock_pm

        # Access property multiple times
        pm1 = group_manager_instance.policy_manager
        pm2 = group_manager_instance.policy_manager

        assert pm1 is pm2
        assert pm1 is mock_pm

    def test_user_manager_lazy_init(self, group_manager_instance):
        """Test that user_manager is lazily initialized."""
        assert group_manager_instance._user_manager is None

        # Access the property - should trigger lazy init
        with patch.object(group_manager_instance, "_user_manager", None):
            with patch("src.minio.managers.user_manager.UserManager") as mock_um_class:
                mock_um_instance = MagicMock()
                mock_um_class.return_value = mock_um_instance

                # Reset and trigger lazy init
                group_manager_instance._user_manager = None
                _ = group_manager_instance.user_manager

                # After access, _user_manager should no longer be None
                assert group_manager_instance._user_manager is not None

    def test_user_manager_cached(self, group_manager_instance):
        """Test that user_manager is cached after first access."""
        mock_um = MagicMock()
        group_manager_instance._user_manager = mock_um

        um1 = group_manager_instance.user_manager
        um2 = group_manager_instance.user_manager

        assert um1 is um2
        assert um1 is mock_um


# =============================================================================
# TEST CREATE GROUP
# =============================================================================


class TestCreateGroup:
    """Tests for create_group method."""

    @pytest.mark.asyncio
    async def test_create_group_success(
        self, group_manager_instance, mock_policy_manager, mock_user_manager
    ):
        """Test successful group creation."""
        group_manager_instance._policy_manager = mock_policy_manager
        group_manager_instance._user_manager = mock_user_manager

        # Mock resource_exists to return False (group doesn't exist)
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            # Mock command execution
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout="",
                    stderr="",
                    return_code=0,
                    command="mc admin group add",
                )
            )

            result, ro_result = await group_manager_instance.create_group(
                "testgroup", "creator"
            )

            assert isinstance(result, GroupModel)
            assert result.group_name == "testgroup"
            assert result.members == ["creator"]
            assert result.policy_name == "group-policy-testgroup"

            # Verify read-only group was also created
            assert isinstance(ro_result, GroupModel)
            assert ro_result.group_name == "testgroupro"
            assert ro_result.policy_name == "group-policy-testgroupro"

    @pytest.mark.asyncio
    async def test_create_group_creator_not_exists(
        self, group_manager_instance, mock_policy_manager, mock_user_manager
    ):
        """Test create_group fails when creator doesn't exist."""
        mock_user_manager.resource_exists.return_value = False
        group_manager_instance._policy_manager = mock_policy_manager
        group_manager_instance._user_manager = mock_user_manager

        with pytest.raises(GroupOperationError) as exc_info:
            await group_manager_instance.create_group("testgroup", "nonexistent")

        assert "does not exist" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_group_idempotent_existing_group(
        self, group_manager_instance, mock_policy_manager, mock_user_manager
    ):
        """Test create_group is idempotent when group already exists."""
        group_manager_instance._policy_manager = mock_policy_manager
        group_manager_instance._user_manager = mock_user_manager

        # Group already exists
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            result, ro_result = await group_manager_instance.create_group(
                "testgroup", "creator"
            )

            assert isinstance(result, GroupModel)
            assert isinstance(ro_result, GroupModel)
            # Should not call execute_command to create the group
            # But should still attach policy if not attached

    @pytest.mark.asyncio
    async def test_create_group_policy_already_attached(
        self, group_manager_instance, mock_policy_manager, mock_user_manager
    ):
        """Test create_group skips policy attachment if already attached."""
        mock_policy_manager.is_policy_attached_to_group.return_value = True
        group_manager_instance._policy_manager = mock_policy_manager
        group_manager_instance._user_manager = mock_user_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout="",
                    stderr="",
                    return_code=0,
                    command="mc admin group add",
                )
            )

            result, ro_result = await group_manager_instance.create_group(
                "testgroup", "creator"
            )

            # Verify both groups returned
            assert isinstance(result, GroupModel)
            assert isinstance(ro_result, GroupModel)
            # attach_policy_to_group should NOT be called since policies are already attached
            mock_policy_manager.attach_policy_to_group.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_group_command_fails(
        self, group_manager_instance, mock_policy_manager, mock_user_manager
    ):
        """Test create_group raises error when command fails."""
        group_manager_instance._policy_manager = mock_policy_manager
        group_manager_instance._user_manager = mock_user_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=False,
                    stdout="",
                    stderr="Group creation failed",
                    return_code=1,
                    command="mc admin group add",
                )
            )

            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.create_group("testgroup", "creator")

            assert "Failed to create group" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_group_policy_creation_fallback(
        self, group_manager_instance, mock_policy_manager, mock_user_manager
    ):
        """Test create_group falls back to ensure_group_policy if get_group_policy fails."""
        # Make get_group_policy fail first time (for both main and RO group)
        mock_policy_manager.get_group_policy.side_effect = Exception("Policy not found")
        group_manager_instance._policy_manager = mock_policy_manager
        group_manager_instance._user_manager = mock_user_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout="",
                    stderr="",
                    return_code=0,
                    command="mc admin group add",
                )
            )

            result, ro_result = await group_manager_instance.create_group(
                "testgroup", "creator"
            )

            # Verify both groups were created
            assert isinstance(result, GroupModel)
            assert isinstance(ro_result, GroupModel)

            # Should call ensure_group_policy with read_only=True as fallback
            mock_policy_manager.ensure_group_policy.assert_any_call("testgroup")
            mock_policy_manager.ensure_group_policy.assert_any_call(
                "testgroupro", read_only=True
            )


# =============================================================================
# TEST ADD USER TO GROUP
# =============================================================================


class TestAddUserToGroup:
    """Tests for add_user_to_group method."""

    @pytest.mark.asyncio
    async def test_add_user_to_group_success(
        self, group_manager_instance, mock_user_manager
    ):
        """Test successfully adding a user to a group."""
        group_manager_instance._user_manager = mock_user_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout="",
                    stderr="",
                    return_code=0,
                    command="mc admin group add",
                )
            )

            await group_manager_instance.add_user_to_group("testuser", "testgroup")

            # Verify command was called
            group_manager_instance._executor._execute_command.assert_called()

    @pytest.mark.asyncio
    async def test_add_user_to_group_group_not_exists(
        self, group_manager_instance, mock_user_manager
    ):
        """Test add_user_to_group fails when group doesn't exist."""
        group_manager_instance._user_manager = mock_user_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.add_user_to_group(
                    "testuser", "nonexistent"
                )

            assert "Group" in str(exc_info.value)
            assert "not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_add_user_to_group_user_not_exists(
        self, group_manager_instance, mock_user_manager
    ):
        """Test add_user_to_group fails when user doesn't exist."""
        mock_user_manager.resource_exists.return_value = False
        group_manager_instance._user_manager = mock_user_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.add_user_to_group(
                    "nonexistent", "testgroup"
                )

            assert "User" in str(exc_info.value)
            assert "does not exist" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_add_user_to_group_command_fails(
        self, group_manager_instance, mock_user_manager
    ):
        """Test add_user_to_group raises error when command fails."""
        group_manager_instance._user_manager = mock_user_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=False,
                    stdout="",
                    stderr="Add failed",
                    return_code=1,
                    command="mc admin group add",
                )
            )

            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.add_user_to_group("testuser", "testgroup")

            assert "Failed to add user" in str(exc_info.value)


# =============================================================================
# TEST REMOVE USER FROM GROUP
# =============================================================================


class TestRemoveUserFromGroup:
    """Tests for remove_user_from_group method."""

    @pytest.mark.asyncio
    async def test_remove_user_from_group_success(self, group_manager_instance):
        """Test successfully removing a user from a group."""
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout="",
                    stderr="",
                    return_code=0,
                    command="mc admin group rm",
                )
            )

            await group_manager_instance.remove_user_from_group("testuser", "testgroup")

            group_manager_instance._executor._execute_command.assert_called()

    @pytest.mark.asyncio
    async def test_remove_user_from_group_group_not_exists(
        self, group_manager_instance
    ):
        """Test remove_user_from_group fails when group doesn't exist."""
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.remove_user_from_group(
                    "testuser", "nonexistent"
                )

            assert "Group" in str(exc_info.value)
            assert "not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_remove_user_from_group_command_fails(self, group_manager_instance):
        """Test remove_user_from_group raises error when command fails."""
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=False,
                    stdout="",
                    stderr="Remove failed",
                    return_code=1,
                    command="mc admin group rm",
                )
            )

            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.remove_user_from_group(
                    "testuser", "testgroup"
                )

            assert "Failed to remove user" in str(exc_info.value)


# =============================================================================
# TEST GET GROUP MEMBERS
# =============================================================================


class TestGetGroupMembers:
    """Tests for get_group_members method."""

    @pytest.mark.asyncio
    async def test_get_group_members_success(
        self, group_manager_instance, sample_group_info_json
    ):
        """Test successfully getting group members."""
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout=sample_group_info_json,
                    stderr="",
                    return_code=0,
                    command="mc admin group info",
                )
            )

            members = await group_manager_instance.get_group_members("testgroup")

            assert members == ["user1", "user2", "user3"]

    @pytest.mark.asyncio
    async def test_get_group_members_empty_group(
        self, group_manager_instance, sample_empty_group_info_json
    ):
        """Test get_group_members returns empty list for empty group."""
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout=sample_empty_group_info_json,
                    stderr="",
                    return_code=0,
                    command="mc admin group info",
                )
            )

            members = await group_manager_instance.get_group_members("emptygroup")

            assert members == []

    @pytest.mark.asyncio
    async def test_get_group_members_group_not_exists(self, group_manager_instance):
        """Test get_group_members fails when group doesn't exist."""
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.get_group_members("nonexistent")

            assert "not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_group_members_command_fails(self, group_manager_instance):
        """Test get_group_members raises error when command fails."""
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=False,
                    stdout="",
                    stderr="Command failed",
                    return_code=1,
                    command="mc admin group info",
                )
            )

            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.get_group_members("testgroup")

            assert "Failed to get group info" in str(exc_info.value)


# =============================================================================
# TEST GET GROUP INFO
# =============================================================================


class TestGetGroupInfo:
    """Tests for get_group_info method."""

    @pytest.mark.asyncio
    async def test_get_group_info_success(
        self, group_manager_instance, mock_policy_manager, sample_group_info_json
    ):
        """Test successfully getting group info."""
        group_manager_instance._policy_manager = mock_policy_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            with patch.object(
                group_manager_instance,
                "get_group_members",
                AsyncMock(return_value=["user1", "user2", "user3"]),
            ):
                result = await group_manager_instance.get_group_info("testgroup")

                assert isinstance(result, GroupModel)
                assert result.group_name == "testgroup"
                assert result.members == ["user1", "user2", "user3"]
                assert result.policy_name == "group-policy-testgroup"

    @pytest.mark.asyncio
    async def test_get_group_info_group_not_exists(
        self, group_manager_instance, mock_policy_manager
    ):
        """Test get_group_info fails when group doesn't exist."""
        group_manager_instance._policy_manager = mock_policy_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.get_group_info("nonexistent")

            assert "not found" in str(exc_info.value)


# =============================================================================
# TEST IS USER IN GROUP
# =============================================================================


class TestIsUserInGroup:
    """Tests for is_user_in_group method."""

    @pytest.mark.asyncio
    async def test_is_user_in_group_true(self, group_manager_instance):
        """Test is_user_in_group returns True when user is a member."""
        with patch.object(
            group_manager_instance,
            "get_group_members",
            AsyncMock(return_value=["user1", "user2", "user3"]),
        ):
            result = await group_manager_instance.is_user_in_group("user2", "testgroup")

            assert result is True

    @pytest.mark.asyncio
    async def test_is_user_in_group_false(self, group_manager_instance):
        """Test is_user_in_group returns False when user is not a member."""
        with patch.object(
            group_manager_instance,
            "get_group_members",
            AsyncMock(return_value=["user1", "user2", "user3"]),
        ):
            result = await group_manager_instance.is_user_in_group("user4", "testgroup")

            assert result is False

    @pytest.mark.asyncio
    async def test_is_user_in_group_exception(self, group_manager_instance):
        """Test is_user_in_group raises error on failure."""
        with patch.object(
            group_manager_instance,
            "get_group_members",
            AsyncMock(side_effect=Exception("Get members failed")),
        ):
            with pytest.raises(GroupOperationError) as exc_info:
                await group_manager_instance.is_user_in_group("testuser", "testgroup")

            assert "Failed to check" in str(exc_info.value)


# =============================================================================
# TEST GET USER GROUPS
# =============================================================================


class TestGetUserGroups:
    """Tests for get_user_groups method."""

    @pytest.mark.asyncio
    async def test_get_user_groups_success(self, group_manager_instance):
        """Test successfully getting user's groups."""
        with patch.object(
            group_manager_instance,
            "list_resources",
            AsyncMock(return_value=["group1", "group2", "group3"]),
        ):
            with patch.object(
                group_manager_instance,
                "is_user_in_group",
                AsyncMock(
                    side_effect=[True, False, True]
                ),  # user is in group1 and group3
            ):
                result = await group_manager_instance.get_user_groups("testuser")

                # Results should be sorted
                assert result == ["group1", "group3"]

    @pytest.mark.asyncio
    async def test_get_user_groups_no_groups(self, group_manager_instance):
        """Test get_user_groups when user is not in any group."""
        with patch.object(
            group_manager_instance,
            "list_resources",
            AsyncMock(return_value=["group1", "group2"]),
        ):
            with patch.object(
                group_manager_instance,
                "is_user_in_group",
                AsyncMock(return_value=False),
            ):
                result = await group_manager_instance.get_user_groups("testuser")

                assert result == []

    @pytest.mark.asyncio
    async def test_get_user_groups_empty_system(self, group_manager_instance):
        """Test get_user_groups when no groups exist."""
        with patch.object(
            group_manager_instance, "list_resources", AsyncMock(return_value=[])
        ):
            result = await group_manager_instance.get_user_groups("testuser")

            assert result == []


# =============================================================================
# TEST PRE/POST DELETE CLEANUP
# =============================================================================


class TestDeleteCleanup:
    """Tests for pre and post delete cleanup methods."""

    @pytest.mark.asyncio
    async def test_pre_delete_cleanup_success(
        self, group_manager_instance, mock_policy_manager
    ):
        """Test _pre_delete_cleanup detaches and deletes policy for main and read-only groups."""
        group_manager_instance._policy_manager = mock_policy_manager

        # Mock resource_exists to return True for read-only group
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            # Mock command execution for deleting read-only group
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout="",
                    stderr="",
                    return_code=0,
                    command="mc admin group rm",
                )
            )

            await group_manager_instance._pre_delete_cleanup("testgroup")

        # Should detach policy from both main group and read-only group
        assert mock_policy_manager.detach_policy_from_group.call_count == 2
        # Should delete both main and read-only policies
        assert mock_policy_manager.delete_group_policy.call_count == 2
        mock_policy_manager.delete_group_policy.assert_any_call("testgroup")
        mock_policy_manager.delete_group_policy.assert_any_call(
            "testgroupro", read_only=True
        )

    @pytest.mark.asyncio
    async def test_pre_delete_cleanup_detach_fails_continues(
        self, group_manager_instance, mock_policy_manager
    ):
        """Test _pre_delete_cleanup continues if detach fails."""
        mock_policy_manager.detach_policy_from_group.side_effect = Exception(
            "Detach failed"
        )
        group_manager_instance._policy_manager = mock_policy_manager

        # Should not raise
        await group_manager_instance._pre_delete_cleanup("testgroup")

        # delete_group_policy should still be called for both policies
        assert mock_policy_manager.delete_group_policy.call_count == 2

    @pytest.mark.asyncio
    async def test_pre_delete_cleanup_delete_policy_fails_continues(
        self, group_manager_instance, mock_policy_manager
    ):
        """Test _pre_delete_cleanup continues if policy deletion fails."""
        mock_policy_manager.delete_group_policy.side_effect = Exception("Delete failed")
        group_manager_instance._policy_manager = mock_policy_manager

        # Should not raise
        await group_manager_instance._pre_delete_cleanup("testgroup")

    @pytest.mark.asyncio
    async def test_pre_delete_cleanup_ro_group_not_exists(
        self, group_manager_instance, mock_policy_manager
    ):
        """Test _pre_delete_cleanup handles case when read-only group doesn't exist."""
        group_manager_instance._policy_manager = mock_policy_manager

        # Mock resource_exists to return False for read-only group
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            await group_manager_instance._pre_delete_cleanup("testgroup")

        # Should still detach from main group (once, not twice)
        assert mock_policy_manager.detach_policy_from_group.call_count == 1
        # Should still call delete_group_policy
        mock_policy_manager.delete_group_policy.assert_called_once_with("testgroup")

    @pytest.mark.asyncio
    async def test_post_delete_cleanup_success(
        self, group_manager_instance, mock_minio_client
    ):
        """Test _post_delete_cleanup deletes shared directories."""
        mock_minio_client.list_objects.return_value = ["obj1", "obj2"]

        await group_manager_instance._post_delete_cleanup("testgroup")

        # Should delete objects from both warehouse directories
        assert mock_minio_client.delete_object.call_count >= 2

    @pytest.mark.asyncio
    async def test_post_delete_cleanup_handles_exception(
        self, group_manager_instance, mock_minio_client
    ):
        """Test _post_delete_cleanup handles exceptions gracefully."""
        mock_minio_client.list_objects.side_effect = Exception("List failed")

        # Should not raise
        await group_manager_instance._post_delete_cleanup("testgroup")


# =============================================================================
# TEST DIRECTORY CREATION
# =============================================================================


class TestDirectoryCreation:
    """Tests for directory creation methods."""

    @pytest.mark.asyncio
    async def test_create_group_shared_directory_bucket_exists(
        self, group_manager_instance, mock_minio_client
    ):
        """Test _create_group_shared_directory when bucket exists."""
        await group_manager_instance._create_group_shared_directory("testgroup")

        mock_minio_client.bucket_exists.assert_called()
        mock_minio_client.create_bucket.assert_not_called()
        # Should create directory markers and welcome file
        assert mock_minio_client.put_object.call_count >= 1

    @pytest.mark.asyncio
    async def test_create_group_shared_directory_bucket_not_exists(
        self, group_manager_instance, mock_minio_client
    ):
        """Test _create_group_shared_directory creates bucket if needed."""
        mock_minio_client.bucket_exists.return_value = False

        await group_manager_instance._create_group_shared_directory("testgroup")

        mock_minio_client.create_bucket.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_group_directory_structure(
        self, group_manager_instance, mock_minio_client
    ):
        """Test _create_group_directory_structure creates correct paths."""
        await group_manager_instance._create_group_directory_structure(
            "testgroup", "data-lake"
        )

        # Should create 5 directory markers
        assert mock_minio_client.put_object.call_count == 5

        # Verify calls include expected paths
        call_args = [call[0] for call in mock_minio_client.put_object.call_args_list]
        paths = [args[1] for args in call_args]  # Extract object keys

        assert any("groups-sql-warehouse/testgroup/" in p for p in paths)
        assert any("groups-general-warehouse/testgroup/" in p for p in paths)
        assert any("shared/" in p for p in paths)
        assert any("datasets/" in p for p in paths)
        assert any("projects/" in p for p in paths)

    @pytest.mark.asyncio
    async def test_create_group_welcome_file(
        self, group_manager_instance, mock_minio_client
    ):
        """Test _create_group_welcome_file creates correct content."""
        await group_manager_instance._create_group_welcome_file(
            "testgroup", "data-lake"
        )

        mock_minio_client.put_object.assert_called_once()
        call_args = mock_minio_client.put_object.call_args
        assert call_args[0][0] == "data-lake"  # bucket
        assert "README.txt" in call_args[0][1]  # key
        assert b"testgroup" in call_args[0][2]  # content contains group name


# =============================================================================
# TEST PRIVATE HELPER METHODS
# =============================================================================


class TestPrivateHelperMethods:
    """Tests for private helper methods."""

    @pytest.mark.asyncio
    async def test_parse_group_members_with_members(self, group_manager_instance):
        """Test _parse_group_members extracts members correctly."""
        json_output = json.dumps(
            {
                "status": "success",
                "groupName": "testgroup",
                "members": ["user1", "user2"],
                "groupStatus": "enabled",
            }
        )

        result = await group_manager_instance._parse_group_members(json_output)

        assert result == ["user1", "user2"]

    @pytest.mark.asyncio
    async def test_parse_group_members_no_members_key(self, group_manager_instance):
        """Test _parse_group_members returns empty list when no members key."""
        json_output = json.dumps(
            {"status": "success", "groupName": "emptygroup", "groupStatus": "enabled"}
        )

        result = await group_manager_instance._parse_group_members(json_output)

        assert result == []

    @pytest.mark.asyncio
    async def test_parse_group_members_invalid_json(self, group_manager_instance):
        """Test _parse_group_members raises error on invalid JSON."""
        with pytest.raises(GroupOperationError) as exc_info:
            await group_manager_instance._parse_group_members("not valid json")

        assert "Failed to parse group members" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_delete_group_shared_directory(
        self, group_manager_instance, mock_minio_client
    ):
        """Test _delete_group_shared_directory deletes both warehouse dirs."""
        mock_minio_client.list_objects.return_value = ["file1.txt", "file2.txt"]

        await group_manager_instance._delete_group_shared_directory("testgroup")

        # Should list objects from both prefixes
        assert mock_minio_client.list_objects.call_count == 2

        # Should delete all objects
        assert mock_minio_client.delete_object.call_count == 4  # 2 files x 2 dirs


# =============================================================================
# TEST EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_create_group_with_whitespace_name(
        self, group_manager_instance, mock_user_manager, mock_policy_manager
    ):
        """Test create_group handles whitespace in name."""
        group_manager_instance._user_manager = mock_user_manager
        group_manager_instance._policy_manager = mock_policy_manager

        # Validation should handle whitespace stripping
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout="",
                    stderr="",
                    return_code=0,
                    command="mc admin group add",
                )
            )

            result, ro_result = await group_manager_instance.create_group(
                "  testgroup  ", "creator"
            )
            assert result.group_name == "testgroup"
            assert ro_result.group_name == "testgroupro"

    @pytest.mark.asyncio
    async def test_group_name_validation_special_chars(self, group_manager_instance):
        """Test group name validation rejects special characters."""
        invalid_names = ["test@group", "test#group", "test$group", "test%group"]

        for name in invalid_names:
            with pytest.raises(GroupOperationError):
                group_manager_instance._validate_resource_name(name)

    @pytest.mark.asyncio
    async def test_group_name_validation_hyphens_periods(self, group_manager_instance):
        """Test group name validation rejects hyphens and periods."""
        # Group names only allow lowercase alphanumeric
        invalid_names = ["test-group", "test.group"]

        for name in invalid_names:
            with pytest.raises(GroupOperationError):
                group_manager_instance._validate_resource_name(name)

    @pytest.mark.asyncio
    async def test_concurrent_add_remove_idempotent(
        self, group_manager_instance, mock_user_manager
    ):
        """Test that add/remove operations are idempotent."""
        group_manager_instance._user_manager = mock_user_manager

        # Both add and remove should succeed without errors for idempotent behavior
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=True,
                    stdout="",
                    stderr="",
                    return_code=0,
                    command="mc admin group",
                )
            )

            # Add user twice - should not fail
            await group_manager_instance.add_user_to_group("user1", "testgroup")
            await group_manager_instance.add_user_to_group("user1", "testgroup")

            # Remove user twice - should not fail
            await group_manager_instance.remove_user_from_group("user1", "testgroup")
            await group_manager_instance.remove_user_from_group("user1", "testgroup")

    @pytest.mark.asyncio
    async def test_get_user_groups_sorted(self, group_manager_instance):
        """Test get_user_groups returns sorted list."""
        with patch.object(
            group_manager_instance,
            "list_resources",
            AsyncMock(return_value=["zebra", "alpha", "middle"]),
        ):
            with patch.object(
                group_manager_instance, "is_user_in_group", AsyncMock(return_value=True)
            ):
                result = await group_manager_instance.get_user_groups("testuser")

                assert result == ["alpha", "middle", "zebra"]

    def test_group_model_properties(self):
        """Test GroupModel computed properties."""
        group = GroupModel(
            group_name="testgroup",
            members=["user1", "user2"],
            policy_name="group-policy-testgroup",
        )

        assert group.member_count == 2
        assert group.is_empty is False

        empty_group = GroupModel(
            group_name="emptygroup", members=[], policy_name="group-policy-emptygroup"
        )

        assert empty_group.member_count == 0
        assert empty_group.is_empty is True

    @pytest.mark.asyncio
    async def test_resource_exists_returns_false_on_exception(
        self, group_manager_instance
    ):
        """Test resource_exists returns False when exception occurs."""
        group_manager_instance._executor._execute_command.side_effect = Exception(
            "Error"
        )

        result = await group_manager_instance.resource_exists("testgroup")

        assert result is False

    @pytest.mark.asyncio
    async def test_list_resources_returns_empty_on_failure(
        self, group_manager_instance
    ):
        """Test list_resources returns empty list on failure."""
        group_manager_instance._executor._execute_command.return_value = CommandResult(
            success=False,
            stdout="",
            stderr="Failed",
            return_code=1,
            command="mc admin group list",
        )

        result = await group_manager_instance.list_resources()

        assert result == []

    @pytest.mark.asyncio
    async def test_list_resources_with_filter(
        self, group_manager_instance, sample_group_list_json
    ):
        """Test list_resources applies filter correctly."""
        group_manager_instance._executor._execute_command.return_value = CommandResult(
            success=True,
            stdout=sample_group_list_json,
            stderr="",
            return_code=0,
            command="mc admin group list",
        )

        result = await group_manager_instance.list_resources(name_filter="test")

        assert "testgroup" in result
        assert "devteam" not in result

    @pytest.mark.asyncio
    async def test_delete_resource_not_exists(self, group_manager_instance):
        """Test delete_resource returns False when resource doesn't exist."""
        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=False)
        ):
            result = await group_manager_instance.delete_resource("nonexistent")

            assert result is False

    @pytest.mark.asyncio
    async def test_delete_resource_command_fails(
        self, group_manager_instance, mock_policy_manager
    ):
        """Test delete_resource returns False when command fails."""
        group_manager_instance._policy_manager = mock_policy_manager

        with patch.object(
            group_manager_instance, "resource_exists", AsyncMock(return_value=True)
        ):
            group_manager_instance._executor._execute_command.return_value = (
                CommandResult(
                    success=False,
                    stdout="",
                    stderr="Delete failed",
                    return_code=1,
                    command="mc admin group rm",
                )
            )

            result = await group_manager_instance.delete_resource("testgroup")

            assert result is False
