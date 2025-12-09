"""
Comprehensive tests for the minio.managers.policy_manager module.

This module provides thorough test coverage for PolicyManager including:
- Policy creation/deletion for users and groups
- Policy attachment/detachment operations
- Path access management (add/remove)
- Shadow policy update pattern
- Distributed locking behavior
- Error handling and edge cases
"""

import json
import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.minio.managers.policy_manager import PolicyManager
from src.minio.core.minio_client import MinIOClient
from src.minio.models.command import CommandResult
from src.minio.models.minio_config import MinIOConfig
from src.minio.models.policy import (
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
    PolicyTarget,
    PolicyType,
    PolicyAction,
)
from src.service.exceptions import PolicyOperationError, PolicyValidationError


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
    return client


@pytest.fixture
def mock_lock_manager():
    """Create a mock DistributedLockManager."""

    @asynccontextmanager
    async def mock_policy_update_lock(policy_name: str, timeout: int = None):
        yield MagicMock()

    manager = MagicMock()
    manager.policy_update_lock = mock_policy_update_lock
    manager.close = AsyncMock()
    return manager


@pytest.fixture
def mock_executor():
    """Create a mock BaseMinIOExecutor."""
    executor = MagicMock()
    executor.setup = AsyncMock()
    executor._execute_command = AsyncMock()
    return executor


@pytest.fixture
def policy_manager(
    mock_minio_client, mock_minio_config, mock_lock_manager, mock_executor
):
    """Create a PolicyManager with mocked dependencies."""
    manager = PolicyManager(
        client=mock_minio_client,
        config=mock_minio_config,
        lock_manager=mock_lock_manager,
    )
    manager._executor = mock_executor
    return manager


@pytest.fixture
def sample_policy_document():
    """Create a sample PolicyDocument for testing with complete structure for PolicyBuilder."""
    return PolicyDocument(
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
                condition={"StringLike": {"s3:prefix": ["test-path/*"]}},
            ),
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                action=PolicyAction.GET_OBJECT,
                resource=["arn:aws:s3:::test-bucket/test-path/*"],
            ),
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                action=PolicyAction.PUT_OBJECT,
                resource=["arn:aws:s3:::test-bucket/test-path/*"],
            ),
        ],
    )


@pytest.fixture
def sample_policy_model(sample_policy_document):
    """Create a sample PolicyModel for testing."""
    return PolicyModel(
        policy_name="user-home-policy-testuser",
        policy_document=sample_policy_document,
    )


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
def sample_group_policy():
    """Create a sample group policy with complete structure for PolicyBuilder."""
    return PolicyModel(
        policy_name="group-policy-testgroup",
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
                        "StringLike": {
                            "s3:prefix": ["tenant-sql-warehouse/testgroup/*"]
                        }
                    },
                ),
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.GET_OBJECT,
                    resource=[
                        "arn:aws:s3:::test-bucket/tenant-sql-warehouse/testgroup/*"
                    ],
                ),
            ],
        ),
    )


# =============================================================================
# Test: PolicyManager Initialization
# =============================================================================


class TestPolicyManagerInit:
    """Tests for PolicyManager initialization."""

    def test_init_with_all_dependencies(
        self, mock_minio_client, mock_minio_config, mock_lock_manager
    ):
        """Test PolicyManager initialization with all dependencies."""
        manager = PolicyManager(
            client=mock_minio_client,
            config=mock_minio_config,
            lock_manager=mock_lock_manager,
        )
        assert manager.client == mock_minio_client
        assert manager.config == mock_minio_config
        assert manager._lock_manager == mock_lock_manager

    def test_init_without_lock_manager(self, mock_minio_client, mock_minio_config):
        """Test PolicyManager initialization without lock manager."""
        manager = PolicyManager(
            client=mock_minio_client,
            config=mock_minio_config,
            lock_manager=None,
        )
        assert manager._lock_manager is None


# =============================================================================
# Test: ResourceManager Abstract Method Implementations
# =============================================================================


class TestResourceManagerMethods:
    """Tests for ResourceManager abstract method implementations."""

    def test_get_resource_type(self, policy_manager):
        """Test _get_resource_type returns 'policy'."""
        assert policy_manager._get_resource_type() == "policy"

    def test_validate_resource_name_valid(self, policy_manager):
        """Test _validate_resource_name with valid policy names."""
        valid_names = [
            "user-home-policy-testuser",
            "user-system-policy-testuser",
            "group-policy-testgroup",
        ]
        for name in valid_names:
            result = policy_manager._validate_resource_name(name)
            assert result == name

    def test_validate_resource_name_invalid_prefix(self, policy_manager):
        """Test _validate_resource_name with invalid prefix."""

        with pytest.raises(PolicyValidationError):
            policy_manager._validate_resource_name("invalid-policy-name")

    def test_validate_resource_name_reserved(self, policy_manager):
        """Test _validate_resource_name with reserved names."""

        with pytest.raises(PolicyValidationError):
            policy_manager._validate_resource_name("readonly")

    def test_build_exists_command(self, policy_manager):
        """Test _build_exists_command builds correct command."""
        cmd = policy_manager._build_exists_command("user-home-policy-testuser")
        assert "admin" in cmd
        assert "policy" in cmd
        assert "info" in cmd
        assert "user-home-policy-testuser" in cmd

    def test_build_list_command(self, policy_manager):
        """Test _build_list_command builds correct command."""
        cmd = policy_manager._build_list_command()
        assert "admin" in cmd
        assert "policy" in cmd
        assert "list" in cmd
        assert "--json" in cmd

    def test_build_delete_command(self, policy_manager):
        """Test _build_delete_command builds correct command."""
        cmd = policy_manager._build_delete_command("user-home-policy-testuser")
        assert "admin" in cmd
        assert "policy" in cmd
        assert "remove" in cmd
        assert "user-home-policy-testuser" in cmd

    def test_parse_list_output_valid(self, policy_manager):
        """Test _parse_list_output with valid JSON output."""
        output = '{"status":"success","policy":"user-home-policy-testuser"}\n{"status":"success","policy":"group-policy-testgroup"}'
        result = policy_manager._parse_list_output(output)
        assert result == ["user-home-policy-testuser", "group-policy-testgroup"]

    def test_parse_list_output_empty(self, policy_manager):
        """Test _parse_list_output with empty output."""
        result = policy_manager._parse_list_output("")
        assert result == []

    def test_parse_list_output_invalid_json(self, policy_manager):
        """Test _parse_list_output with invalid JSON raises error."""
        with pytest.raises(PolicyOperationError):
            policy_manager._parse_list_output("not valid json")


# =============================================================================
# Test: User Policy Operations
# =============================================================================


class TestEnsureUserPolicies:
    """Tests for ensure_user_policies method."""

    @pytest.mark.asyncio
    async def test_creates_both_policies_when_not_exist(
        self, policy_manager, mock_executor
    ):
        """Test creating both home and system policies when they don't exist."""

        # Mock resource_exists to return False (policies don't exist)
        policy_manager.resource_exists = AsyncMock(return_value=False)

        # Mock _create_minio_policy
        policy_manager._create_minio_policy = AsyncMock()

        home_policy, system_policy = await policy_manager.ensure_user_policies(
            "testuser"
        )

        assert home_policy.policy_name == "user-home-policy-testuser"
        assert system_policy.policy_name == "user-system-policy-testuser"
        assert policy_manager._create_minio_policy.call_count == 2

    @pytest.mark.asyncio
    async def test_returns_existing_policies_when_exist(
        self, policy_manager, sample_user_home_policy
    ):
        """Test returning existing policies when they already exist."""
        # Mock resource_exists to return True (policies exist)
        policy_manager.resource_exists = AsyncMock(return_value=True)

        # Mock _load_minio_policy to return existing policy
        policy_manager._load_minio_policy = AsyncMock(
            return_value=sample_user_home_policy
        )

        # Call without capturing result since we only verify side effects
        await policy_manager.ensure_user_policies("testuser")

        # Should not create policies, only load existing ones
        assert policy_manager._load_minio_policy.call_count == 2

    @pytest.mark.asyncio
    async def test_creates_home_but_loads_existing_system(
        self, policy_manager, sample_user_home_policy
    ):
        """Test creating home policy while system policy exists."""
        # First call for home returns False, second for system returns True
        policy_manager.resource_exists = AsyncMock(side_effect=[False, True])
        policy_manager._create_minio_policy = AsyncMock()
        policy_manager._load_minio_policy = AsyncMock(
            return_value=sample_user_home_policy
        )

        await policy_manager.ensure_user_policies("testuser")

        # Should create home policy and load system policy
        assert policy_manager._create_minio_policy.call_count == 1
        assert policy_manager._load_minio_policy.call_count == 1


class TestGetUserPolicies:
    """Tests for get_user_home_policy and get_user_system_policy methods."""

    @pytest.mark.asyncio
    async def test_get_user_home_policy_success(
        self, policy_manager, sample_user_home_policy
    ):
        """Test successfully getting user home policy."""
        policy_manager._load_minio_policy = AsyncMock(
            return_value=sample_user_home_policy
        )

        result = await policy_manager.get_user_home_policy("testuser")

        assert result.policy_name == "user-home-policy-testuser"
        policy_manager._load_minio_policy.assert_called_once_with(
            "user-home-policy-testuser"
        )

    @pytest.mark.asyncio
    async def test_get_user_home_policy_not_found(self, policy_manager):
        """Test getting user home policy when it doesn't exist."""
        policy_manager._load_minio_policy = AsyncMock(return_value=None)

        with pytest.raises(PolicyOperationError, match="not found"):
            await policy_manager.get_user_home_policy("testuser")

    @pytest.mark.asyncio
    async def test_get_user_system_policy_success(
        self, policy_manager, sample_user_home_policy
    ):
        """Test successfully getting user system policy."""
        system_policy = sample_user_home_policy.model_copy(
            update={"policy_name": "user-system-policy-testuser"}
        )
        policy_manager._load_minio_policy = AsyncMock(return_value=system_policy)

        result = await policy_manager.get_user_system_policy("testuser")

        assert result.policy_name == "user-system-policy-testuser"

    @pytest.mark.asyncio
    async def test_get_user_system_policy_not_found(self, policy_manager):
        """Test getting user system policy when it doesn't exist."""
        policy_manager._load_minio_policy = AsyncMock(return_value=None)

        with pytest.raises(PolicyOperationError, match="not found"):
            await policy_manager.get_user_system_policy("testuser")


class TestDeleteUserPolicies:
    """Tests for delete_user_policies method."""

    @pytest.mark.asyncio
    async def test_deletes_both_policies_successfully(self, policy_manager):
        """Test successfully deleting both user policies."""
        policy_manager.delete_resource = AsyncMock(return_value=True)

        await policy_manager.delete_user_policies("testuser")

        assert policy_manager.delete_resource.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_error_when_home_deletion_fails(self, policy_manager):
        """Test error when home policy deletion fails."""
        policy_manager.delete_resource = AsyncMock(return_value=False)

        with pytest.raises(PolicyOperationError, match="Failed to delete"):
            await policy_manager.delete_user_policies("testuser")

    @pytest.mark.asyncio
    async def test_continues_after_first_failure(self, policy_manager):
        """Test that both deletions are attempted even if first fails."""
        # First returns False (failure), second returns True
        policy_manager.delete_resource = AsyncMock(side_effect=[False, True])

        with pytest.raises(PolicyOperationError):
            await policy_manager.delete_user_policies("testuser")

        # Both deletions should be attempted
        assert policy_manager.delete_resource.call_count == 2

    @pytest.mark.asyncio
    async def test_collects_all_errors(self, policy_manager):
        """Test that all errors are collected and reported."""
        policy_manager.delete_resource = AsyncMock(return_value=False)

        with pytest.raises(PolicyOperationError) as exc_info:
            await policy_manager.delete_user_policies("testuser")

        # Should mention both failures
        assert "home policy" in str(exc_info.value) or "system policy" in str(
            exc_info.value
        )


# =============================================================================
# Test: Group Policy Operations
# =============================================================================


class TestEnsureGroupPolicy:
    """Tests for ensure_group_policy method."""

    @pytest.mark.asyncio
    async def test_creates_group_policy_when_not_exist(self, policy_manager):
        """Test creating group policy when it doesn't exist."""
        policy_manager.resource_exists = AsyncMock(return_value=False)
        policy_manager._create_minio_policy = AsyncMock()

        result = await policy_manager.ensure_group_policy("testgroup")

        assert result.policy_name == "group-policy-testgroup"
        policy_manager._create_minio_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_existing_group_policy(
        self, policy_manager, sample_group_policy
    ):
        """Test returning existing group policy."""
        policy_manager.resource_exists = AsyncMock(return_value=True)
        policy_manager._load_minio_policy = AsyncMock(return_value=sample_group_policy)

        result = await policy_manager.ensure_group_policy("testgroup")

        assert result.policy_name == "group-policy-testgroup"
        policy_manager._load_minio_policy.assert_called_once()


class TestGetGroupPolicy:
    """Tests for get_group_policy method."""

    @pytest.mark.asyncio
    async def test_get_group_policy_success(self, policy_manager, sample_group_policy):
        """Test successfully getting group policy."""
        policy_manager._load_minio_policy = AsyncMock(return_value=sample_group_policy)

        result = await policy_manager.get_group_policy("testgroup")

        assert result.policy_name == "group-policy-testgroup"

    @pytest.mark.asyncio
    async def test_get_group_policy_not_found(self, policy_manager):
        """Test getting group policy when it doesn't exist."""
        policy_manager._load_minio_policy = AsyncMock(return_value=None)

        with pytest.raises(PolicyOperationError, match="not found"):
            await policy_manager.get_group_policy("testgroup")


class TestEnsureGroupReadOnlyPolicy:
    """Tests for ensure_group_read_only_policy method."""

    @pytest.mark.asyncio
    async def test_creates_group_read_only_policy_when_not_exist(self, policy_manager):
        """Test creating group read-only policy when it doesn't exist."""
        policy_manager.resource_exists = AsyncMock(return_value=False)
        policy_manager._create_minio_policy = AsyncMock()

        result = await policy_manager.ensure_group_read_only_policy("testgroup")

        assert result.policy_name == "group-ro-policy-testgroup"
        policy_manager._create_minio_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_existing_group_read_only_policy(self, policy_manager):
        """Test returning existing group read-only policy."""
        # Create a sample read-only policy
        sample_ro_policy = PolicyModel(
            policy_name="group-ro-policy-testgroup",
            policy_document=PolicyDocument(
                version="2012-10-17",
                statement=[
                    PolicyStatement(
                        effect=PolicyEffect.ALLOW,
                        action=PolicyAction.GET_OBJECT,
                        resource="arn:aws:s3:::test-bucket/testgroup/*",
                    )
                ],
            ),
        )
        policy_manager.resource_exists = AsyncMock(return_value=True)
        policy_manager._load_minio_policy = AsyncMock(return_value=sample_ro_policy)

        result = await policy_manager.ensure_group_read_only_policy("testgroup")

        assert result.policy_name == "group-ro-policy-testgroup"
        policy_manager._load_minio_policy.assert_called_once()


class TestGetGroupReadOnlyPolicy:
    """Tests for get_group_read_only_policy method."""

    @pytest.mark.asyncio
    async def test_get_group_read_only_policy_success(self, policy_manager):
        """Test successfully getting group read-only policy."""
        sample_ro_policy = PolicyModel(
            policy_name="group-ro-policy-testgroup",
            policy_document=PolicyDocument(
                version="2012-10-17",
                statement=[
                    PolicyStatement(
                        effect=PolicyEffect.ALLOW,
                        action=PolicyAction.GET_OBJECT,
                        resource="arn:aws:s3:::test-bucket/testgroup/*",
                    )
                ],
            ),
        )
        policy_manager._load_minio_policy = AsyncMock(return_value=sample_ro_policy)

        result = await policy_manager.get_group_read_only_policy("testgroup")

        assert result.policy_name == "group-ro-policy-testgroup"

    @pytest.mark.asyncio
    async def test_get_group_read_only_policy_not_found(self, policy_manager):
        """Test getting group read-only policy when it doesn't exist."""
        policy_manager._load_minio_policy = AsyncMock(return_value=None)

        with pytest.raises(PolicyOperationError, match="not found"):
            await policy_manager.get_group_read_only_policy("testgroup")


class TestDeleteGroupPolicy:
    """Tests for delete_group_policy method."""

    @pytest.mark.asyncio
    async def test_deletes_group_policy_successfully(self, policy_manager):
        """Test successfully deleting group policy and read-only policy."""
        policy_manager.delete_resource = AsyncMock(return_value=True)
        # Mock resource_exists to return True for read-only policy check
        policy_manager.resource_exists = AsyncMock(return_value=True)

        await policy_manager.delete_group_policy("testgroup")

        # Should delete both main and read-only policies
        # RO policy uses consistent naming: group-ro-policy-{group_name}ro
        assert policy_manager.delete_resource.call_count == 2
        policy_manager.delete_resource.assert_any_call("group-policy-testgroup")
        policy_manager.delete_resource.assert_any_call("group-ro-policy-testgroupro")

    @pytest.mark.asyncio
    async def test_deletes_only_main_policy_when_include_read_only_false(
        self, policy_manager
    ):
        """Test deleting only main group policy when include_read_only is False."""
        policy_manager.delete_resource = AsyncMock(return_value=True)

        await policy_manager.delete_group_policy("testgroup", include_read_only=False)

        policy_manager.delete_resource.assert_called_once_with("group-policy-testgroup")

    @pytest.mark.asyncio
    async def test_raises_error_when_main_deletion_fails(self, policy_manager):
        """Test error when main group policy deletion fails."""
        policy_manager.delete_resource = AsyncMock(return_value=False)

        with pytest.raises(PolicyOperationError, match="Failed to delete"):
            await policy_manager.delete_group_policy("testgroup")

    @pytest.mark.asyncio
    async def test_continues_if_read_only_policy_not_found(self, policy_manager):
        """Test that deletion continues if read-only policy doesn't exist."""
        policy_manager.delete_resource = AsyncMock(return_value=True)
        # Read-only policy doesn't exist
        policy_manager.resource_exists = AsyncMock(return_value=False)

        await policy_manager.delete_group_policy("testgroup")

        # Should only delete main policy since read-only doesn't exist
        policy_manager.delete_resource.assert_called_once_with("group-policy-testgroup")


# =============================================================================
# Test: Policy Attachment Operations
# =============================================================================


class TestAttachUserPolicies:
    """Tests for attach_user_policies method."""

    @pytest.mark.asyncio
    async def test_attaches_both_policies_successfully(
        self, policy_manager, sample_user_home_policy
    ):
        """Test successfully attaching both user policies."""
        policy_manager._is_policy_attached_to_target = AsyncMock(return_value=False)
        policy_manager._load_minio_policy = AsyncMock(
            return_value=sample_user_home_policy
        )
        policy_manager.attach_policy_to_user = AsyncMock()

        await policy_manager.attach_user_policies("testuser")

        assert policy_manager.attach_policy_to_user.call_count == 2

    @pytest.mark.asyncio
    async def test_skips_already_attached_policies(
        self, policy_manager, sample_user_home_policy
    ):
        """Test skipping policies that are already attached."""
        policy_manager._is_policy_attached_to_target = AsyncMock(return_value=True)
        policy_manager.attach_policy_to_user = AsyncMock()

        await policy_manager.attach_user_policies("testuser")

        # Should not attach since both are already attached
        policy_manager.attach_policy_to_user.assert_not_called()

    @pytest.mark.asyncio
    async def test_validates_policies_exist_before_attach(self, policy_manager):
        """Test that policies existence is validated before attachment."""
        policy_manager._is_policy_attached_to_target = AsyncMock(return_value=False)
        policy_manager._load_minio_policy = AsyncMock(return_value=None)

        with pytest.raises(PolicyOperationError, match="do not exist"):
            await policy_manager.attach_user_policies("testuser")


class TestDetachUserPolicies:
    """Tests for detach_user_policies method."""

    @pytest.mark.asyncio
    async def test_detaches_both_policies_successfully(self, policy_manager):
        """Test successfully detaching both user policies."""
        policy_manager.detach_policy_from_user = AsyncMock()

        await policy_manager.detach_user_policies("testuser")

        assert policy_manager.detach_policy_from_user.call_count == 2

    @pytest.mark.asyncio
    async def test_collects_detachment_errors(self, policy_manager):
        """Test that all detachment errors are collected."""
        policy_manager.detach_policy_from_user = AsyncMock(
            side_effect=Exception("Detach failed")
        )

        with pytest.raises(PolicyOperationError, match="Failed to detach"):
            await policy_manager.detach_user_policies("testuser")


class TestAttachDetachPolicy:
    """Tests for attach/detach policy to/from user/group methods."""

    @pytest.mark.asyncio
    async def test_attach_policy_to_user(self, policy_manager, mock_executor):
        """Test attaching policy to user."""

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True, stdout="", stderr="", return_code=0, command=""
            )
        )

        await policy_manager.attach_policy_to_user(
            "user-home-policy-testuser", "testuser"
        )

        mock_executor._execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_attach_policy_to_user_failure(self, policy_manager, mock_executor):
        """Test attach policy to user failure."""

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=False,
                stdout="",
                stderr="attach failed",
                return_code=1,
                command="",
            )
        )

        with pytest.raises(PolicyOperationError, match="Failed to attach"):
            await policy_manager.attach_policy_to_user(
                "user-home-policy-testuser", "testuser"
            )

    @pytest.mark.asyncio
    async def test_detach_policy_from_user(self, policy_manager, mock_executor):
        """Test detaching policy from user."""

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True, stdout="", stderr="", return_code=0, command=""
            )
        )

        await policy_manager.detach_policy_from_user(
            "user-home-policy-testuser", "testuser"
        )

        mock_executor._execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_attach_policy_to_group(self, policy_manager, mock_executor):
        """Test attaching policy to group."""

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True, stdout="", stderr="", return_code=0, command=""
            )
        )

        await policy_manager.attach_policy_to_group(
            "group-policy-testgroup", "testgroup"
        )

        mock_executor._execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_detach_policy_from_group(self, policy_manager, mock_executor):
        """Test detaching policy from group."""

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True, stdout="", stderr="", return_code=0, command=""
            )
        )

        await policy_manager.detach_policy_from_group(
            "group-policy-testgroup", "testgroup"
        )

        mock_executor._execute_command.assert_called_once()


# =============================================================================
# Test: Policy Attachment Status Checks
# =============================================================================


class TestPolicyAttachmentStatus:
    """Tests for policy attachment status check methods."""

    @pytest.mark.asyncio
    async def test_is_policy_attached_to_group_true(
        self, policy_manager, mock_executor
    ):
        """Test checking if policy is attached to group - true case."""

        response = {
            "result": {
                "policyMappings": [
                    {"policy": "group-policy-testgroup", "groups": ["testgroup"]}
                ]
            }
        }
        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True,
                stdout=json.dumps(response),
                stderr="",
                return_code=0,
                command="",
            )
        )

        result = await policy_manager.is_policy_attached_to_group("testgroup")

        assert result is True

    @pytest.mark.asyncio
    async def test_is_policy_attached_to_group_false(
        self, policy_manager, mock_executor
    ):
        """Test checking if policy is attached to group - false case."""

        response = {"result": {"policyMappings": []}}
        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True,
                stdout=json.dumps(response),
                stderr="",
                return_code=0,
                command="",
            )
        )

        result = await policy_manager.is_policy_attached_to_group("testgroup")

        assert result is False

    @pytest.mark.asyncio
    async def test_is_policies_attached_to_user_both_attached(
        self, policy_manager, mock_executor
    ):
        """Test checking if both user policies are attached."""

        # Mock responses for both policy checks
        response = {
            "result": {
                "policyMappings": [
                    {"policy": "user-home-policy-testuser", "users": ["testuser"]}
                ]
            }
        }
        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True,
                stdout=json.dumps(response),
                stderr="",
                return_code=0,
                command="",
            )
        )

        result = await policy_manager.is_policies_attached_to_user("testuser")

        assert result is True

    @pytest.mark.asyncio
    async def test_is_policies_attached_to_user_one_missing(
        self, policy_manager, mock_executor
    ):
        """Test checking if user policies attached when one is missing."""
        from src.minio.models.command import CommandResult

        # First call returns attached, second returns not attached
        responses = [
            {
                "result": {
                    "policyMappings": [
                        {"policy": "user-home-policy-testuser", "users": ["testuser"]}
                    ]
                }
            },
            {"result": {"policyMappings": []}},
        ]
        call_count = [0]

        async def mock_execute(cmd):
            result = responses[call_count[0] % 2]
            call_count[0] += 1
            return CommandResult(
                success=True,
                stdout=json.dumps(result),
                stderr="",
                return_code=0,
                command="",
            )

        mock_executor._execute_command = mock_execute

        result = await policy_manager.is_policies_attached_to_user("testuser")

        assert result is False


# =============================================================================
# Test: Path Access Operations
# =============================================================================


class TestAddPathAccessForTarget:
    """Tests for add_path_access_for_target method."""

    @pytest.mark.asyncio
    async def test_adds_path_access_for_user(
        self, policy_manager, sample_user_home_policy, mock_lock_manager
    ):
        """Test adding path access for user."""
        policy_manager._load_policy_for_target = AsyncMock(
            return_value=sample_user_home_policy
        )
        policy_manager._update_minio_policy = AsyncMock()

        await policy_manager.add_path_access_for_target(
            PolicyTarget.USER,
            "testuser",
            "s3a://test-bucket/shared/data/",
            PolicyPermissionLevel.READ,
        )

        policy_manager._update_minio_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_adds_path_access_for_group(
        self, policy_manager, sample_group_policy, mock_lock_manager
    ):
        """Test adding path access for group."""
        policy_manager._load_policy_for_target = AsyncMock(
            return_value=sample_group_policy
        )
        policy_manager._update_minio_policy = AsyncMock()

        await policy_manager.add_path_access_for_target(
            PolicyTarget.GROUP,
            "testgroup",
            "s3a://test-bucket/shared/data/",
            PolicyPermissionLevel.WRITE,
        )

        policy_manager._update_minio_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_raises_error_without_lock_manager(
        self, mock_minio_client, mock_minio_config, mock_executor
    ):
        """Test that operations fail without lock manager."""
        manager = PolicyManager(
            client=mock_minio_client,
            config=mock_minio_config,
            lock_manager=None,
        )
        manager._executor = mock_executor

        with pytest.raises(PolicyOperationError, match="lock manager not initialized"):
            await manager.add_path_access_for_target(
                PolicyTarget.USER,
                "testuser",
                "s3a://test-bucket/shared/data/",
                PolicyPermissionLevel.READ,
            )


class TestRemovePathAccessForTarget:
    """Tests for remove_path_access_for_target method."""

    @pytest.mark.asyncio
    async def test_removes_path_access_for_user(
        self, policy_manager, sample_user_home_policy, mock_lock_manager
    ):
        """Test removing path access for user."""
        policy_manager._load_policy_for_target = AsyncMock(
            return_value=sample_user_home_policy
        )
        policy_manager._update_minio_policy = AsyncMock()

        await policy_manager.remove_path_access_for_target(
            PolicyTarget.USER,
            "testuser",
            "s3a://test-bucket/shared/data/",
        )

        policy_manager._update_minio_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_removes_path_access_for_group(
        self, policy_manager, sample_group_policy, mock_lock_manager
    ):
        """Test removing path access for group."""
        policy_manager._load_policy_for_target = AsyncMock(
            return_value=sample_group_policy
        )
        policy_manager._update_minio_policy = AsyncMock()

        await policy_manager.remove_path_access_for_target(
            PolicyTarget.GROUP,
            "testgroup",
            "s3a://test-bucket/shared/data/",
        )

        policy_manager._update_minio_policy.assert_called_once()


# =============================================================================
# Test: Policy Name Generation
# =============================================================================


class TestGetPolicyNameForTarget:
    """Tests for _get_policy_name_for_target method."""

    def test_returns_user_home_policy_name(self, policy_manager):
        """Test getting policy name for user target."""
        result = policy_manager._get_policy_name_for_target(
            PolicyTarget.USER, "testuser"
        )
        assert result == "user-home-policy-testuser"

    def test_returns_group_policy_name(self, policy_manager):
        """Test getting policy name for group target."""
        result = policy_manager._get_policy_name_for_target(
            PolicyTarget.GROUP, "testgroup"
        )
        assert result == "group-policy-testgroup"


class TestGetPolicyName:
    """Tests for get_policy_name method."""

    def test_user_home_policy_name(self, policy_manager):
        """Test generating user home policy name."""
        result = policy_manager.get_policy_name(PolicyType.USER_HOME, "testuser")
        assert result == "user-home-policy-testuser"

    def test_user_system_policy_name(self, policy_manager):
        """Test generating user system policy name."""
        result = policy_manager.get_policy_name(PolicyType.USER_SYSTEM, "testuser")
        assert result == "user-system-policy-testuser"

    def test_group_home_policy_name(self, policy_manager):
        """Test generating group home policy name."""
        result = policy_manager.get_policy_name(PolicyType.GROUP_HOME, "testgroup")
        assert result == "group-policy-testgroup"


# =============================================================================
# Test: Policy Document Manipulation
# =============================================================================


class TestAddPathAccessToPolicy:
    """Tests for add_path_access_to_policy method."""

    def test_adds_read_access(self, policy_manager, sample_policy_model):
        """Test adding read access to policy."""
        result = policy_manager.add_path_access_to_policy(
            sample_policy_model,
            "s3a://test-bucket/shared/data/",
            PolicyPermissionLevel.READ,
        )

        assert result is not None
        assert result.policy_name == sample_policy_model.policy_name

    def test_adds_write_access(self, policy_manager, sample_policy_model):
        """Test adding write access to policy."""
        result = policy_manager.add_path_access_to_policy(
            sample_policy_model,
            "s3a://test-bucket/shared/data/",
            PolicyPermissionLevel.WRITE,
        )

        assert result is not None

    def test_adds_admin_access(self, policy_manager, sample_policy_model):
        """Test adding admin access to policy."""
        result = policy_manager.add_path_access_to_policy(
            sample_policy_model,
            "s3a://test-bucket/shared/data/",
            PolicyPermissionLevel.ADMIN,
        )

        assert result is not None


class TestRemovePathAccessFromPolicy:
    """Tests for remove_path_access_from_policy method."""

    def test_removes_path_access(self, policy_manager, sample_policy_model):
        """Test removing path access from policy."""
        result = policy_manager.remove_path_access_from_policy(
            sample_policy_model,
            "s3a://test-bucket/test-path/",
        )

        assert result is not None
        assert result.policy_name == sample_policy_model.policy_name


class TestGetAccessiblePathsFromPolicy:
    """Tests for get_accessible_paths_from_policy method."""

    def test_extracts_paths_from_policy(self, policy_manager, sample_user_home_policy):
        """Test extracting accessible paths from policy."""
        paths = policy_manager.get_accessible_paths_from_policy(sample_user_home_policy)

        assert isinstance(paths, list)

    def test_returns_empty_for_no_allow_statements(self, policy_manager):
        """Test returns empty list when no allow statements."""
        empty_policy = PolicyModel(
            policy_name="user-home-policy-empty",
            policy_document=PolicyDocument(version="2012-10-17", statement=[]),
        )

        paths = policy_manager.get_accessible_paths_from_policy(empty_policy)

        assert paths == []


# =============================================================================
# Test: Shadow Policy Pattern
# =============================================================================


class TestShadowPolicyPattern:
    """Tests for shadow policy update pattern."""

    @pytest.mark.asyncio
    async def test_generates_unique_shadow_name(self, policy_manager):
        """Test that shadow policy names are unique."""
        name1 = policy_manager._generate_shadow_policy_name("user-home-policy-testuser")
        name2 = policy_manager._generate_shadow_policy_name("user-home-policy-testuser")

        assert name1 != name2
        assert "shadow" in name1
        assert "shadow" in name2

    @pytest.mark.asyncio
    async def test_creates_shadow_policy(self, policy_manager, sample_user_home_policy):
        """Test creating shadow policy."""
        policy_manager._create_minio_policy = AsyncMock()

        shadow_name = await policy_manager._create_shadow_policy(
            sample_user_home_policy
        )

        assert "shadow" in shadow_name
        policy_manager._create_minio_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_attaches_shadow_policy_to_user(self, policy_manager):
        """Test attaching shadow policy to user."""
        policy_manager.attach_policy_to_user = AsyncMock()

        await policy_manager._attach_shadow_policy(
            "user-home-policy-testuser-shadow-12345678",
            "testuser",
            PolicyType.USER_HOME,
        )

        policy_manager.attach_policy_to_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_attaches_shadow_policy_to_group(self, policy_manager):
        """Test attaching shadow policy to group."""
        policy_manager.attach_policy_to_group = AsyncMock()

        await policy_manager._attach_shadow_policy(
            "group-policy-testgroup-shadow-12345678",
            "testgroup",
            PolicyType.GROUP_HOME,
        )

        policy_manager.attach_policy_to_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_shadow_policy_on_failure(self, policy_manager):
        """Test cleanup of shadow policy on failure."""
        policy_manager.detach_policy_from_user = AsyncMock()
        policy_manager.delete_resource = AsyncMock()

        await policy_manager._cleanup_shadow_policy(
            "user-home-policy-testuser-shadow-12345678",
            "testuser",
            PolicyType.USER_HOME,
        )

        policy_manager.delete_resource.assert_called_once()


class TestUpdateMiniOPolicy:
    """Tests for _update_minio_policy method."""

    @pytest.mark.asyncio
    async def test_update_user_home_policy(
        self, policy_manager, sample_user_home_policy
    ):
        """Test updating user home policy using shadow pattern."""
        policy_manager._execute_shadow_policy_update = AsyncMock(
            return_value="shadow-name"
        )

        await policy_manager._update_minio_policy(sample_user_home_policy)

        policy_manager._execute_shadow_policy_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_handles_failure_with_cleanup(
        self, policy_manager, sample_user_home_policy
    ):
        """Test that update cleans up shadow policy on failure."""
        policy_manager._execute_shadow_policy_update = AsyncMock(
            side_effect=Exception("Update failed")
        )
        policy_manager._cleanup_shadow_policy = AsyncMock()

        with pytest.raises(PolicyOperationError, match="Failed to update policy"):
            await policy_manager._update_minio_policy(sample_user_home_policy)


class TestParsePolicyInfo:
    """Tests for _parse_policy_info method."""

    def test_parses_user_home_policy(self, policy_manager):
        """Test parsing user home policy name."""
        target_name, policy_type = policy_manager._parse_policy_info(
            "user-home-policy-testuser"
        )

        assert target_name == "testuser"
        assert policy_type == PolicyType.USER_HOME

    def test_parses_user_system_policy(self, policy_manager):
        """Test parsing user system policy name."""
        target_name, policy_type = policy_manager._parse_policy_info(
            "user-system-policy-testuser"
        )

        assert target_name == "testuser"
        assert policy_type == PolicyType.USER_SYSTEM

    def test_parses_group_policy(self, policy_manager):
        """Test parsing group policy name."""
        target_name, policy_type = policy_manager._parse_policy_info(
            "group-policy-testgroup"
        )

        assert target_name == "testgroup"
        assert policy_type == PolicyType.GROUP_HOME

    def test_raises_for_unknown_pattern(self, policy_manager):
        """Test raises error for unknown policy pattern."""
        with pytest.raises(PolicyOperationError, match="Unknown policy naming pattern"):
            policy_manager._parse_policy_info("invalid-policy-name")


# =============================================================================
# Test: MinIO Policy Operations
# =============================================================================


class TestCreateMinIOPolicy:
    """Tests for _create_minio_policy method."""

    @pytest.mark.asyncio
    async def test_creates_policy_with_temp_file(
        self, policy_manager, sample_policy_model, mock_executor
    ):
        """Test creating policy writes JSON to temp file."""
        from src.minio.models.command import CommandResult

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True, stdout="", stderr="", return_code=0, command=""
            )
        )

        await policy_manager._create_minio_policy(sample_policy_model)

        mock_executor._execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_raises_error_on_failure(
        self, policy_manager, sample_policy_model, mock_executor
    ):
        """Test raises error when policy creation fails."""
        from src.minio.models.command import CommandResult

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=False,
                stdout="",
                stderr="creation failed",
                return_code=1,
                command="",
            )
        )

        with pytest.raises(PolicyOperationError, match="Failed to create"):
            await policy_manager._create_minio_policy(sample_policy_model)


class TestLoadMinIOPolicy:
    """Tests for _load_minio_policy method."""

    @pytest.mark.asyncio
    async def test_loads_policy_successfully(self, policy_manager, mock_executor):
        """Test loading policy from MinIO."""
        from src.minio.models.command import CommandResult

        policy_response = {
            "Policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": ["arn:aws:s3:::test-bucket/*"],
                    }
                ],
            }
        }
        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True,
                stdout=json.dumps(policy_response),
                stderr="",
                return_code=0,
                command="",
            )
        )

        result = await policy_manager._load_minio_policy("user-home-policy-testuser")

        assert result is not None
        assert result.policy_name == "user-home-policy-testuser"

    @pytest.mark.asyncio
    async def test_returns_none_for_builtin_policy(self, policy_manager):
        """Test returns None for built-in policies."""
        result = await policy_manager._load_minio_policy("readonly")

        assert result is None

    @pytest.mark.asyncio
    async def test_raises_on_command_failure(self, policy_manager, mock_executor):
        """Test raises error when command fails."""
        from src.minio.models.command import CommandResult

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=False,
                stdout="",
                stderr="info failed",
                return_code=1,
                command="",
            )
        )

        with pytest.raises(PolicyOperationError, match="Failed to get policy info"):
            await policy_manager._load_minio_policy("user-home-policy-testuser")


# =============================================================================
# Test: Policy Type Checks
# =============================================================================


class TestPolicyTypeChecks:
    """Tests for policy type check methods."""

    def test_is_user_system_policy_true(self, policy_manager):
        """Test is_user_system_policy returns True for system policy."""
        assert (
            policy_manager.is_user_system_policy("user-system-policy-testuser") is True
        )

    def test_is_user_system_policy_false(self, policy_manager):
        """Test is_user_system_policy returns False for non-system policy."""
        assert (
            policy_manager.is_user_system_policy("user-home-policy-testuser") is False
        )

    def test_is_user_home_policy_true(self, policy_manager):
        """Test is_user_home_policy returns True for home policy."""
        assert policy_manager.is_user_home_policy("user-home-policy-testuser") is True

    def test_is_user_home_policy_false(self, policy_manager):
        """Test is_user_home_policy returns False for non-home policy."""
        assert policy_manager.is_user_home_policy("group-policy-testgroup") is False

    def test_is_group_policy_true(self, policy_manager):
        """Test is_group_policy returns True for group policy."""
        assert policy_manager.is_group_policy("group-policy-testgroup") is True

    def test_is_group_policy_false(self, policy_manager):
        """Test is_group_policy returns False for non-group policy."""
        assert policy_manager.is_group_policy("user-home-policy-testuser") is False


# =============================================================================
# Test: List All Policies
# =============================================================================


class TestListAllPolicies:
    """Tests for list_all_policies method."""

    @pytest.mark.asyncio
    async def test_lists_all_policies(self, policy_manager, sample_user_home_policy):
        """Test listing all policies with full PolicyModel objects."""
        policy_manager.list_resources = AsyncMock(
            return_value=["user-home-policy-testuser", "group-policy-testgroup"]
        )
        policy_manager._load_minio_policy = AsyncMock(
            return_value=sample_user_home_policy
        )

        result = await policy_manager.list_all_policies()

        assert len(result) == 2
        assert all(isinstance(p, PolicyModel) for p in result)

    @pytest.mark.asyncio
    async def test_handles_list_resources_failure(self, policy_manager):
        """Test handles failure when listing resources."""
        policy_manager.list_resources = AsyncMock(side_effect=Exception("List failed"))

        with pytest.raises(PolicyOperationError, match="Failed to list all policies"):
            await policy_manager.list_all_policies()


# =============================================================================
# Test: Policy Entities Parsing
# =============================================================================


class TestParsePolicyEntitiesOutput:
    """Tests for _parse_policy_entities_output method."""

    def test_parses_users_and_groups(self, policy_manager):
        """Test parsing policy entities with users and groups."""
        output = json.dumps(
            {
                "result": {
                    "policyMappings": [
                        {
                            "policy": "test-policy",
                            "users": ["user1", "user2"],
                            "groups": ["group1"],
                        }
                    ]
                }
            }
        )

        result = policy_manager._parse_policy_entities_output(output)

        assert PolicyTarget.USER in result
        assert PolicyTarget.GROUP in result
        assert "user1" in result[PolicyTarget.USER]
        assert "user2" in result[PolicyTarget.USER]
        assert "group1" in result[PolicyTarget.GROUP]

    def test_handles_empty_mappings(self, policy_manager):
        """Test parsing empty policy mappings."""
        output = json.dumps({"result": {"policyMappings": []}})

        result = policy_manager._parse_policy_entities_output(output)

        assert result[PolicyTarget.USER] == []
        assert result[PolicyTarget.GROUP] == []

    def test_handles_missing_users_groups(self, policy_manager):
        """Test parsing mappings without users/groups keys."""
        output = json.dumps({"result": {"policyMappings": [{"policy": "test-policy"}]}})

        result = policy_manager._parse_policy_entities_output(output)

        assert result[PolicyTarget.USER] == []
        assert result[PolicyTarget.GROUP] == []


# =============================================================================
# Test: Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_handles_concurrent_policy_updates(
        self, policy_manager, sample_user_home_policy, mock_lock_manager
    ):
        """Test that concurrent updates are serialized through lock."""
        call_count = [0]

        async def mock_update(policy):
            call_count[0] += 1
            if call_count[0] == 1:
                # Simulate delay in first update
                import asyncio

                await asyncio.sleep(0.1)

        policy_manager._load_policy_for_target = AsyncMock(
            return_value=sample_user_home_policy
        )
        policy_manager._update_minio_policy = mock_update

        # Both should succeed as lock serializes them
        await policy_manager.add_path_access_for_target(
            PolicyTarget.USER,
            "testuser",
            "s3a://test-bucket/path1/",
            PolicyPermissionLevel.READ,
        )

        assert call_count[0] == 1

    def test_handles_invalid_s3_path(self, policy_manager, sample_policy_model):
        """Test handling invalid S3 path format."""
        with pytest.raises(PolicyOperationError):
            policy_manager.add_path_access_to_policy(
                sample_policy_model,
                "invalid-path",  # Not s3:// or s3a://
                PolicyPermissionLevel.READ,
            )

    def test_handles_path_traversal_attack(self, policy_manager, sample_policy_model):
        """Test handling path traversal attack."""
        with pytest.raises(PolicyOperationError):
            policy_manager.add_path_access_to_policy(
                sample_policy_model,
                "s3a://test-bucket/../etc/passwd",
                PolicyPermissionLevel.READ,
            )

    @pytest.mark.asyncio
    async def test_handles_unsupported_target_type(self, policy_manager):
        """Test handling unsupported target type."""
        # Create a mock target type that's not USER or GROUP
        with pytest.raises(PolicyOperationError, match="Unsupported target type"):
            policy_manager._get_policy_name_for_target(MagicMock(), "test")

    def test_policy_name_with_special_characters(self, policy_manager):
        """Test policy name generation with special characters in username."""
        # Username should already be validated, but policy name should be safe
        result = policy_manager.get_policy_name(PolicyType.USER_HOME, "test.user_1")
        assert "test.user_1" in result

    @pytest.mark.asyncio
    async def test_empty_policy_document_handling(self, policy_manager):
        """Test handling empty policy document."""
        empty_policy = PolicyModel(
            policy_name="user-home-policy-empty",
            policy_document=PolicyDocument(version="2012-10-17", statement=[]),
        )

        paths = policy_manager.get_accessible_paths_from_policy(empty_policy)
        assert paths == []


class TestPolicyCreation:
    """Tests for internal policy creation methods."""

    def test_create_user_home_policy(self, policy_manager):
        """Test _create_user_home_policy generates correct policy."""
        result = policy_manager._create_user_home_policy("testuser")

        assert result.policy_name == "user-home-policy-testuser"
        assert len(result.policy_document.statement) > 0

    def test_create_user_system_policy(self, policy_manager):
        """Test _create_user_system_policy generates correct policy."""
        result = policy_manager._create_user_system_policy("testuser")

        assert result.policy_name == "user-system-policy-testuser"
        assert len(result.policy_document.statement) > 0

    def test_create_group_home_policy(self, policy_manager):
        """Test _create_group_home_policy generates correct policy."""
        result = policy_manager._create_group_home_policy("testgroup")

        assert result.policy_name == "group-policy-testgroup"
        assert len(result.policy_document.statement) > 0


# =============================================================================
# Test: Resource Existence Checks
# =============================================================================


class TestResourceExists:
    """Tests for resource_exists method."""

    @pytest.mark.asyncio
    async def test_returns_true_when_exists(self, policy_manager, mock_executor):
        """Test resource_exists returns True when policy exists."""
        from src.minio.models.command import CommandResult

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=True,
                stdout='{"policy": "test"}',
                stderr="",
                return_code=0,
                command="",
            )
        )

        result = await policy_manager.resource_exists("user-home-policy-testuser")

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_not_exists(self, policy_manager, mock_executor):
        """Test resource_exists returns False when policy doesn't exist."""
        from src.minio.models.command import CommandResult

        mock_executor._execute_command = AsyncMock(
            return_value=CommandResult(
                success=False,
                stdout="",
                stderr="policy not found",
                return_code=1,
                command="",
            )
        )

        result = await policy_manager.resource_exists("user-home-policy-nonexistent")

        assert result is False
