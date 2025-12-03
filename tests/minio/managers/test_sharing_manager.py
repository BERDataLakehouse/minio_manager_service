"""
Comprehensive tests for the minio.managers.sharing_manager module.

Tests cover:
- SharingResult and UnsharingResult dataclasses
- SharingManager initialization
- share_path workflow
- unshare_path workflow
- make_public and make_private operations
- get_path_access_info
- Helper methods and validation
- Error handling and edge cases
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.minio.managers.sharing_manager import (
    PathAccessInfo,
    SharingManager,
    SharingOperation,
    SharingResult,
    UnsharingResult,
)
from src.minio.models.policy import PolicyPermissionLevel, PolicyTarget
from src.service.exceptions import DataGovernanceError, PolicyValidationError


# === FIXTURES ===


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Ensure MC_PATH is set for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


@pytest.fixture
def mock_client():
    """Create a mock MinIO client."""
    return MagicMock()


@pytest.fixture
def mock_config():
    """Create a mock MinIO configuration."""
    config = MagicMock()
    config.default_bucket = "test-bucket"
    return config


@pytest.fixture
def mock_policy_manager():
    """Create a mock PolicyManager."""
    pm = AsyncMock()
    pm.add_path_access_for_target = AsyncMock()
    pm.remove_path_access_for_target = AsyncMock()
    pm.list_resources = AsyncMock(return_value=[])
    pm._load_minio_policy = AsyncMock(return_value=None)
    pm.get_accessible_paths_from_policy = MagicMock(return_value=[])
    pm.is_user_home_policy = MagicMock(return_value=False)
    pm.is_group_policy = MagicMock(return_value=False)
    return pm


@pytest.fixture
def mock_user_manager():
    """Create a mock UserManager."""
    um = AsyncMock()
    um.can_user_share_path = AsyncMock(return_value=True)
    return um


@pytest.fixture
def mock_group_manager():
    """Create a mock GroupManager."""
    return AsyncMock()


@pytest.fixture
def sharing_manager(
    mock_client, mock_config, mock_policy_manager, mock_user_manager, mock_group_manager
):
    """Create a SharingManager instance with mocked dependencies."""
    return SharingManager(
        client=mock_client,
        config=mock_config,
        policy_manager=mock_policy_manager,
        user_manager=mock_user_manager,
        group_manager=mock_group_manager,
    )


# === SHARING RESULT TESTS ===


class TestSharingResult:
    """Tests for SharingResult dataclass."""

    def test_sharing_result_initialization(self):
        """Test SharingResult initializes with path and empty lists."""
        result = SharingResult(path="s3a://bucket/path/")
        assert result.path == "s3a://bucket/path/"
        assert result.shared_with_users == []
        assert result.shared_with_groups == []
        assert result.errors == []
        assert result.failed_users == []
        assert result.failed_groups == []

    def test_sharing_result_add_success_user(self):
        """Test adding a successful user share."""
        result = SharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "john")
        assert result.shared_with_users == ["john"]
        assert result.shared_with_groups == []

    def test_sharing_result_add_success_group(self):
        """Test adding a successful group share."""
        result = SharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.GROUP, "data-team")
        assert result.shared_with_users == []
        assert result.shared_with_groups == ["data-team"]

    def test_sharing_result_add_multiple_successes(self):
        """Test adding multiple successful shares."""
        result = SharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "alice")
        result.add_success(PolicyTarget.USER, "bob")
        result.add_success(PolicyTarget.GROUP, "team1")
        result.add_success(PolicyTarget.GROUP, "team2")
        assert result.shared_with_users == ["alice", "bob"]
        assert result.shared_with_groups == ["team1", "team2"]

    def test_sharing_result_add_failure_user(self):
        """Test adding a failed user share."""
        result = SharingResult(path="s3a://bucket/path/")
        result.add_failure(PolicyTarget.USER.value, "john", "User not found")
        assert result.failed_users == ["john"]
        assert result.failed_groups == []
        assert "Error sharing with user john: User not found" in result.errors

    def test_sharing_result_add_failure_group(self):
        """Test adding a failed group share."""
        result = SharingResult(path="s3a://bucket/path/")
        result.add_failure(
            PolicyTarget.GROUP.value, "missing-team", "Group does not exist"
        )
        assert result.failed_users == []
        assert result.failed_groups == ["missing-team"]
        assert (
            "Error sharing with group missing-team: Group does not exist"
            in result.errors
        )

    def test_sharing_result_success_count_empty(self):
        """Test success_count property with no successes."""
        result = SharingResult(path="s3a://bucket/path/")
        assert result.success_count == 0

    def test_sharing_result_success_count(self):
        """Test success_count property with multiple successes."""
        result = SharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "alice")
        result.add_success(PolicyTarget.USER, "bob")
        result.add_success(PolicyTarget.GROUP, "team1")
        assert result.success_count == 3

    def test_sharing_result_has_errors_false(self):
        """Test has_errors property with no errors."""
        result = SharingResult(path="s3a://bucket/path/")
        assert result.has_errors is False

    def test_sharing_result_has_errors_true(self):
        """Test has_errors property with errors."""
        result = SharingResult(path="s3a://bucket/path/")
        result.add_failure(PolicyTarget.USER, "john", "Error")
        assert result.has_errors is True

    def test_sharing_result_mixed_success_and_failure(self):
        """Test SharingResult with both successes and failures."""
        result = SharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "alice")
        result.add_failure(PolicyTarget.USER, "bob", "Not found")
        result.add_success(PolicyTarget.GROUP, "team1")
        result.add_failure(PolicyTarget.GROUP, "team2", "Does not exist")

        assert result.success_count == 2
        assert result.has_errors is True
        assert result.shared_with_users == ["alice"]
        assert result.failed_users == ["bob"]
        assert result.shared_with_groups == ["team1"]
        assert result.failed_groups == ["team2"]
        assert len(result.errors) == 2


# === UNSHARING RESULT TESTS ===


class TestUnsharingResult:
    """Tests for UnsharingResult dataclass."""

    def test_unsharing_result_initialization(self):
        """Test UnsharingResult initializes with path and empty lists."""
        result = UnsharingResult(path="s3a://bucket/path/")
        assert result.path == "s3a://bucket/path/"
        assert result.unshared_from_users == []
        assert result.unshared_from_groups == []
        assert result.errors == []
        assert result.failed_users == []
        assert result.failed_groups == []

    def test_unsharing_result_add_success_user(self):
        """Test adding a successful user unshare."""
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "john")
        assert result.unshared_from_users == ["john"]
        assert result.unshared_from_groups == []

    def test_unsharing_result_add_success_group(self):
        """Test adding a successful group unshare."""
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.GROUP, "data-team")
        assert result.unshared_from_users == []
        assert result.unshared_from_groups == ["data-team"]

    def test_unsharing_result_add_multiple_successes(self):
        """Test adding multiple successful unshares."""
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "alice")
        result.add_success(PolicyTarget.USER, "bob")
        result.add_success(PolicyTarget.GROUP, "team1")
        assert result.unshared_from_users == ["alice", "bob"]
        assert result.unshared_from_groups == ["team1"]

    def test_unsharing_result_add_failure_user(self):
        """Test adding a failed user unshare."""
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_failure(PolicyTarget.USER.value, "john", "Policy update failed")
        assert result.failed_users == ["john"]
        assert result.failed_groups == []
        assert "Error unsharing from user john: Policy update failed" in result.errors

    def test_unsharing_result_add_failure_group(self):
        """Test adding a failed group unshare."""
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_failure(PolicyTarget.GROUP.value, "team", "Error")
        assert result.failed_users == []
        assert result.failed_groups == ["team"]
        assert "Error unsharing from group team: Error" in result.errors

    def test_unsharing_result_success_count_empty(self):
        """Test success_count property with no successes."""
        result = UnsharingResult(path="s3a://bucket/path/")
        assert result.success_count == 0

    def test_unsharing_result_success_count(self):
        """Test success_count property with multiple successes."""
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "alice")
        result.add_success(PolicyTarget.GROUP, "team1")
        result.add_success(PolicyTarget.GROUP, "team2")
        assert result.success_count == 3

    def test_unsharing_result_has_errors_false(self):
        """Test has_errors property with no errors."""
        result = UnsharingResult(path="s3a://bucket/path/")
        assert result.has_errors is False

    def test_unsharing_result_has_errors_true(self):
        """Test has_errors property with errors."""
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_failure(PolicyTarget.USER, "john", "Error")
        assert result.has_errors is True


# === SHARING OPERATION ENUM TESTS ===


class TestSharingOperation:
    """Tests for SharingOperation enum."""

    def test_sharing_operation_add(self):
        """Test ADD operation value."""
        assert SharingOperation.ADD.value == "add"

    def test_sharing_operation_remove(self):
        """Test REMOVE operation value."""
        assert SharingOperation.REMOVE.value == "remove"


# === PATH ACCESS INFO TESTS ===


class TestPathAccessInfo:
    """Tests for PathAccessInfo model."""

    def test_path_access_info_initialization(self):
        """Test PathAccessInfo initialization."""
        info = PathAccessInfo(users=["alice", "bob"], groups=["team1"], public=False)
        assert info.users == ["alice", "bob"]
        assert info.groups == ["team1"]
        assert info.public is False

    def test_path_access_info_public(self):
        """Test PathAccessInfo with public access."""
        info = PathAccessInfo(users=[], groups=["all-users"], public=True)
        assert info.public is True

    def test_path_access_info_empty(self):
        """Test PathAccessInfo with empty access."""
        info = PathAccessInfo(users=[], groups=[], public=False)
        assert info.users == []
        assert info.groups == []
        assert info.public is False


# === SHARING MANAGER INITIALIZATION TESTS ===


class TestSharingManagerInit:
    """Tests for SharingManager initialization."""

    def test_sharing_manager_initialization(
        self,
        mock_client,
        mock_config,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        """Test SharingManager initializes with all dependencies."""
        manager = SharingManager(
            client=mock_client,
            config=mock_config,
            policy_manager=mock_policy_manager,
            user_manager=mock_user_manager,
            group_manager=mock_group_manager,
        )
        assert manager.client is mock_client
        assert manager.config is mock_config
        assert manager.policy_manager is mock_policy_manager
        assert manager.user_manager is mock_user_manager
        assert manager.group_manager is mock_group_manager


# === SHARE PATH TESTS ===


class TestSharePath:
    """Tests for share_path method."""

    @pytest.mark.asyncio
    async def test_share_path_with_users(self, sharing_manager, mock_policy_manager):
        """Test sharing path with users."""
        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=["alice", "bob"],
        )

        assert result.path == "s3a://test-bucket/data/project/"
        assert result.shared_with_users == ["alice", "bob"]
        assert result.success_count == 2
        assert not result.has_errors

        # Verify policy manager was called for each user
        assert mock_policy_manager.add_path_access_for_target.call_count == 2

    @pytest.mark.asyncio
    async def test_share_path_with_groups(self, sharing_manager, mock_policy_manager):
        """Test sharing path with groups."""
        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_groups=["team1", "team2"],
        )

        assert result.shared_with_groups == ["team1", "team2"]
        assert result.success_count == 2

    @pytest.mark.asyncio
    async def test_share_path_with_users_and_groups(
        self, sharing_manager, mock_policy_manager
    ):
        """Test sharing path with both users and groups."""
        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=["alice"],
            with_groups=["team1"],
        )

        assert result.shared_with_users == ["alice"]
        assert result.shared_with_groups == ["team1"]
        assert result.success_count == 2

    @pytest.mark.asyncio
    async def test_share_path_empty_targets(self, sharing_manager):
        """Test sharing path with no targets."""
        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=[],
            with_groups=[],
        )

        assert result.success_count == 0
        assert not result.has_errors

    @pytest.mark.asyncio
    async def test_share_path_none_targets(self, sharing_manager):
        """Test sharing path with None targets (defaults to empty lists)."""
        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=None,
            with_groups=None,
        )

        assert result.success_count == 0
        assert not result.has_errors

    @pytest.mark.asyncio
    async def test_share_path_authorization_failure(
        self, sharing_manager, mock_user_manager
    ):
        """Test share_path fails when user is not authorized."""
        mock_user_manager.can_user_share_path.return_value = False

        with pytest.raises(DataGovernanceError) as exc_info:
            await sharing_manager.share_path(
                path="s3a://test-bucket/data/project/",
                requesting_user="unauthorized_user",
                with_users=["alice"],
            )

        assert "does not have admin privileges" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_share_path_invalid_path(self, sharing_manager):
        """Test share_path fails with invalid path."""
        with pytest.raises(PolicyValidationError):
            await sharing_manager.share_path(
                path="invalid-path",
                requesting_user="owner",
                with_users=["alice"],
            )

    @pytest.mark.asyncio
    async def test_share_path_user_failure(self, sharing_manager, mock_policy_manager):
        """Test share_path handles user sharing failure."""
        mock_policy_manager.add_path_access_for_target.side_effect = [
            None,  # alice succeeds
            Exception("Policy update failed"),  # bob fails
        ]

        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=["alice", "bob"],
        )

        assert result.shared_with_users == ["alice"]
        assert result.failed_users == ["bob"]
        assert result.has_errors
        assert result.success_count == 1

    @pytest.mark.asyncio
    async def test_share_path_group_failure(self, sharing_manager, mock_policy_manager):
        """Test share_path handles group sharing failure."""
        mock_policy_manager.add_path_access_for_target.side_effect = Exception(
            "Group not found"
        )

        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_groups=["missing-team"],
        )

        assert result.failed_groups == ["missing-team"]
        assert result.has_errors


# === UNSHARE PATH TESTS ===


class TestUnsharePath:
    """Tests for unshare_path method."""

    @pytest.mark.asyncio
    async def test_unshare_path_from_users(self, sharing_manager, mock_policy_manager):
        """Test unsharing path from users."""
        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_users=["alice", "bob"],
        )

        assert result.path == "s3a://test-bucket/data/project/"
        assert result.unshared_from_users == ["alice", "bob"]
        assert result.success_count == 2
        assert not result.has_errors

        # Verify policy manager was called for each user
        assert mock_policy_manager.remove_path_access_for_target.call_count == 2

    @pytest.mark.asyncio
    async def test_unshare_path_from_groups(self, sharing_manager, mock_policy_manager):
        """Test unsharing path from groups."""
        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_groups=["team1"],
        )

        assert result.unshared_from_groups == ["team1"]
        assert result.success_count == 1

    @pytest.mark.asyncio
    async def test_unshare_path_from_users_and_groups(
        self, sharing_manager, mock_policy_manager
    ):
        """Test unsharing path from both users and groups."""
        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_users=["alice"],
            from_groups=["team1"],
        )

        assert result.unshared_from_users == ["alice"]
        assert result.unshared_from_groups == ["team1"]
        assert result.success_count == 2

    @pytest.mark.asyncio
    async def test_unshare_path_empty_targets(self, sharing_manager):
        """Test unsharing path with no targets."""
        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_users=[],
            from_groups=[],
        )

        assert result.success_count == 0
        assert not result.has_errors

    @pytest.mark.asyncio
    async def test_unshare_path_none_targets(self, sharing_manager):
        """Test unsharing path with None targets."""
        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_users=None,
            from_groups=None,
        )

        assert result.success_count == 0

    @pytest.mark.asyncio
    async def test_unshare_path_authorization_failure(
        self, sharing_manager, mock_user_manager
    ):
        """Test unshare_path fails when user is not authorized."""
        mock_user_manager.can_user_share_path.return_value = False

        with pytest.raises(DataGovernanceError) as exc_info:
            await sharing_manager.unshare_path(
                path="s3a://test-bucket/data/project/",
                requesting_user="unauthorized_user",
                from_users=["alice"],
            )

        assert "does not have admin privileges" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_unshare_path_user_failure(
        self, sharing_manager, mock_policy_manager
    ):
        """Test unshare_path handles user unsharing failure."""
        mock_policy_manager.remove_path_access_for_target.side_effect = [
            None,  # alice succeeds
            Exception("Policy not found"),  # bob fails
        ]

        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_users=["alice", "bob"],
        )

        assert result.unshared_from_users == ["alice"]
        assert result.failed_users == ["bob"]
        assert result.has_errors


# === MAKE PUBLIC TESTS ===


class TestMakePublic:
    """Tests for make_public method."""

    @pytest.mark.asyncio
    async def test_make_public_success(self, sharing_manager, mock_policy_manager):
        """Test making path public successfully."""
        result = await sharing_manager.make_public(
            path="s3a://test-bucket/data/public-dataset/",
            requesting_user="owner",
        )

        assert result.success_count == 1
        assert "globalusers" in result.shared_with_groups
        assert not result.has_errors

    @pytest.mark.asyncio
    async def test_make_public_authorization_failure(
        self, sharing_manager, mock_user_manager
    ):
        """Test make_public fails when user is not authorized."""
        mock_user_manager.can_user_share_path.return_value = False

        with pytest.raises(DataGovernanceError) as exc_info:
            await sharing_manager.make_public(
                path="s3a://test-bucket/data/dataset/",
                requesting_user="unauthorized_user",
            )

        assert "does not have admin privileges" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_make_public_shares_with_global_group(
        self, sharing_manager, mock_policy_manager
    ):
        """Test that make_public shares with the global user group."""
        await sharing_manager.make_public(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        # Verify it was shared with the global group
        mock_policy_manager.add_path_access_for_target.assert_called_once()
        call_args = mock_policy_manager.add_path_access_for_target.call_args
        assert call_args[0][0] == PolicyTarget.GROUP
        assert call_args[0][1] == "globalusers"


# === MAKE PRIVATE TESTS ===


class TestMakePrivate:
    """Tests for make_private method."""

    @pytest.mark.asyncio
    async def test_make_private_success_no_access(
        self, sharing_manager, mock_policy_manager
    ):
        """Test making path private when no one has access."""
        mock_policy_manager.list_resources.return_value = []

        result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        assert result.success_count == 0
        assert not result.has_errors

    @pytest.mark.asyncio
    async def test_make_private_removes_user_access(
        self, sharing_manager, mock_policy_manager
    ):
        """Test making path private removes user access."""
        # Setup: path is accessible by alice
        mock_policy_model = MagicMock()
        mock_policy_manager.list_resources.return_value = ["user-home-policy-alice"]
        mock_policy_manager._load_minio_policy.return_value = mock_policy_model
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/dataset/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = True

        result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        # Alice (not the owner) should be removed
        assert "alice" in result.unshared_from_users

    @pytest.mark.asyncio
    async def test_make_private_excludes_owner(
        self, sharing_manager, mock_policy_manager
    ):
        """Test making path private does not remove owner's access."""
        # Setup: path is accessible by owner
        mock_policy_model = MagicMock()
        mock_policy_manager.list_resources.return_value = ["user-home-policy-owner"]
        mock_policy_manager._load_minio_policy.return_value = mock_policy_model
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/dataset/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = True

        result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        # Owner should NOT be in the unshared list
        assert "owner" not in result.unshared_from_users

    @pytest.mark.asyncio
    async def test_make_private_removes_group_access(
        self, sharing_manager, mock_policy_manager
    ):
        """Test making path private removes group access."""
        # Setup: path is accessible by team1 group
        mock_policy_model = MagicMock()
        mock_policy_manager.list_resources.return_value = ["group-policy-team1"]
        mock_policy_manager._load_minio_policy.return_value = mock_policy_model
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/dataset/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = False
        mock_policy_manager.is_group_policy.return_value = True

        result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        assert "team1" in result.unshared_from_groups

    @pytest.mark.asyncio
    async def test_make_private_authorization_failure(
        self, sharing_manager, mock_user_manager
    ):
        """Test make_private fails when user is not authorized."""
        mock_user_manager.can_user_share_path.return_value = False

        with pytest.raises(DataGovernanceError):
            await sharing_manager.make_private(
                path="s3a://test-bucket/data/dataset/",
                requesting_user="unauthorized_user",
            )


# === GET PATH ACCESS INFO TESTS ===


class TestGetPathAccessInfo:
    """Tests for get_path_access_info method."""

    @pytest.mark.asyncio
    async def test_get_path_access_info_empty(
        self, sharing_manager, mock_policy_manager
    ):
        """Test getting access info when no one has access."""
        mock_policy_manager.list_resources.return_value = []

        result = await sharing_manager.get_path_access_info(
            path="s3a://test-bucket/data/path/"
        )

        assert result.users == []
        assert result.groups == []
        assert result.public is False

    @pytest.mark.asyncio
    async def test_get_path_access_info_with_user(
        self, sharing_manager, mock_policy_manager
    ):
        """Test getting access info with user access."""
        mock_policy_model = MagicMock()
        mock_policy_manager.list_resources.return_value = ["user-home-policy-alice"]
        mock_policy_manager._load_minio_policy.return_value = mock_policy_model
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/path/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = True

        result = await sharing_manager.get_path_access_info(
            path="s3a://test-bucket/data/path/"
        )

        assert "alice" in result.users
        assert result.public is False

    @pytest.mark.asyncio
    async def test_get_path_access_info_with_group(
        self, sharing_manager, mock_policy_manager
    ):
        """Test getting access info with group access."""
        mock_policy_model = MagicMock()
        mock_policy_manager.list_resources.return_value = ["group-policy-team1"]
        mock_policy_manager._load_minio_policy.return_value = mock_policy_model
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/path/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = False
        mock_policy_manager.is_group_policy.return_value = True

        result = await sharing_manager.get_path_access_info(
            path="s3a://test-bucket/data/path/"
        )

        assert "team1" in result.groups

    @pytest.mark.asyncio
    async def test_get_path_access_info_public(
        self, sharing_manager, mock_policy_manager
    ):
        """Test getting access info for public path."""
        mock_policy_model = MagicMock()
        mock_policy_manager.list_resources.return_value = ["group-policy-globalusers"]
        mock_policy_manager._load_minio_policy.return_value = mock_policy_model
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/path/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = False
        mock_policy_manager.is_group_policy.return_value = True

        result = await sharing_manager.get_path_access_info(
            path="s3a://test-bucket/data/path/"
        )

        assert "globalusers" in result.groups
        assert result.public is True

    @pytest.mark.asyncio
    async def test_get_path_access_info_invalid_path(self, sharing_manager):
        """Test getting access info with invalid path."""
        with pytest.raises(PolicyValidationError):
            await sharing_manager.get_path_access_info(path="invalid-path")

    @pytest.mark.asyncio
    async def test_get_path_access_info_skips_unsupported_policies(
        self, sharing_manager, mock_policy_manager
    ):
        """Test that unsupported policies are skipped."""
        mock_policy_manager.list_resources.return_value = [
            "user-home-policy-alice",
            "some-other-policy",
        ]
        mock_policy_manager._load_minio_policy.side_effect = [
            MagicMock(),  # alice's policy
            None,  # unsupported policy returns None
        ]
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/path/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = True

        result = await sharing_manager.get_path_access_info(
            path="s3a://test-bucket/data/path/"
        )

        assert "alice" in result.users

    @pytest.mark.asyncio
    async def test_get_path_access_info_parent_path_match(
        self, sharing_manager, mock_policy_manager
    ):
        """Test that parent path access is detected."""
        mock_policy_model = MagicMock()
        mock_policy_manager.list_resources.return_value = ["user-home-policy-alice"]
        mock_policy_manager._load_minio_policy.return_value = mock_policy_model
        # User has access to parent path
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = True

        result = await sharing_manager.get_path_access_info(
            path="s3a://test-bucket/data/subpath/"
        )

        assert "alice" in result.users


# === HELPER METHODS TESTS ===


class TestHelperMethods:
    """Tests for helper methods."""

    def test_path_matches_any_accessible_path_exact_match(self, sharing_manager):
        """Test exact path match."""
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/",
            ["s3a://bucket/path/"],
        )

    def test_path_matches_any_accessible_path_parent_access(self, sharing_manager):
        """Test parent path gives access."""
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/subdir/",
            ["s3a://bucket/path/"],
        )

    def test_path_matches_any_accessible_path_child_access(self, sharing_manager):
        """Test child path matches when target is parent."""
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/",
            ["s3a://bucket/path/subdir/"],
        )

    def test_path_matches_any_accessible_path_no_match(self, sharing_manager):
        """Test no match for unrelated paths."""
        assert not sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path1/",
            ["s3a://bucket/path2/"],
        )

    def test_path_matches_any_accessible_path_empty_list(self, sharing_manager):
        """Test no match when accessible paths is empty."""
        assert not sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/",
            [],
        )

    def test_path_matches_any_accessible_path_trailing_slash_normalization(
        self, sharing_manager
    ):
        """Test path matching normalizes trailing slashes."""
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path",
            ["s3a://bucket/path/"],
        )
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/",
            ["s3a://bucket/path"],
        )


# === VALIDATE AND AUTHORIZE TESTS ===


class TestValidateAndAuthorize:
    """Tests for _validate_and_authorize_request method."""

    @pytest.mark.asyncio
    async def test_validate_and_authorize_success(
        self, sharing_manager, mock_user_manager
    ):
        """Test validation and authorization succeeds for authorized user."""
        mock_user_manager.can_user_share_path.return_value = True

        # Should not raise
        await sharing_manager._validate_and_authorize_request(
            path="s3a://test-bucket/data/path/",
            requesting_user="owner",
        )

        mock_user_manager.can_user_share_path.assert_called_once_with(
            "s3a://test-bucket/data/path/", "owner"
        )

    @pytest.mark.asyncio
    async def test_validate_and_authorize_invalid_path(self, sharing_manager):
        """Test validation fails for invalid path."""
        with pytest.raises(PolicyValidationError):
            await sharing_manager._validate_and_authorize_request(
                path="not-a-valid-path",
                requesting_user="owner",
            )

    @pytest.mark.asyncio
    async def test_validate_and_authorize_unauthorized(
        self, sharing_manager, mock_user_manager
    ):
        """Test authorization fails for unauthorized user."""
        mock_user_manager.can_user_share_path.return_value = False

        with pytest.raises(DataGovernanceError) as exc_info:
            await sharing_manager._validate_and_authorize_request(
                path="s3a://test-bucket/data/path/",
                requesting_user="unauthorized",
            )

        assert "does not have admin privileges" in str(exc_info.value)


# === UPDATE TARGETS SHARING TESTS ===


class TestUpdateTargetsSharing:
    """Tests for _update_targets_sharing method."""

    @pytest.mark.asyncio
    async def test_update_targets_sharing_add_users(
        self, sharing_manager, mock_policy_manager
    ):
        """Test adding path access to multiple users."""
        result = SharingResult(path="s3a://bucket/path/")

        await sharing_manager._update_targets_sharing(
            operation=SharingOperation.ADD,
            target_type=PolicyTarget.USER,
            names=["alice", "bob"],
            path="s3a://bucket/path/",
            result=result,
        )

        assert result.shared_with_users == ["alice", "bob"]
        assert mock_policy_manager.add_path_access_for_target.call_count == 2

    @pytest.mark.asyncio
    async def test_update_targets_sharing_remove_users(
        self, sharing_manager, mock_policy_manager
    ):
        """Test removing path access from multiple users."""
        result = UnsharingResult(path="s3a://bucket/path/")

        await sharing_manager._update_targets_sharing(
            operation=SharingOperation.REMOVE,
            target_type=PolicyTarget.USER,
            names=["alice", "bob"],
            path="s3a://bucket/path/",
            result=result,
        )

        assert result.unshared_from_users == ["alice", "bob"]
        assert mock_policy_manager.remove_path_access_for_target.call_count == 2

    @pytest.mark.asyncio
    async def test_update_targets_sharing_add_groups(
        self, sharing_manager, mock_policy_manager
    ):
        """Test adding path access to multiple groups."""
        result = SharingResult(path="s3a://bucket/path/")

        await sharing_manager._update_targets_sharing(
            operation=SharingOperation.ADD,
            target_type=PolicyTarget.GROUP,
            names=["team1", "team2"],
            path="s3a://bucket/path/",
            result=result,
        )

        assert result.shared_with_groups == ["team1", "team2"]

    @pytest.mark.asyncio
    async def test_update_targets_sharing_handles_exception(
        self, sharing_manager, mock_policy_manager
    ):
        """Test that exceptions are caught and added to errors."""
        mock_policy_manager.add_path_access_for_target.side_effect = Exception(
            "Policy error"
        )
        result = SharingResult(path="s3a://bucket/path/")

        await sharing_manager._update_targets_sharing(
            operation=SharingOperation.ADD,
            target_type=PolicyTarget.USER,
            names=["alice"],
            path="s3a://bucket/path/",
            result=result,
        )

        assert result.has_errors
        assert result.failed_users == ["alice"]

    @pytest.mark.asyncio
    async def test_update_targets_sharing_empty_names(
        self, sharing_manager, mock_policy_manager
    ):
        """Test with empty names list."""
        result = SharingResult(path="s3a://bucket/path/")

        await sharing_manager._update_targets_sharing(
            operation=SharingOperation.ADD,
            target_type=PolicyTarget.USER,
            names=[],
            path="s3a://bucket/path/",
            result=result,
        )

        assert result.success_count == 0
        mock_policy_manager.add_path_access_for_target.assert_not_called()


# === UPDATE PATH SHARING TESTS ===


class TestUpdatePathSharing:
    """Tests for _update_path_sharing method."""

    @pytest.mark.asyncio
    async def test_update_path_sharing_add(self, sharing_manager, mock_policy_manager):
        """Test adding path sharing."""
        await sharing_manager._update_path_sharing(
            operation=SharingOperation.ADD,
            target_type=PolicyTarget.USER,
            target_name="alice",
            path="s3a://bucket/path/",
        )

        mock_policy_manager.add_path_access_for_target.assert_called_once_with(
            PolicyTarget.USER,
            "alice",
            "s3a://bucket/path/",
            PolicyPermissionLevel.WRITE,
        )

    @pytest.mark.asyncio
    async def test_update_path_sharing_remove(
        self, sharing_manager, mock_policy_manager
    ):
        """Test removing path sharing."""
        await sharing_manager._update_path_sharing(
            operation=SharingOperation.REMOVE,
            target_type=PolicyTarget.USER,
            target_name="alice",
            path="s3a://bucket/path/",
        )

        mock_policy_manager.remove_path_access_for_target.assert_called_once_with(
            PolicyTarget.USER,
            "alice",
            "s3a://bucket/path/",
        )

    @pytest.mark.asyncio
    async def test_update_path_sharing_add_group(
        self, sharing_manager, mock_policy_manager
    ):
        """Test adding path sharing for group."""
        await sharing_manager._update_path_sharing(
            operation=SharingOperation.ADD,
            target_type=PolicyTarget.GROUP,
            target_name="team1",
            path="s3a://bucket/path/",
        )

        mock_policy_manager.add_path_access_for_target.assert_called_once_with(
            PolicyTarget.GROUP,
            "team1",
            "s3a://bucket/path/",
            PolicyPermissionLevel.WRITE,
        )


# === INTEGRATION-LIKE TESTS ===


class TestSharingManagerIntegration:
    """Integration-like tests for complex scenarios."""

    @pytest.mark.asyncio
    async def test_share_then_make_private(
        self, sharing_manager, mock_policy_manager, mock_user_manager
    ):
        """Test sharing and then making private."""
        # First share with user
        share_result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=["alice"],
        )

        assert share_result.success_count == 1

        # Setup for make_private - alice has access
        mock_policy_model = MagicMock()
        mock_policy_manager.list_resources.return_value = ["user-home-policy-alice"]
        mock_policy_manager._load_minio_policy.return_value = mock_policy_model
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/project/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = True

        # Now make private
        private_result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
        )

        assert "alice" in private_result.unshared_from_users

    @pytest.mark.asyncio
    async def test_partial_share_failure(self, sharing_manager, mock_policy_manager):
        """Test partial failure in sharing operation."""
        call_count = [0]

        async def mock_add_access(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:  # Fail on second call
                raise Exception("Network error")

        mock_policy_manager.add_path_access_for_target.side_effect = mock_add_access

        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=["alice", "bob", "charlie"],
        )

        # One failure, two successes
        assert result.success_count == 2
        assert result.has_errors
        assert len(result.errors) == 1

    @pytest.mark.asyncio
    async def test_make_public_then_make_private(
        self, sharing_manager, mock_policy_manager, mock_user_manager
    ):
        """Test making public then private."""
        # Make public
        public_result = await sharing_manager.make_public(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        assert "globalusers" in public_result.shared_with_groups

        # Setup for make_private - global group has access
        mock_policy_model = MagicMock()
        mock_policy_manager.list_resources.return_value = ["group-policy-globalusers"]
        mock_policy_manager._load_minio_policy.return_value = mock_policy_model
        mock_policy_manager.get_accessible_paths_from_policy.return_value = [
            "s3a://test-bucket/data/dataset/"
        ]
        mock_policy_manager.is_user_home_policy.return_value = False
        mock_policy_manager.is_group_policy.return_value = True

        # Make private
        private_result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        assert "globalusers" in private_result.unshared_from_groups
