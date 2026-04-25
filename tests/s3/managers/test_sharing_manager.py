"""Tests for src.s3.managers.sharing_manager."""

import re
from unittest.mock import create_autospec

import pytest

from s3.managers.group_manager import GroupManager
from s3.managers.policy_manager import PolicyManager
from s3.managers.sharing_manager import (
    PathAccessInfo,
    SharingManager,
    SharingOperation,
    SharingResult,
    UnsharingResult,
)
from s3.managers.user_manager import UserManager
from s3.models.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
    PolicyTarget,
)
from service.exceptions import DataGovernanceError, PolicyValidationError


# =============================================================================
# Helpers
# =============================================================================


def make_policy_model(paths: list[str] | None = None) -> PolicyModel:
    """Create a real PolicyModel with GET_OBJECT statements for the given s3a:// paths."""
    statements = []
    for path in paths or []:
        clean = re.sub(r"^s3a?://", "", path).rstrip("/")
        statements.append(
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                action=PolicyAction.GET_OBJECT,
                resource=f"arn:aws:s3:::{clean}/*",
                condition=None,
                principal=None,
            )
        )
    return PolicyModel(
        policy_name="test-policy", policy_document=PolicyDocument(statement=statements)
    )


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_policy_manager():
    pm = create_autospec(PolicyManager, spec_set=True, instance=True)
    pm.get_user_home_policy.return_value = make_policy_model()
    pm.get_group_policy.return_value = make_policy_model()
    return pm


@pytest.fixture
def mock_user_manager():
    um = create_autospec(UserManager, spec_set=True, instance=True)
    um.can_user_share_path.return_value = True
    um.list_users.return_value = []
    return um


@pytest.fixture
def mock_group_manager():
    gm = create_autospec(GroupManager, spec_set=True, instance=True)
    gm.list_groups.return_value = []
    return gm


@pytest.fixture
def sharing_manager(mock_policy_manager, mock_user_manager, mock_group_manager):
    return SharingManager(
        policy_manager=mock_policy_manager,
        user_manager=mock_user_manager,
        group_manager=mock_group_manager,
    )


# =============================================================================
# SharingResult
# =============================================================================


class TestSharingResult:
    def test_initialization(self):
        result = SharingResult(path="s3a://bucket/path/")
        assert result.path == "s3a://bucket/path/"
        assert result.shared_with_users == []
        assert result.shared_with_groups == []
        assert result.errors == []
        assert result.failed_users == []
        assert result.failed_groups == []

    def test_add_success_user(self):
        result = SharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "john")
        assert result.shared_with_users == ["john"]
        assert result.shared_with_groups == []

    def test_add_success_group(self):
        result = SharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.GROUP, "data-team")
        assert result.shared_with_users == []
        assert result.shared_with_groups == ["data-team"]

    def test_add_multiple_successes(self):
        result = SharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "alice")
        result.add_success(PolicyTarget.USER, "bob")
        result.add_success(PolicyTarget.GROUP, "team1")
        result.add_success(PolicyTarget.GROUP, "team2")
        assert result.shared_with_users == ["alice", "bob"]
        assert result.shared_with_groups == ["team1", "team2"]

    def test_add_failure_user(self):
        result = SharingResult(path="s3a://bucket/path/")
        result.add_failure(PolicyTarget.USER.value, "john", "User not found")
        assert result.failed_users == ["john"]
        assert result.failed_groups == []
        assert "Error sharing with user john: User not found" in result.errors

    def test_add_failure_group(self):
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

    def test_success_count(self):
        result = SharingResult(path="s3a://bucket/path/")
        assert result.success_count == 0
        result.add_success(PolicyTarget.USER, "alice")
        result.add_success(PolicyTarget.USER, "bob")
        result.add_success(PolicyTarget.GROUP, "team1")
        assert result.success_count == 3

    def test_has_errors(self):
        result = SharingResult(path="s3a://bucket/path/")
        assert result.has_errors is False
        result.add_failure(PolicyTarget.USER.value, "john", "Error")
        assert result.has_errors is True

    def test_mixed_success_and_failure(self):
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


# =============================================================================
# UnsharingResult
# =============================================================================


class TestUnsharingResult:
    def test_initialization(self):
        result = UnsharingResult(path="s3a://bucket/path/")
        assert result.path == "s3a://bucket/path/"
        assert result.unshared_from_users == []
        assert result.unshared_from_groups == []
        assert result.errors == []
        assert result.failed_users == []
        assert result.failed_groups == []

    def test_add_success_user(self):
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "john")
        assert result.unshared_from_users == ["john"]
        assert result.unshared_from_groups == []

    def test_add_success_group(self):
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.GROUP, "data-team")
        assert result.unshared_from_users == []
        assert result.unshared_from_groups == ["data-team"]

    def test_add_multiple_successes(self):
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "alice")
        result.add_success(PolicyTarget.USER, "bob")
        result.add_success(PolicyTarget.GROUP, "team1")
        assert result.unshared_from_users == ["alice", "bob"]
        assert result.unshared_from_groups == ["team1"]

    def test_add_failure_user(self):
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_failure(PolicyTarget.USER.value, "john", "Policy update failed")
        assert result.failed_users == ["john"]
        assert result.failed_groups == []
        assert "Error unsharing from user john: Policy update failed" in result.errors

    def test_add_failure_group(self):
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_failure(PolicyTarget.GROUP.value, "team", "Error")
        assert result.failed_users == []
        assert result.failed_groups == ["team"]
        assert "Error unsharing from group team: Error" in result.errors

    def test_success_count_empty(self):
        result = UnsharingResult(path="s3a://bucket/path/")
        assert result.success_count == 0

    def test_success_count(self):
        result = UnsharingResult(path="s3a://bucket/path/")
        result.add_success(PolicyTarget.USER, "alice")
        result.add_success(PolicyTarget.GROUP, "team1")
        result.add_success(PolicyTarget.GROUP, "team2")
        assert result.success_count == 3

    def test_has_errors(self):
        result = UnsharingResult(path="s3a://bucket/path/")
        assert result.has_errors is False
        result.add_failure(PolicyTarget.USER.value, "john", "Error")
        assert result.has_errors is True


# =============================================================================
# SharingOperation
# =============================================================================


class TestSharingOperation:
    def test_add(self):
        assert SharingOperation.ADD.value == "add"

    def test_remove(self):
        assert SharingOperation.REMOVE.value == "remove"


# =============================================================================
# PathAccessInfo
# =============================================================================


class TestPathAccessInfo:
    def test_initialization(self):
        info = PathAccessInfo(users=["alice", "bob"], groups=["team1"], public=False)
        assert info.users == ["alice", "bob"]
        assert info.groups == ["team1"]
        assert info.public is False

    def test_public(self):
        info = PathAccessInfo(users=[], groups=["globalusers"], public=True)
        assert info.public is True

    def test_empty(self):
        info = PathAccessInfo(users=[], groups=[], public=False)
        assert info.users == []
        assert info.groups == []
        assert info.public is False


# =============================================================================
# SharingManager init
# =============================================================================


class TestSharingManagerInit:
    def test_initialization(
        self, mock_policy_manager, mock_user_manager, mock_group_manager
    ):
        manager = SharingManager(
            policy_manager=mock_policy_manager,
            user_manager=mock_user_manager,
            group_manager=mock_group_manager,
        )
        assert manager.policy_manager is mock_policy_manager
        assert manager.user_manager is mock_user_manager
        assert manager.group_manager is mock_group_manager


# =============================================================================
# share_path
# =============================================================================


class TestSharePath:
    async def test_share_with_users(self, sharing_manager, mock_policy_manager):
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

    async def test_share_with_groups(self, sharing_manager, mock_policy_manager):
        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_groups=["team1", "team2"],
        )

        assert result.shared_with_groups == ["team1", "team2"]
        assert result.success_count == 2

    async def test_share_with_users_and_groups(self, sharing_manager):
        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=["alice"],
            with_groups=["team1"],
        )

        assert result.shared_with_users == ["alice"]
        assert result.shared_with_groups == ["team1"]
        assert result.success_count == 2

    async def test_empty_targets(self, sharing_manager):
        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=[],
            with_groups=[],
        )

        assert result.success_count == 0
        assert not result.has_errors

    async def test_none_targets(self, sharing_manager):
        result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=None,
            with_groups=None,
        )

        assert result.success_count == 0
        assert not result.has_errors

    async def test_authorization_failure(self, sharing_manager, mock_user_manager):
        mock_user_manager.can_user_share_path.return_value = False
        with pytest.raises(DataGovernanceError, match="does not have admin privileges"):
            await sharing_manager.share_path(
                path="s3a://test-bucket/data/project/",
                requesting_user="unauthorized_user",
                with_users=["alice"],
            )

    async def test_invalid_path(self, sharing_manager):
        with pytest.raises(PolicyValidationError):
            await sharing_manager.share_path(
                path="invalid-path",
                requesting_user="owner",
                with_users=["alice"],
            )

    async def test_user_failure(self, sharing_manager, mock_policy_manager):
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

    async def test_group_failure(self, sharing_manager, mock_policy_manager):
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


# =============================================================================
# unshare_path
# =============================================================================


class TestUnsharePath:
    async def test_unshare_from_users(self, sharing_manager, mock_policy_manager):
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

    async def test_unshare_from_groups(self, sharing_manager):
        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_groups=["team1"],
        )

        assert result.unshared_from_groups == ["team1"]
        assert result.success_count == 1

    async def test_unshare_from_users_and_groups(
        self, sharing_manager, mock_policy_manager
    ):
        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_users=["alice"],
            from_groups=["team1"],
        )

        assert result.unshared_from_users == ["alice"]
        assert result.unshared_from_groups == ["team1"]
        assert result.success_count == 2

    async def test_empty_targets(self, sharing_manager):
        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_users=[],
            from_groups=[],
        )

        assert result.success_count == 0
        assert not result.has_errors

    async def test_unshare_none_targets(self, sharing_manager):
        result = await sharing_manager.unshare_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            from_users=None,
            from_groups=None,
        )

        assert result.success_count == 0

    async def test_authorization_failure(self, sharing_manager, mock_user_manager):
        mock_user_manager.can_user_share_path.return_value = False
        with pytest.raises(DataGovernanceError, match="does not have admin privileges"):
            await sharing_manager.unshare_path(
                path="s3a://test-bucket/data/project/",
                requesting_user="unauthorized_user",
                from_users=["alice"],
            )

    async def test_user_failure(self, sharing_manager, mock_policy_manager):
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


# =============================================================================
# make_public
# =============================================================================


class TestMakePublic:
    async def test_success(self, sharing_manager):
        result = await sharing_manager.make_public(
            path="s3a://test-bucket/data/public-dataset/",
            requesting_user="owner",
        )

        assert result.success_count == 1
        assert "globalusers" in result.shared_with_groups
        assert not result.has_errors

    async def test_authorization_failure(self, sharing_manager, mock_user_manager):
        mock_user_manager.can_user_share_path.return_value = False
        with pytest.raises(DataGovernanceError, match="does not have admin privileges"):
            await sharing_manager.make_public(
                path="s3a://test-bucket/data/dataset/",
                requesting_user="unauthorized_user",
            )

    async def test_shares_with_global_group(self, sharing_manager, mock_policy_manager):
        await sharing_manager.make_public(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        # Verify it was shared with the global group
        mock_policy_manager.add_path_access_for_target.assert_called_once()
        call_args = mock_policy_manager.add_path_access_for_target.call_args
        assert call_args[0][0] == PolicyTarget.GROUP
        assert call_args[0][1] == "globalusers"


# =============================================================================
# make_private
# =============================================================================


class TestMakePrivate:
    async def test_success_no_access(
        self, sharing_manager, mock_user_manager, mock_group_manager
    ):
        mock_user_manager.list_users.return_value = []
        mock_group_manager.list_groups.return_value = []

        result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        assert result.success_count == 0
        assert not result.has_errors

    async def test_removes_user_access(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        mock_user_manager.list_users.return_value = ["alice"]
        mock_policy_manager.get_user_home_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/dataset/"]
        )
        mock_group_manager.list_groups.return_value = []

        result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        # Alice (not the owner) should be removed
        assert "alice" in result.unshared_from_users

    async def test_excludes_owner(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        mock_user_manager.list_users.return_value = ["owner"]
        mock_policy_manager.get_user_home_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/dataset/"]
        )
        mock_group_manager.list_groups.return_value = []

        result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        # Owner should NOT be in the unshared list
        assert "owner" not in result.unshared_from_users

    async def test_removes_group_access(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        mock_user_manager.list_users.return_value = []
        mock_group_manager.list_groups.return_value = ["team1"]
        mock_policy_manager.get_group_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/dataset/"]
        )

        result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        assert "team1" in result.unshared_from_groups

    async def test_authorization_failure(self, sharing_manager, mock_user_manager):
        mock_user_manager.can_user_share_path.return_value = False

        with pytest.raises(DataGovernanceError):
            await sharing_manager.make_private(
                path="s3a://test-bucket/data/dataset/",
                requesting_user="unauthorized_user",
            )


# =============================================================================
# get_path_access_info
# =============================================================================


class TestGetPathAccessInfo:
    async def test_empty(self, sharing_manager, mock_user_manager, mock_group_manager):
        mock_user_manager.list_users.return_value = []
        mock_group_manager.list_groups.return_value = []

        result = await sharing_manager.get_path_access_info(
            "s3a://test-bucket/data/path/"
        )

        assert result.users == []
        assert result.groups == []
        assert result.public is False

    async def test_with_user(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        mock_user_manager.list_users.return_value = ["alice"]
        mock_policy_manager.get_user_home_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/path/"]
        )
        mock_group_manager.list_groups.return_value = []

        result = await sharing_manager.get_path_access_info(
            "s3a://test-bucket/data/path/"
        )

        assert "alice" in result.users
        assert result.public is False

    async def test_user_without_matching_policy(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        mock_user_manager.list_users.return_value = ["alice"]
        mock_policy_manager.get_user_home_policy.return_value = make_policy_model(
            ["s3a://test-bucket/other/"]
        )
        mock_group_manager.list_groups.return_value = []

        result = await sharing_manager.get_path_access_info(
            "s3a://test-bucket/data/path/"
        )

        assert "alice" not in result.users

    async def test_with_group(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        mock_user_manager.list_users.return_value = []
        mock_group_manager.list_groups.return_value = ["team1"]
        mock_policy_manager.get_group_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/path/"]
        )

        result = await sharing_manager.get_path_access_info(
            "s3a://test-bucket/data/path/"
        )

        assert "team1" in result.groups

    async def test_public(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        mock_user_manager.list_users.return_value = []
        mock_group_manager.list_groups.return_value = ["globalusers"]
        mock_policy_manager.get_group_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/path/"]
        )

        result = await sharing_manager.get_path_access_info(
            "s3a://test-bucket/data/path/"
        )

        assert "globalusers" in result.groups
        assert result.public is True

    async def test_invalid_path(self, sharing_manager):
        with pytest.raises(PolicyValidationError):
            await sharing_manager.get_path_access_info("invalid-path")

    async def test_ro_groups_are_included(
        self,
        sharing_manager,
        mock_user_manager,
        mock_group_manager,
        mock_policy_manager,
    ):
        mock_user_manager.list_users.return_value = []
        mock_group_manager.list_groups.return_value = ["team1", "team1ro"]
        mock_policy_manager.get_group_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/path/"]
        )

        result = await sharing_manager.get_path_access_info(
            "s3a://test-bucket/data/path/"
        )

        assert "team1" in result.groups
        assert "team1ro" in result.groups

    async def test_parent_path_match(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        mock_user_manager.list_users.return_value = ["alice"]
        mock_policy_manager.get_user_home_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/"]
        )
        mock_group_manager.list_groups.return_value = []

        result = await sharing_manager.get_path_access_info(
            "s3a://test-bucket/data/subpath/"
        )

        assert "alice" in result.users


# =============================================================================
# _path_matches_any_accessible_path
# =============================================================================


class TestPathMatchesAnyAccessiblePath:
    def test_exact_match(self, sharing_manager):
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/", ["s3a://bucket/path/"]
        )

    def test_parent_access(self, sharing_manager):
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/subdir/", ["s3a://bucket/path/"]
        )

    def test_child_access(self, sharing_manager):
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/", ["s3a://bucket/path/subdir/"]
        )

    def test_no_match(self, sharing_manager):
        assert not sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path1/", ["s3a://bucket/path2/"]
        )

    def test_empty_list(self, sharing_manager):
        assert not sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/", []
        )

    def test_trailing_slash_normalization(self, sharing_manager):
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path", ["s3a://bucket/path/"]
        )
        assert sharing_manager._path_matches_any_accessible_path(
            "s3a://bucket/path/", ["s3a://bucket/path"]
        )


# =============================================================================
# _validate_and_authorize_request
# =============================================================================


class TestValidateAndAuthorize:
    async def test_success(self, sharing_manager, mock_user_manager):
        mock_user_manager.can_user_share_path.return_value = True

        # Should not raise
        await sharing_manager._validate_and_authorize_request(
            path="s3a://test-bucket/data/path/",
            requesting_user="owner",
        )

        mock_user_manager.can_user_share_path.assert_called_once_with(
            "s3a://test-bucket/data/path/", "owner"
        )

    async def test_invalid_path(self, sharing_manager):
        with pytest.raises(PolicyValidationError):
            await sharing_manager._validate_and_authorize_request(
                path="not-a-valid-path",
                requesting_user="owner",
            )

    async def test_unauthorized(self, sharing_manager, mock_user_manager):
        mock_user_manager.can_user_share_path.return_value = False
        with pytest.raises(DataGovernanceError, match="does not have admin privileges"):
            await sharing_manager._validate_and_authorize_request(
                path="s3a://test-bucket/data/path/",
                requesting_user="unauthorized",
            )


# =============================================================================
# _update_targets_sharing
# =============================================================================


class TestUpdateTargetsSharing:
    async def test_add_users(self, sharing_manager, mock_policy_manager):
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

    async def test_remove_users(self, sharing_manager, mock_policy_manager):
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

    async def test_add_groups(self, sharing_manager):
        result = SharingResult(path="s3a://bucket/path/")

        await sharing_manager._update_targets_sharing(
            operation=SharingOperation.ADD,
            target_type=PolicyTarget.GROUP,
            names=["team1", "team2"],
            path="s3a://bucket/path/",
            result=result,
        )

        assert result.shared_with_groups == ["team1", "team2"]

    async def test_handles_exception(self, sharing_manager, mock_policy_manager):
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

    async def test_empty_names(self, sharing_manager, mock_policy_manager):
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


# =============================================================================
# _update_path_sharing
# =============================================================================


class TestUpdatePathSharing:
    async def test_add(self, sharing_manager, mock_policy_manager):
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

    async def test_remove(self, sharing_manager, mock_policy_manager):
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

    async def test_add_group(self, sharing_manager, mock_policy_manager):
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


# =============================================================================
# Integration-like tests
# =============================================================================


class TestSharingManagerIntegration:
    async def test_share_then_make_private(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        # First share with user
        share_result = await sharing_manager.share_path(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
            with_users=["alice"],
        )

        assert share_result.success_count == 1

        # Setup for make_private - alice has access
        mock_user_manager.list_users.return_value = ["alice"]
        mock_policy_manager.get_user_home_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/project/"]
        )
        mock_group_manager.list_groups.return_value = []

        # Now make private
        private_result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/project/",
            requesting_user="owner",
        )

        assert "alice" in private_result.unshared_from_users

    async def test_partial_share_failure(self, sharing_manager, mock_policy_manager):
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

    async def test_make_public_then_make_private(
        self,
        sharing_manager,
        mock_policy_manager,
        mock_user_manager,
        mock_group_manager,
    ):
        # Make public
        public_result = await sharing_manager.make_public(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        assert "globalusers" in public_result.shared_with_groups

        # Setup for make_private - global group has access
        mock_user_manager.list_users.return_value = []
        mock_group_manager.list_groups.return_value = ["globalusers"]
        mock_policy_manager.get_group_policy.return_value = make_policy_model(
            ["s3a://test-bucket/data/dataset/"]
        )

        # Make private
        private_result = await sharing_manager.make_private(
            path="s3a://test-bucket/data/dataset/",
            requesting_user="owner",
        )

        assert "globalusers" in private_result.unshared_from_groups
