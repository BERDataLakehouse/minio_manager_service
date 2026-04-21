"""
Tests for src.s3.managers.user_manager.

All external dependencies (S3IAMClient, S3Client, PolicyManager) are mocked.
"""

import re
from unittest.mock import create_autospec

import pytest

from s3.core.s3_client import S3Client
from s3.core.s3_iam_client import S3IAMClient
from s3.managers.group_manager import GroupManager
from s3.managers.policy_manager import PolicyManager
from s3.managers.user_manager import (
    GLOBAL_USER_GROUP,
    REFDATA_TENANT_RO_GROUP,
    UserManager,
)
from s3.models.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyStatement,
)
from s3.models.s3_config import S3Config
from service.exceptions import GroupNotFoundError, UserOperationError


# TODO TESTING these tests are AI generated and... aren't great. Could probably use a rework
#              at some point


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
    return PolicyModel(policy_document=PolicyDocument(statement=statements))


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def s3_config() -> S3Config:
    return S3Config(
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
def mock_iam_client():
    client = create_autospec(S3IAMClient, spec_set=True, instance=True)
    client.user_exists.return_value = True
    client.list_access_key_ids.return_value = ["KEY123"]
    client.rotate_access_key.return_value = ("KEY123", "secret123")
    client.list_users.return_value = ["alice"]
    return client


@pytest.fixture
def mock_s3_client():
    client = create_autospec(S3Client, spec_set=True, instance=True)
    client.list_objects.return_value = []
    client.bucket_exists.return_value = True
    return client


@pytest.fixture
def mock_policy_manager():
    home = make_policy_model()
    system = make_policy_model()
    manager = create_autospec(PolicyManager, spec_set=True, instance=True)
    manager.ensure_user_policies.return_value = (home, system)
    manager.get_user_home_policy.return_value = home
    manager.get_user_system_policy.return_value = system
    manager.get_group_policy.return_value = make_policy_model()
    return manager


@pytest.fixture
def mock_group_manager():
    manager = create_autospec(GroupManager, spec_set=True, instance=True)
    manager.get_user_groups.return_value = []
    return manager


@pytest.fixture
def user_manager(
    mock_iam_client, mock_s3_client, mock_policy_manager, mock_group_manager, s3_config
):
    return UserManager(
        iam_client=mock_iam_client,
        s3_client=mock_s3_client,
        policy_manager=mock_policy_manager,
        group_manager=mock_group_manager,
        config=s3_config,
    )


# =============================================================================
# create_user
# =============================================================================


async def test_create_user_calls_iam_create_user(user_manager, mock_iam_client):
    await user_manager.create_user("alice")
    mock_iam_client.create_user.assert_called_once_with("alice", exists_ok=True)


async def test_create_user_ensures_user_policies(user_manager, mock_policy_manager):
    await user_manager.create_user("alice")
    mock_policy_manager.ensure_user_policies.assert_called_once_with("alice")


async def test_create_user_rotates_access_key(user_manager, mock_iam_client):
    await user_manager.create_user("alice")
    mock_iam_client.rotate_access_key.assert_called_once_with("alice")


async def test_create_user_creates_home_directory(user_manager, mock_s3_client):
    await user_manager.create_user("alice")
    mock_s3_client.create_bucket.assert_any_call("test-bucket", exists_ok=True)
    put_keys = {call.args[1] for call in mock_s3_client.put_object.call_args_list}
    assert "users-sql-warehouse/alice/.s3keep" in put_keys
    assert "users-general-warehouse/alice/.s3keep" in put_keys
    assert "users-general-warehouse/alice/data/.s3keep" in put_keys
    assert "users-general-warehouse/alice/notebooks/.s3keep" in put_keys
    assert "users-general-warehouse/alice/shared/.s3keep" in put_keys


async def test_create_user_creates_global_group_if_not_exists(
    user_manager, mock_group_manager
):
    mock_group_manager.group_exists.return_value = False
    await user_manager.create_user("alice")
    mock_group_manager.create_group.assert_called_once_with(GLOBAL_USER_GROUP, "alice")
    mock_group_manager.add_user_to_group.assert_any_call("alice", GLOBAL_USER_GROUP)


async def test_create_user_skips_create_group_if_global_group_exists(
    user_manager, mock_group_manager
):
    mock_group_manager.group_exists.return_value = True
    await user_manager.create_user("alice")
    mock_group_manager.create_group.assert_not_called()
    mock_group_manager.add_user_to_group.assert_any_call("alice", GLOBAL_USER_GROUP)


async def test_adds_user_to_refdata_ro_when_group_exists(
    user_manager, mock_group_manager
):
    """New users are auto-added to the RefData RO group when it exists."""
    await user_manager.create_user("alice")
    mock_group_manager.add_user_to_group.assert_any_call(
        "alice", REFDATA_TENANT_RO_GROUP
    )


async def test_skips_refdata_ro_add_when_group_missing(
    user_manager, mock_group_manager
):
    """If the RefData RO group does not exist, auto-add is skipped (not created)."""

    async def add_user_to_group_side_effect(username, group_name):
        if group_name == REFDATA_TENANT_RO_GROUP:
            raise GroupNotFoundError(f"Group {group_name} not found")
        return None

    mock_group_manager.add_user_to_group.side_effect = add_user_to_group_side_effect

    await user_manager.create_user("alice")

    mock_group_manager.add_user_to_group.assert_any_call("alice", GLOBAL_USER_GROUP)
    mock_group_manager.add_user_to_group.assert_any_call(
        "alice", REFDATA_TENANT_RO_GROUP
    )
    mock_group_manager.create_group.assert_not_called()


async def test_create_user_returns_user_model_with_credentials(user_manager):
    result = await user_manager.create_user("alice")
    assert result.username == "alice"
    assert result.access_key == "KEY123"
    assert result.secret_key == "secret123"


async def test_create_user_returns_user_model_with_home_paths(user_manager):
    result = await user_manager.create_user("alice")
    assert "s3a://test-bucket/users-general-warehouse/alice/" in result.home_paths
    assert "s3a://test-bucket/users-sql-warehouse/alice/" in result.home_paths


async def test_create_user_invalid_username_raises(user_manager):
    with pytest.raises(UserOperationError):
        await user_manager.create_user("inv@lid!")


# =============================================================================
# get_user
# =============================================================================


async def test_get_user_raises_if_not_exists(user_manager, mock_iam_client):
    mock_iam_client.user_exists.return_value = False
    with pytest.raises(UserOperationError, match="alice"):
        await user_manager.get_user("alice")


async def test_get_user_returns_access_key_from_iam(user_manager, mock_iam_client):
    mock_iam_client.list_access_key_ids.return_value = ["IAMKEY456"]
    result = await user_manager.get_user("alice")
    assert result.access_key == "IAMKEY456"


async def test_get_user_empty_access_key_when_no_keys(user_manager, mock_iam_client):
    mock_iam_client.list_access_key_ids.return_value = []
    result = await user_manager.get_user("alice")
    assert result.access_key == ""


async def test_get_user_aggregates_paths_from_home_and_system_policies(
    user_manager, mock_policy_manager
):
    mock_policy_manager.get_user_home_policy.return_value = make_policy_model(
        ["s3a://test-bucket/users-general-warehouse/alice/"]
    )
    mock_policy_manager.get_user_system_policy.return_value = make_policy_model(
        ["s3a://cdm-spark-job-logs/spark-job-logs/alice/"]
    )
    result = await user_manager.get_user("alice")
    assert "s3a://test-bucket/users-general-warehouse/alice/" in result.accessible_paths
    assert "s3a://cdm-spark-job-logs/spark-job-logs/alice/" in result.accessible_paths


async def test_get_user_aggregates_group_policy_paths(
    user_manager, mock_group_manager, mock_policy_manager
):
    mock_group_manager.get_user_groups.return_value = ["researchers"]
    mock_policy_manager.get_group_policy.return_value = make_policy_model(
        ["s3a://test-bucket/tenant-general-warehouse/researchers/"]
    )
    result = await user_manager.get_user("alice")
    assert result.groups == ["researchers"]
    assert len(result.group_policies) == 1
    assert (
        "s3a://test-bucket/tenant-general-warehouse/researchers/"
        in result.accessible_paths
    )


async def test_get_user_accessible_paths_are_sorted(user_manager, mock_policy_manager):
    mock_policy_manager.get_user_home_policy.return_value = make_policy_model(
        ["s3a://z-bucket/z/", "s3a://a-bucket/a/"]
    )
    result = await user_manager.get_user("alice")
    assert result.accessible_paths == sorted(result.accessible_paths)


# =============================================================================
# get_or_rotate_user_credentials
# =============================================================================


async def test_get_or_rotate_user_credentials_raises_if_not_exists(
    user_manager, mock_iam_client
):
    mock_iam_client.user_exists.return_value = False
    with pytest.raises(UserOperationError, match="alice"):
        await user_manager.get_or_rotate_user_credentials("alice")


async def test_get_or_rotate_user_credentials_returns_new_key(
    user_manager, mock_iam_client
):
    mock_iam_client.rotate_access_key.return_value = ("NEWKEY", "newsecret")
    key_id, secret = await user_manager.get_or_rotate_user_credentials("alice")
    assert key_id == "NEWKEY"
    assert secret == "newsecret"
    mock_iam_client.rotate_access_key.assert_called_once_with("alice")


# =============================================================================
# get_user_policies
# =============================================================================


async def test_get_user_policies_raises_if_not_exists(user_manager, mock_iam_client):
    mock_iam_client.user_exists.return_value = False
    with pytest.raises(UserOperationError, match="alice"):
        await user_manager.get_user_policies("alice")


async def test_get_user_policies_returns_home_system_and_group_policies(
    user_manager, mock_group_manager, mock_policy_manager
):
    home_policy = make_policy_model(["s3a://bucket/users-general-warehouse/alice/"])
    system_policy = make_policy_model(
        ["s3a://cdm-spark-job-logs/spark-job-logs/alice/"]
    )
    group_policy = make_policy_model(
        ["s3a://bucket/tenant-general-warehouse/researchers/"]
    )
    mock_policy_manager.get_user_home_policy.return_value = home_policy
    mock_policy_manager.get_user_system_policy.return_value = system_policy
    mock_group_manager.get_user_groups.return_value = ["researchers"]
    mock_policy_manager.get_group_policy.return_value = group_policy

    result = await user_manager.get_user_policies("alice")

    assert result["user_home_policy"] is home_policy
    assert result["user_system_policy"] is system_policy
    assert result["group_policies"] == [group_policy]
    mock_policy_manager.get_group_policy.assert_called_once_with("researchers")


# =============================================================================
# can_user_share_path
# =============================================================================


async def test_can_user_share_path_general_warehouse_returns_true(user_manager):
    path = "s3a://test-bucket/users-general-warehouse/alice/data/"
    assert await user_manager.can_user_share_path(path, "alice") is True


async def test_can_user_share_path_sql_warehouse_returns_true(user_manager):
    path = "s3a://test-bucket/users-sql-warehouse/alice/mydb/"
    assert await user_manager.can_user_share_path(path, "alice") is True


async def test_can_user_share_path_bare_bucket_returns_false(user_manager):
    # Path with no key component (no slash after bucket) — hits the early-return False branch
    assert await user_manager.can_user_share_path("s3a://test-bucket", "alice") is False


async def test_can_user_share_path_outside_home_returns_false(user_manager):
    path = "s3a://test-bucket/tenant-general-warehouse/researchers/"
    assert await user_manager.can_user_share_path(path, "alice") is False


async def test_can_user_share_path_other_user_home_returns_false(user_manager):
    path = "s3a://test-bucket/users-general-warehouse/bob/data/"
    assert await user_manager.can_user_share_path(path, "alice") is False


# =============================================================================
# get_user_accessible_paths
# =============================================================================


async def test_get_user_accessible_paths_raises_if_not_exists(
    user_manager, mock_iam_client
):
    mock_iam_client.user_exists.return_value = False
    with pytest.raises(UserOperationError, match="alice"):
        await user_manager.get_user_accessible_paths("alice")


async def test_get_user_accessible_paths_returns_sorted_union(
    user_manager, mock_group_manager, mock_policy_manager
):
    mock_policy_manager.get_user_home_policy.return_value = make_policy_model(
        ["s3a://z/z/"]
    )
    mock_policy_manager.get_user_system_policy.return_value = make_policy_model(
        ["s3a://a/a/"]
    )
    mock_group_manager.get_user_groups.return_value = ["researchers"]
    mock_policy_manager.get_group_policy.return_value = make_policy_model(
        ["s3a://m/m/"]
    )

    result = await user_manager.get_user_accessible_paths("alice")

    assert result == ["s3a://a/a/", "s3a://m/m/", "s3a://z/z/"]


# =============================================================================
# list_users / delete_user / user_exists
# =============================================================================


async def test_list_users_delegates_to_iam_client(user_manager, mock_iam_client):
    mock_iam_client.list_users.return_value = ["alice", "bob"]
    result = await user_manager.list_users()
    assert result == ["alice", "bob"]
    mock_iam_client.list_users.assert_called_once()


async def test_delete_user_calls_iam_delete_user(user_manager, mock_iam_client):
    await user_manager.delete_user("alice")
    mock_iam_client.delete_user.assert_called_once_with("alice")


async def test_delete_user_deletes_s3_home_objects(user_manager, mock_s3_client):
    # list_objects returns these for every prefix; we assert the home objects are deleted
    mock_s3_client.list_objects.return_value = [
        "users-general-warehouse/alice/.s3keep",
        "users-general-warehouse/alice/README.txt",
    ]
    await user_manager.delete_user("alice")
    deleted_keys = {
        call.args[1] for call in mock_s3_client.delete_object.call_args_list
    }
    assert "users-general-warehouse/alice/.s3keep" in deleted_keys
    assert "users-general-warehouse/alice/README.txt" in deleted_keys


async def test_delete_user_skips_missing_system_bucket(user_manager, mock_s3_client):
    mock_s3_client.bucket_exists.return_value = False
    await user_manager.delete_user("alice")
    # bucket_exists returned False, so no list_objects or delete_object calls for system dirs
    mock_s3_client.delete_object.assert_not_called()


async def test_delete_user_s3_failure_does_not_raise(user_manager, mock_s3_client):
    mock_s3_client.list_objects.side_effect = Exception("S3 unavailable")
    # Should not raise — IAM deletion already succeeded
    await user_manager.delete_user("alice")


async def test_user_exists_true(user_manager, mock_iam_client):
    mock_iam_client.user_exists.return_value = True
    assert await user_manager.user_exists("alice") is True


async def test_user_exists_false(user_manager, mock_iam_client):
    mock_iam_client.user_exists.return_value = False
    assert await user_manager.user_exists("alice") is False


# =============================================================================
# Compatibility shims
# =============================================================================


async def test_list_resources_delegates_to_list_users(user_manager, mock_iam_client):
    mock_iam_client.list_users.return_value = ["alice"]
    assert await user_manager.list_resources() == ["alice"]


async def test_delete_resource_returns_true_on_success(user_manager):
    assert await user_manager.delete_resource("alice") is True


async def test_delete_resource_returns_false_on_failure(user_manager, mock_iam_client):
    mock_iam_client.delete_user.side_effect = Exception("IAM error")
    assert await user_manager.delete_resource("alice") is False


async def test_resource_exists_delegates_to_user_exists(user_manager, mock_iam_client):
    mock_iam_client.user_exists.return_value = True
    assert await user_manager.resource_exists("alice") is True
