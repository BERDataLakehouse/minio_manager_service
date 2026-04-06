"""
Tests for src.s3.managers.group_manager.

All external dependencies (S3IAMClient, S3Client, PolicyManager) are mocked.
"""

from unittest.mock import create_autospec

import pytest

from s3.core.s3_client import S3Client
from s3.core.s3_iam_client import S3IAMClient
from s3.managers.group_manager import GroupManager
from s3.managers.policy_manager import PolicyManager
from s3.models.s3_config import S3Config
from service.exceptions import GroupOperationError


# TODO TESTING these tests are AI generated and... aren't great. Could probably use a rework
#              at some point


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
        tenant_general_warehouse_prefix="tenant-general-warehouse",
        tenant_sql_warehouse_prefix="tenant-sql-warehouse",
    )


@pytest.fixture
def mock_iam_client():
    client = create_autospec(S3IAMClient, spec_set=True, instance=True)
    client.user_exists.return_value = True
    client.group_exists.return_value = True
    client.list_users_in_group.return_value = []
    client.list_groups_for_user.return_value = []
    client.list_groups.return_value = []
    return client


@pytest.fixture
def mock_s3_client():
    client = create_autospec(S3Client, spec_set=True, instance=True)
    client.list_objects.return_value = []
    return client


@pytest.fixture
def mock_policy_manager():
    return create_autospec(PolicyManager, spec_set=True, instance=True)


@pytest.fixture
def group_manager(mock_iam_client, mock_s3_client, mock_policy_manager, s3_config):
    return GroupManager(
        iam_client=mock_iam_client,
        s3_client=mock_s3_client,
        policy_manager=mock_policy_manager,
        config=s3_config,
    )


# =============================================================================
# group_exists / list_groups
# =============================================================================


async def test_group_exists_true(group_manager, mock_iam_client):
    mock_iam_client.group_exists.return_value = True
    assert await group_manager.group_exists("researchers") is True


async def test_group_exists_false(group_manager, mock_iam_client):
    mock_iam_client.group_exists.return_value = False
    assert await group_manager.group_exists("researchers") is False


async def test_list_groups_delegates(group_manager, mock_iam_client):
    mock_iam_client.list_groups.return_value = ["researchers", "admins"]
    assert await group_manager.list_groups() == ["researchers", "admins"]


# =============================================================================
# delete_group
# =============================================================================


async def test_delete_group_deletes_ro_if_exists(group_manager, mock_iam_client):
    mock_iam_client.group_exists.return_value = True
    await group_manager.delete_group("researchers")
    mock_iam_client.delete_group.assert_any_call("researchersro")
    mock_iam_client.delete_group.assert_any_call("researchers")


async def test_delete_group_skips_ro_if_not_exists(group_manager, mock_iam_client):
    # group_exists returns False for the ro group, True for the main group
    mock_iam_client.group_exists.side_effect = lambda name: not name.endswith("ro")
    await group_manager.delete_group("researchers")
    deleted = [call.args[0] for call in mock_iam_client.delete_group.call_args_list]
    assert "researchersro" not in deleted
    assert "researchers" in deleted


async def test_delete_group_deletes_s3_objects(group_manager, mock_s3_client):
    mock_s3_client.list_objects.return_value = [
        "tenant-general-warehouse/researchers/.s3keep",
        "tenant-general-warehouse/researchers/README.txt",
    ]
    await group_manager.delete_group("researchers")
    deleted_keys = {
        call.args[1] for call in mock_s3_client.delete_object.call_args_list
    }
    assert "tenant-general-warehouse/researchers/.s3keep" in deleted_keys
    assert "tenant-general-warehouse/researchers/README.txt" in deleted_keys


async def test_delete_group_s3_failure_does_not_raise(group_manager, mock_s3_client):
    mock_s3_client.list_objects.side_effect = Exception("S3 unavailable")
    await group_manager.delete_group("researchers")  # must not raise


# =============================================================================
# create_group
# =============================================================================


async def test_create_group_raises_if_creator_missing(group_manager, mock_iam_client):
    mock_iam_client.user_exists.return_value = False
    with pytest.raises(GroupOperationError, match="alice"):
        await group_manager.create_group("researchers", "alice")


async def test_create_group_invalid_name_raises(group_manager):
    with pytest.raises(Exception):
        await group_manager.create_group("inv@lid!", "alice")


async def test_create_group_creates_iam_groups(group_manager, mock_iam_client):
    await group_manager.create_group("researchers", "alice")
    mock_iam_client.create_group.assert_any_call("researchers", exists_ok=True)
    mock_iam_client.create_group.assert_any_call("researchersro", exists_ok=True)


async def test_create_group_ensures_policies(group_manager, mock_policy_manager):
    await group_manager.create_group("researchers", "alice")
    mock_policy_manager.ensure_group_policy.assert_any_call("researchers")
    mock_policy_manager.ensure_group_policy.assert_any_call(
        "researchersro", read_only=True, path_target="researchers"
    )


async def test_create_group_adds_creator_to_both_groups(group_manager, mock_iam_client):
    await group_manager.create_group("researchers", "alice")
    mock_iam_client.add_user_to_group.assert_any_call("alice", "researchers")
    mock_iam_client.add_user_to_group.assert_any_call("alice", "researchersro")


async def test_create_group_creates_s3_directory(group_manager, mock_s3_client):
    await group_manager.create_group("researchers", "alice")
    mock_s3_client.create_bucket.assert_called_once_with("test-bucket", exists_ok=True)
    put_keys = {call.args[1] for call in mock_s3_client.put_object.call_args_list}
    assert "tenant-sql-warehouse/researchers/.s3keep" in put_keys
    assert "tenant-general-warehouse/researchers/.s3keep" in put_keys
    assert "tenant-general-warehouse/researchers/shared/.s3keep" in put_keys
    assert "tenant-general-warehouse/researchers/datasets/.s3keep" in put_keys
    assert "tenant-general-warehouse/researchers/projects/.s3keep" in put_keys
    assert "tenant-general-warehouse/researchers/README.txt" in put_keys


async def test_create_group_returns_group_models(group_manager):
    main, ro = await group_manager.create_group("researchers", "alice")
    assert main.group_name == "researchers"
    assert main.members == ["alice"]
    assert ro.group_name == "researchersro"
    assert ro.members == ["alice"]


# =============================================================================
# add_user_to_group
# =============================================================================


async def test_add_user_to_group_raises_if_group_missing(
    group_manager, mock_iam_client
):
    mock_iam_client.group_exists.return_value = False
    with pytest.raises(GroupOperationError, match="researchers"):
        await group_manager.add_user_to_group("alice", "researchers")


async def test_add_user_to_group_raises_if_user_missing(group_manager, mock_iam_client):
    mock_iam_client.user_exists.return_value = False
    with pytest.raises(GroupOperationError, match="alice"):
        await group_manager.add_user_to_group("alice", "researchers")


async def test_add_user_to_group_calls_iam(group_manager, mock_iam_client):
    await group_manager.add_user_to_group("alice", "researchers")
    mock_iam_client.add_user_to_group.assert_called_once_with("alice", "researchers")


# =============================================================================
# remove_user_from_group
# =============================================================================


async def test_remove_user_from_group_raises_if_group_missing(
    group_manager, mock_iam_client
):
    mock_iam_client.group_exists.return_value = False
    with pytest.raises(GroupOperationError, match="researchers"):
        await group_manager.remove_user_from_group("alice", "researchers")


async def test_remove_user_from_group_calls_iam(group_manager, mock_iam_client):
    await group_manager.remove_user_from_group("alice", "researchers")
    mock_iam_client.remove_user_from_group.assert_called_once_with(
        "alice", "researchers"
    )


# =============================================================================
# get_group_members
# =============================================================================


async def test_get_group_members_raises_if_not_exists(group_manager, mock_iam_client):
    mock_iam_client.group_exists.return_value = False
    with pytest.raises(GroupOperationError, match="researchers"):
        await group_manager.get_group_members("researchers")


async def test_get_group_members_returns_members(group_manager, mock_iam_client):
    mock_iam_client.list_users_in_group.return_value = ["alice", "bob"]
    assert await group_manager.get_group_members("researchers") == ["alice", "bob"]


# =============================================================================
# get_group_info
# =============================================================================


async def test_get_group_info_raises_if_not_exists(group_manager, mock_iam_client):
    mock_iam_client.group_exists.return_value = False
    with pytest.raises(GroupOperationError, match="researchers"):
        await group_manager.get_group_info("researchers")


async def test_get_group_info_returns_group_model(group_manager, mock_iam_client):
    mock_iam_client.list_users_in_group.return_value = ["alice", "bob"]
    result = await group_manager.get_group_info("researchers")
    assert result.group_name == "researchers"
    assert result.members == ["alice", "bob"]


# =============================================================================
# is_user_in_group
# =============================================================================


async def test_is_user_in_group_true(group_manager, mock_iam_client):
    mock_iam_client.list_users_in_group.return_value = ["alice", "bob"]
    assert await group_manager.is_user_in_group("alice", "researchers") is True


async def test_is_user_in_group_false(group_manager, mock_iam_client):
    mock_iam_client.list_users_in_group.return_value = ["bob"]
    assert await group_manager.is_user_in_group("alice", "researchers") is False


async def test_is_user_in_group_wraps_exception(group_manager, mock_iam_client):
    mock_iam_client.group_exists.return_value = False
    with pytest.raises(GroupOperationError, match="researchers"):
        await group_manager.is_user_in_group("alice", "researchers")


# =============================================================================
# get_user_groups
# =============================================================================


async def test_get_user_groups_returns_sorted(group_manager, mock_iam_client):
    mock_iam_client.list_groups_for_user.return_value = ["zebra", "alpha", "middle"]
    assert await group_manager.get_user_groups("alice") == ["alpha", "middle", "zebra"]


# =============================================================================
# Compatibility shims
# =============================================================================


async def test_list_resources_delegates(group_manager, mock_iam_client):
    mock_iam_client.list_groups.return_value = ["researchers"]
    assert await group_manager.list_resources() == ["researchers"]


async def test_delete_resource_returns_true_on_success(group_manager):
    assert await group_manager.delete_resource("researchers") is True


async def test_delete_resource_returns_false_on_failure(group_manager, mock_iam_client):
    mock_iam_client.delete_group.side_effect = Exception("IAM error")
    assert await group_manager.delete_resource("researchers") is False
