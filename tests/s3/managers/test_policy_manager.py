"""
Tests for src.s3.managers.policy_manager.

All external dependencies (S3IAMClient, DistributedLockManager) are mocked.
PolicyBuilder and PolicyCreator run for real so that integration of the
pure-logic layer is exercised without a live IAM endpoint.
"""

# TODO TESTING these tests are AI generated and... aren't great. Could probably use a rework
#              at some point

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, call, create_autospec, patch

import pytest
from s3.core.s3_iam_client import S3IAMClient
from s3.managers.policy_manager import (
    PolicyManager,
    _GROUP_IAM_POLICY,
    _USER_HOME_IAM_POLICY,
    _USER_SYSTEM_IAM_POLICY,
)
from s3.models.policy import (
    PolicyDocument,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyTarget,
    PolicyAction,
)
from s3.models.s3_config import S3Config
from s3.exceptions import IamPolicyNotFoundError
from service.exceptions import PolicyOperationError


# =============================================================================
# Helpers
# =============================================================================


def empty_policy_doc() -> dict:
    """Minimal policy document dict that PolicyDocument.from_dict accepts."""
    return {"Version": "2012-10-17", "Statement": []}


def make_policy_model(statements: list | None = None) -> PolicyModel:
    return PolicyModel(
        policy_document=PolicyDocument(statement=statements or []),
    )


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
    client.get_user_policy.return_value = empty_policy_doc()
    client.get_group_policy.return_value = empty_policy_doc()
    return client


@pytest.fixture
def mock_lock_manager():
    @asynccontextmanager
    async def _lock(lock_key: str, timeout=None):
        yield MagicMock()

    manager = MagicMock()
    manager.policy_update_lock = _lock
    return manager


@pytest.fixture
def policy_manager(mock_iam_client, s3_config, mock_lock_manager):
    return PolicyManager(
        iam_client=mock_iam_client,
        config=s3_config,
        lock_manager=mock_lock_manager,
    )


@pytest.fixture
def policy_manager_no_lock(mock_iam_client, s3_config):
    return PolicyManager(iam_client=mock_iam_client, config=s3_config)


@pytest.fixture
async def user_home_policy_doc(s3_config) -> dict:
    """Real user home policy doc generated via a dedicated manager."""
    dedicated_iam = create_autospec(S3IAMClient, spec_set=True, instance=True)
    await PolicyManager(
        iam_client=dedicated_iam, config=s3_config
    ).regenerate_user_home_policy("alice")
    return dedicated_iam.set_user_policy.call_args.args[2]


@pytest.fixture
async def group_home_policy_doc(s3_config) -> dict:
    """Real group home policy doc generated via a dedicated manager."""
    dedicated_iam = create_autospec(S3IAMClient, spec_set=True, instance=True)
    await PolicyManager(
        iam_client=dedicated_iam, config=s3_config
    ).regenerate_group_home_policy("researchers")
    return dedicated_iam.set_group_policy.call_args.args[2]


# =============================================================================
# regenerate_user_home_policy / regenerate_group_home_policy
# =============================================================================


async def test_regenerate_user_home_policy_always_writes(
    policy_manager, mock_iam_client
):
    result = await policy_manager.regenerate_user_home_policy("alice")

    assert result.policy_name is None
    assert len(result.policy_document.statement) > 0
    mock_iam_client.set_user_policy.assert_called_once_with(
        "alice", _USER_HOME_IAM_POLICY, result.policy_document.to_dict()
    )


async def test_regenerate_user_home_policy_overwrites_existing(
    policy_manager, mock_iam_client
):
    # Even when get_user_policy would return an existing doc, regenerate still writes.
    mock_iam_client.get_user_policy = AsyncMock(return_value=empty_policy_doc())

    await policy_manager.regenerate_user_home_policy("alice")

    mock_iam_client.set_user_policy.assert_called_once()


async def test_regenerate_group_home_policy_rw(policy_manager, mock_iam_client):
    result = await policy_manager.regenerate_group_home_policy("researchers")

    assert result.policy_name is None
    assert len(result.policy_document.statement) > 0
    mock_iam_client.set_group_policy.assert_called_once_with(
        "researchers", _GROUP_IAM_POLICY, result.policy_document.to_dict()
    )


async def test_regenerate_group_home_policy_read_only(policy_manager, mock_iam_client):
    result = await policy_manager.regenerate_group_home_policy(
        "researchersro", read_only=True, path_target="researchers"
    )

    assert result.policy_name is None
    mock_iam_client.set_group_policy.assert_called_once_with(
        "researchersro", _GROUP_IAM_POLICY, result.policy_document.to_dict()
    )


async def test_regenerate_group_home_policy_overwrites_existing(
    policy_manager, mock_iam_client
):
    mock_iam_client.get_group_policy = AsyncMock(return_value=empty_policy_doc())

    await policy_manager.regenerate_group_home_policy("researchers")

    mock_iam_client.set_group_policy.assert_called_once()


# =============================================================================
# ensure_user_policies — create when absent
# =============================================================================


async def test_ensure_user_policies_creates_both_when_absent(
    policy_manager, mock_iam_client
):
    mock_iam_client.get_user_policy = AsyncMock(return_value=None)

    home, system = await policy_manager.ensure_user_policies("alice")

    assert home.policy_name is None
    assert system.policy_name is None
    assert mock_iam_client.set_user_policy.call_count == 2
    calls = mock_iam_client.set_user_policy.call_args_list
    # First call: home policy
    assert calls[0] == call(
        "alice", _USER_HOME_IAM_POLICY, home.policy_document.to_dict()
    )
    # Second call: system policy
    assert calls[1] == call(
        "alice", _USER_SYSTEM_IAM_POLICY, system.policy_document.to_dict()
    )


async def test_ensure_user_policies_returns_existing_when_present(
    policy_manager, mock_iam_client
):
    mock_iam_client.get_user_policy = AsyncMock(return_value=empty_policy_doc())

    home, system = await policy_manager.ensure_user_policies("bob")

    mock_iam_client.set_user_policy.assert_not_called()
    assert home.policy_name is None
    assert system.policy_name is None


async def test_ensure_user_policies_creates_home_but_loads_existing_system(
    policy_manager, mock_iam_client
):
    # Home policy absent (None), system policy already present (returns doc).
    mock_iam_client.get_user_policy = AsyncMock(side_effect=[None, empty_policy_doc()])

    home, system = await policy_manager.ensure_user_policies("carol")

    # Only home should have been written
    mock_iam_client.set_user_policy.assert_called_once_with(
        "carol", _USER_HOME_IAM_POLICY, home.policy_document.to_dict()
    )
    assert home.policy_name is None
    assert system.policy_name is None


# =============================================================================
# ensure_group_policy
# =============================================================================


async def test_ensure_group_policy_creates_when_absent(policy_manager, mock_iam_client):
    mock_iam_client.get_group_policy = AsyncMock(return_value=None)

    result = await policy_manager.ensure_group_policy("researchers")

    assert result.policy_name is None
    mock_iam_client.set_group_policy.assert_called_once_with(
        "researchers", _GROUP_IAM_POLICY, result.policy_document.to_dict()
    )


async def test_ensure_group_policy_returns_existing_when_present(
    policy_manager, mock_iam_client
):
    mock_iam_client.get_group_policy = AsyncMock(return_value=empty_policy_doc())

    result = await policy_manager.ensure_group_policy("researchers")

    mock_iam_client.set_group_policy.assert_not_called()
    assert result.policy_name is None


async def test_ensure_group_policy_read_only_creates_ro_policy(
    policy_manager, mock_iam_client
):
    mock_iam_client.get_group_policy = AsyncMock(return_value=None)

    result = await policy_manager.ensure_group_policy("researchersro", read_only=True)

    mock_iam_client.set_group_policy.assert_called_once()
    actions = {stmt.action for stmt in result.policy_document.statement}
    assert PolicyAction.GET_OBJECT in actions
    assert PolicyAction.PUT_OBJECT not in actions
    assert PolicyAction.DELETE_OBJECT not in actions


# =============================================================================
# get_user_home_policy
# =============================================================================


async def test_get_user_home_policy_returns_policy_model(
    policy_manager, mock_iam_client
):
    mock_iam_client.get_user_policy = AsyncMock(return_value=empty_policy_doc())

    result = await policy_manager.get_user_home_policy("alice")

    mock_iam_client.get_user_policy.assert_called_once_with(
        "alice", _USER_HOME_IAM_POLICY
    )
    assert result.policy_name is None
    assert isinstance(result.policy_document, PolicyDocument)


async def test_get_user_home_policy_raises_on_client_error(
    policy_manager, mock_iam_client
):
    mock_iam_client.get_user_policy = AsyncMock(
        side_effect=IamPolicyNotFoundError("policy not found")
    )

    with pytest.raises(PolicyOperationError, match="alice"):
        await policy_manager.get_user_home_policy("alice")


# =============================================================================
# get_user_system_policy
# =============================================================================


async def test_get_user_system_policy_returns_policy_model(
    policy_manager, mock_iam_client
):
    mock_iam_client.get_user_policy = AsyncMock(return_value=empty_policy_doc())

    result = await policy_manager.get_user_system_policy("alice")

    mock_iam_client.get_user_policy.assert_called_once_with(
        "alice", _USER_SYSTEM_IAM_POLICY
    )
    assert result.policy_name is None


async def test_get_user_system_policy_raises_on_client_error(
    policy_manager, mock_iam_client
):
    mock_iam_client.get_user_policy = AsyncMock(
        side_effect=IamPolicyNotFoundError("policy not found")
    )

    with pytest.raises(PolicyOperationError, match="alice"):
        await policy_manager.get_user_system_policy("alice")


# =============================================================================
# get_group_policy
# =============================================================================


async def test_get_group_policy_returns_policy_model(policy_manager, mock_iam_client):
    mock_iam_client.get_group_policy = AsyncMock(return_value=empty_policy_doc())

    result = await policy_manager.get_group_policy("researchers")

    mock_iam_client.get_group_policy.assert_called_once_with(
        "researchers", _GROUP_IAM_POLICY
    )
    assert result.policy_name is None


async def test_get_group_policy_raises_on_client_error(policy_manager, mock_iam_client):
    mock_iam_client.get_group_policy = AsyncMock(
        side_effect=IamPolicyNotFoundError("policy not found")
    )

    with pytest.raises(PolicyOperationError, match="researchers"):
        await policy_manager.get_group_policy("researchers")


# =============================================================================
# add_path_access_for_target / remove_path_access_for_target
# =============================================================================


async def test_add_path_access_for_user_calls_set_user_policy(
    policy_manager, mock_iam_client, user_home_policy_doc
):
    mock_iam_client.get_user_policy.return_value = user_home_policy_doc
    shared_path = "s3a://test-bucket/users-general-warehouse/alice/shared/"
    shared_arn = "arn:aws:s3:::test-bucket/users-general-warehouse/alice/shared/*"

    await policy_manager.add_path_access_for_target(
        PolicyTarget.USER, "alice", shared_path, PolicyPermissionLevel.READ
    )

    mock_iam_client.set_user_policy.assert_called_once()
    name, iam_name, doc = mock_iam_client.set_user_policy.call_args.args
    assert name == "alice"
    assert iam_name == _USER_HOME_IAM_POLICY
    result = PolicyDocument.from_dict(doc)
    shared_actions = {
        s.action
        for s in result.statement
        if s.resource == shared_arn
        or (isinstance(s.resource, list) and shared_arn in s.resource)
    }
    assert PolicyAction.GET_OBJECT in shared_actions
    assert PolicyAction.PUT_OBJECT not in shared_actions
    assert PolicyAction.DELETE_OBJECT not in shared_actions


async def test_add_path_access_for_group_calls_set_group_policy(
    policy_manager, mock_iam_client, group_home_policy_doc
):
    mock_iam_client.get_group_policy.return_value = group_home_policy_doc
    shared_path = "s3a://test-bucket/tenant-general-warehouse/researchers/shared/"
    shared_arn = (
        "arn:aws:s3:::test-bucket/tenant-general-warehouse/researchers/shared/*"
    )

    await policy_manager.add_path_access_for_target(
        PolicyTarget.GROUP, "researchers", shared_path, PolicyPermissionLevel.WRITE
    )

    mock_iam_client.set_group_policy.assert_called_once()
    name, iam_name, doc = mock_iam_client.set_group_policy.call_args.args
    assert name == "researchers"
    assert iam_name == _GROUP_IAM_POLICY
    result = PolicyDocument.from_dict(doc)
    shared_actions = {
        s.action
        for s in result.statement
        if s.resource == shared_arn
        or (isinstance(s.resource, list) and shared_arn in s.resource)
    }
    assert PolicyAction.GET_OBJECT in shared_actions
    assert PolicyAction.PUT_OBJECT in shared_actions
    assert PolicyAction.DELETE_OBJECT in shared_actions


async def test_remove_path_access_for_user_calls_set_user_policy(
    policy_manager, mock_iam_client, user_home_policy_doc
):
    mock_iam_client.get_user_policy.return_value = user_home_policy_doc
    removed_path = "s3a://test-bucket/users-general-warehouse/alice/"
    removed_arn = "arn:aws:s3:::test-bucket/users-general-warehouse/alice/*"

    await policy_manager.remove_path_access_for_target(
        PolicyTarget.USER, "alice", removed_path
    )

    mock_iam_client.set_user_policy.assert_called_once()
    name, iam_name, doc = mock_iam_client.set_user_policy.call_args.args
    assert name == "alice"
    assert iam_name == _USER_HOME_IAM_POLICY
    result = PolicyDocument.from_dict(doc)
    remaining_arns = {
        r
        for s in result.statement
        for r in (s.resource if isinstance(s.resource, list) else [s.resource])
    }
    assert removed_arn not in remaining_arns


async def test_remove_path_access_for_group_calls_set_group_policy(
    policy_manager, mock_iam_client, group_home_policy_doc
):
    mock_iam_client.get_group_policy.return_value = group_home_policy_doc
    removed_path = "s3a://test-bucket/tenant-general-warehouse/researchers/"
    removed_arn = "arn:aws:s3:::test-bucket/tenant-general-warehouse/researchers/*"

    await policy_manager.remove_path_access_for_target(
        PolicyTarget.GROUP, "researchers", removed_path
    )

    mock_iam_client.set_group_policy.assert_called_once()
    name, iam_name, doc = mock_iam_client.set_group_policy.call_args.args
    assert name == "researchers"
    assert iam_name == _GROUP_IAM_POLICY
    result = PolicyDocument.from_dict(doc)
    remaining_arns = {
        r
        for s in result.statement
        for r in (s.resource if isinstance(s.resource, list) else [s.resource])
    }
    assert removed_arn not in remaining_arns


async def test_add_path_access_without_lock_manager_raises(policy_manager_no_lock):
    with pytest.raises(PolicyOperationError, match="lock manager"):
        await policy_manager_no_lock.add_path_access_for_target(
            PolicyTarget.USER,
            "alice",
            "s3a://test-bucket/users-general-warehouse/alice/",
            PolicyPermissionLevel.READ,
        )


async def test_remove_path_access_without_lock_manager_raises(policy_manager_no_lock):
    with pytest.raises(PolicyOperationError, match="lock manager"):
        await policy_manager_no_lock.remove_path_access_for_target(
            PolicyTarget.USER,
            "alice",
            "s3a://test-bucket/users-general-warehouse/alice/",
        )


# =============================================================================
# Path access validation
# =============================================================================


async def test_add_path_access_for_target_invalid_path_raises(policy_manager):
    with pytest.raises(PolicyOperationError):
        await policy_manager.add_path_access_for_target(
            PolicyTarget.USER, "alice", "invalid-path", PolicyPermissionLevel.READ
        )


async def test_add_path_access_for_target_path_traversal_raises(policy_manager):
    with pytest.raises(PolicyOperationError):
        await policy_manager.add_path_access_for_target(
            PolicyTarget.USER,
            "alice",
            "s3a://test-bucket/../etc/passwd",
            PolicyPermissionLevel.READ,
        )


async def test_add_then_remove_path_access_roundtrip(
    policy_manager, mock_iam_client, user_home_policy_doc
):
    path = "s3a://test-bucket/users-general-warehouse/alice/shared-dir/"
    mock_iam_client.get_user_policy.return_value = user_home_policy_doc

    await policy_manager.add_path_access_for_target(
        PolicyTarget.USER, "alice", path, PolicyPermissionLevel.READ
    )
    after_add_doc = mock_iam_client.set_user_policy.call_args.args[2]

    mock_iam_client.get_user_policy.return_value = after_add_doc
    mock_iam_client.set_user_policy.reset_mock()
    await policy_manager.remove_path_access_for_target(PolicyTarget.USER, "alice", path)
    after_remove_doc = mock_iam_client.set_user_policy.call_args.args[2]

    result = PolicyDocument.from_dict(after_remove_doc)
    assert not any(
        "shared-dir" in s.resource
        for s in result.statement
        if isinstance(s.resource, str)
    )


# =============================================================================
# PolicyBuilder exception wrapping
# =============================================================================


async def test_add_path_access_for_target_builder_exception_wraps(policy_manager):
    with patch("s3.managers.policy_manager.PolicyBuilder") as mock_builder_cls:
        mock_builder_cls.return_value.add_path_access.side_effect = RuntimeError("boom")
        with pytest.raises(PolicyOperationError, match="Failed to add path access"):
            await policy_manager.add_path_access_for_target(
                PolicyTarget.USER,
                "alice",
                "s3a://test-bucket/users-general-warehouse/alice/data/",
                PolicyPermissionLevel.READ,
            )


async def test_remove_path_access_for_target_builder_exception_wraps(policy_manager):
    with patch("s3.managers.policy_manager.PolicyBuilder") as mock_builder_cls:
        mock_builder_cls.return_value.remove_path_access.side_effect = RuntimeError(
            "boom"
        )
        with pytest.raises(PolicyOperationError, match="Failed to remove path access"):
            await policy_manager.remove_path_access_for_target(
                PolicyTarget.USER,
                "alice",
                "s3a://test-bucket/users-general-warehouse/alice/",
            )


# =============================================================================
# Unsupported target type
# =============================================================================


async def test_path_access_for_unsupported_target_raises(policy_manager):
    bad_target = MagicMock(spec=PolicyTarget, value="bad")
    with pytest.raises(PolicyOperationError, match="Unsupported"):
        await policy_manager.add_path_access_for_target(
            bad_target,
            "alice",
            "s3a://test-bucket/users-general-warehouse/alice/",
            PolicyPermissionLevel.READ,
        )


# =============================================================================
# PolicyCreator exception wrapping
# =============================================================================


async def test_policy_creation_wraps_exception(policy_manager):
    with patch("s3.managers.policy_manager.PolicyCreator") as mock_creator_cls:
        mock_creator_cls.return_value.create_default_policy.side_effect = RuntimeError(
            "fail"
        )
        with pytest.raises(PolicyOperationError, match="Failed to create"):
            await policy_manager.regenerate_user_home_policy("alice")
