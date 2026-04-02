"""
Tests for S3IAMClient — async IAM client for Ceph RadosGW / S3-compatible services.

Tests use a mock aiobotocore IAM client injected directly into the client instance,
following the same pattern as test_s3_client.py.
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import quote

import pytest
from botocore.exceptions import ClientError

from src.s3.core.s3_iam_client import S3IAMClient, _parse_policy


# =============================================================================
# Helpers
# =============================================================================


class AsyncIteratorMock:
    """Mock async iterator for paginator testing."""

    def __init__(self, items):
        self.items = items.copy()

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.items:
            raise StopAsyncIteration
        return self.items.pop(0)


def make_paginator(pages: list) -> MagicMock:
    """Build a mock paginator that yields the given pages."""
    paginator = MagicMock()
    paginator.paginate = MagicMock(return_value=AsyncIteratorMock(pages))
    return paginator


def no_such_entity(operation: str = "op") -> ClientError:
    return ClientError(
        {"Error": {"Code": "NoSuchEntity", "Message": "not found"}}, operation
    )


def limit_exceeded(operation: str = "CreateAccessKey") -> ClientError:
    return ClientError(
        {"Error": {"Code": "LimitExceeded", "Message": "limit"}}, operation
    )


def entity_already_exists(operation: str = "op") -> ClientError:
    return ClientError(
        {"Error": {"Code": "EntityAlreadyExists", "Message": "already exists"}},
        operation,
    )


def other_error(operation: str = "op") -> ClientError:
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, operation
    )


def make_mock_session(get_user_side_effect=None):
    mock_inner = MagicMock()
    mock_inner.get_user = AsyncMock(
        return_value={"User": {}},
        side_effect=get_user_side_effect,
    )
    mock_context = MagicMock()
    mock_context.__aenter__ = AsyncMock(return_value=mock_inner)
    mock_context.__aexit__ = AsyncMock(return_value=None)
    mock_session = MagicMock()
    mock_session.create_client = MagicMock(return_value=mock_context)
    return mock_session, mock_context


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_iam_boto_client():
    """Raw mocked aiobotocore IAM client with sensible defaults."""
    client = MagicMock()
    client.create_user = AsyncMock()
    client.delete_user = AsyncMock()
    client.get_user = AsyncMock(return_value={"User": {"UserName": "testuser"}})
    client.create_group = AsyncMock()
    client.delete_group = AsyncMock()
    client.get_group = AsyncMock(
        return_value={"Group": {"GroupName": "testgroup"}, "Users": []}
    )
    client.add_user_to_group = AsyncMock()
    client.remove_user_from_group = AsyncMock()
    client.put_user_policy = AsyncMock()
    client.get_user_policy = AsyncMock(
        return_value={"PolicyDocument": {"Version": "2012-10-17", "Statement": []}}
    )
    client.delete_user_policy = AsyncMock()
    client.put_group_policy = AsyncMock()
    client.get_group_policy = AsyncMock(
        return_value={"PolicyDocument": {"Version": "2012-10-17", "Statement": []}}
    )
    client.delete_group_policy = AsyncMock()
    client.create_access_key = AsyncMock()
    client.delete_access_key = AsyncMock()
    client.list_access_keys = AsyncMock(return_value={"AccessKeyMetadata": []})
    client.update_access_key = AsyncMock()
    return client


@pytest.fixture
def iam_client(mock_iam_boto_client):
    """S3IAMClient with an injected mock aiobotocore client, bypassing _open."""
    mock_context = MagicMock()
    mock_context.__aexit__ = AsyncMock(return_value=None)

    client = S3IAMClient(
        endpoint_url="http://localhost:9000",
        access_key="admin",
        secret_key="secret",
        path_prefix="/mms/",
    )
    client._client = mock_iam_boto_client
    client._context = mock_context
    return client


# =============================================================================
# _parse_policy
# =============================================================================


def test_parse_policy_dict_passthrough():
    doc = {"Version": "2012-10-17", "Statement": []}
    assert _parse_policy(doc) is doc


def test_parse_policy_url_encoded_string():
    policy = {"Version": "2012-10-17", "Statement": []}
    assert _parse_policy(quote(json.dumps(policy))) == policy


def test_parse_policy_plain_json_string():
    policy = {"Version": "2012-10-17", "Statement": []}
    assert _parse_policy(json.dumps(policy)) == policy


# =============================================================================
# Initialisation
# =============================================================================


def test_defaults():
    client = S3IAMClient("http://localhost:9000", "key", "secret")
    assert client._path_prefix == "/"
    assert client._max_keys == 2
    assert client._region_name == "default"


def test_path_prefix_normalization_no_slashes():
    client = S3IAMClient("http://localhost:9000", "key", "secret", path_prefix="mms")
    assert client._path_prefix == "/mms/"


def test_path_prefix_normalization_leading_only():
    client = S3IAMClient("http://localhost:9000", "key", "secret", path_prefix="/mms")
    assert client._path_prefix == "/mms/"


def test_path_prefix_normalization_already_correct():
    client = S3IAMClient("http://localhost:9000", "key", "secret", path_prefix="/mms/")
    assert client._path_prefix == "/mms/"


def test_max_keys_too_low_raises():
    with pytest.raises(ValueError, match="max_keys must be at least 2"):
        S3IAMClient("http://localhost:9000", "key", "secret", max_keys=1)


def test_custom_region_name():
    client = S3IAMClient(
        "http://localhost:9000", "key", "secret", region_name="us-west-2"
    )
    assert client._region_name == "us-west-2"


@pytest.mark.asyncio
async def test_create_factory():
    mock_session, _ = make_mock_session()
    with patch("aiobotocore.session.get_session", return_value=mock_session):
        client = await S3IAMClient.create("http://localhost:9000", "key", "secret")
        assert client._client is not None


@pytest.mark.asyncio
async def test_create_factory_raises_on_bad_credentials():
    mock_session, mock_context = make_mock_session(
        get_user_side_effect=other_error("GetUser")
    )
    with patch("aiobotocore.session.get_session", return_value=mock_session):
        with pytest.raises(ClientError):
            await S3IAMClient.create("http://localhost:9000", "key", "wrong_secret")
    mock_context.__aexit__.assert_called_once_with(None, None, None)


@pytest.mark.asyncio
async def test_context_manager():
    mock_session, mock_context = make_mock_session()
    with patch("aiobotocore.session.get_session", return_value=mock_session):
        async with S3IAMClient("http://localhost:9000", "key", "secret") as client:
            assert client._client is not None

    mock_context.__aexit__.assert_called_once_with(None, None, None)


@pytest.mark.asyncio
async def test_region_name_passed_to_boto():
    mock_session, _ = make_mock_session()
    with patch("aiobotocore.session.get_session", return_value=mock_session):
        await S3IAMClient.create(
            "http://localhost:9000", "key", "secret", region_name="eu-west-1"
        )

    mock_session.create_client.assert_called_once_with(
        "iam",
        endpoint_url="http://localhost:9000",
        aws_access_key_id="key",
        aws_secret_access_key="secret",
        region_name="eu-west-1",
    )


# =============================================================================
# Users
# =============================================================================


@pytest.mark.asyncio
async def test_create_user(iam_client, mock_iam_boto_client):
    await iam_client.create_user("alice")
    mock_iam_boto_client.create_user.assert_called_once_with(
        UserName="alice", Path="/mms/"
    )


@pytest.mark.asyncio
async def test_create_user_exists_ok_suppresses_already_exists(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.create_user = AsyncMock(
        side_effect=entity_already_exists("CreateUser")
    )
    await iam_client.create_user("alice", exists_ok=True)  # should not raise


@pytest.mark.asyncio
async def test_create_user_exists_ok_false_raises_already_exists(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.create_user = AsyncMock(
        side_effect=entity_already_exists("CreateUser")
    )
    with pytest.raises(ClientError):
        await iam_client.create_user("alice", exists_ok=False)


@pytest.mark.asyncio
async def test_create_user_exists_ok_other_error_reraises(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.create_user = AsyncMock(side_effect=other_error("CreateUser"))
    with pytest.raises(ClientError):
        await iam_client.create_user("alice", exists_ok=True)


@pytest.mark.asyncio
async def test_delete_user_cleans_up_groups_policies_and_keys(
    iam_client, mock_iam_boto_client
):
    """delete_user removes group memberships, inline policies, and access keys first."""
    mock_iam_boto_client.get_paginator = MagicMock(
        side_effect=lambda name: {
            "list_groups_for_user": make_paginator(
                [{"Groups": [{"GroupName": "g1"}, {"GroupName": "g2"}]}]
            ),
            "list_user_policies": make_paginator([{"PolicyNames": ["home", "system"]}]),
        }[name]
    )
    mock_iam_boto_client.list_access_keys = AsyncMock(
        return_value={"AccessKeyMetadata": [{"AccessKeyId": "KEYID1"}]}
    )

    await iam_client.delete_user("alice")

    assert mock_iam_boto_client.remove_user_from_group.call_count == 2
    assert mock_iam_boto_client.delete_user_policy.call_count == 2
    mock_iam_boto_client.delete_access_key.assert_called_once_with(
        UserName="alice", AccessKeyId="KEYID1"
    )
    mock_iam_boto_client.delete_user.assert_called_once_with(UserName="alice")


@pytest.mark.asyncio
async def test_delete_user_no_memberships_or_policies(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_paginator = MagicMock(
        side_effect=lambda name: {
            "list_groups_for_user": make_paginator([{"Groups": []}]),
            "list_user_policies": make_paginator([{"PolicyNames": []}]),
        }[name]
    )

    await iam_client.delete_user("alice")

    mock_iam_boto_client.remove_user_from_group.assert_not_called()
    mock_iam_boto_client.delete_user_policy.assert_not_called()
    mock_iam_boto_client.delete_user.assert_called_once_with(UserName="alice")


@pytest.mark.asyncio
async def test_user_exists_true(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_user = AsyncMock(
        return_value={"User": {"UserName": "alice"}}
    )
    assert await iam_client.user_exists("alice") is True


@pytest.mark.asyncio
async def test_user_exists_false(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_user = AsyncMock(side_effect=no_such_entity("GetUser"))
    assert await iam_client.user_exists("alice") is False


@pytest.mark.asyncio
async def test_user_exists_other_error_reraises(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_user = AsyncMock(side_effect=other_error("GetUser"))
    with pytest.raises(ClientError):
        await iam_client.user_exists("alice")


@pytest.mark.asyncio
async def test_list_users(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_paginator = MagicMock(
        return_value=make_paginator(
            [
                {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]},
                {"Users": [{"UserName": "carol"}]},
            ]
        )
    )
    result = await iam_client.list_users()
    assert result == ["alice", "bob", "carol"]
    mock_iam_boto_client.get_paginator.return_value.paginate.assert_called_once_with(
        PathPrefix="/mms/"
    )


@pytest.mark.asyncio
async def test_list_users_empty(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_paginator = MagicMock(
        return_value=make_paginator([{"Users": []}])
    )
    assert await iam_client.list_users() == []


# =============================================================================
# Groups
# =============================================================================


@pytest.mark.asyncio
async def test_create_group(iam_client, mock_iam_boto_client):
    await iam_client.create_group("researchers")
    mock_iam_boto_client.create_group.assert_called_once_with(
        GroupName="researchers", Path="/mms/"
    )


@pytest.mark.asyncio
async def test_create_group_exists_ok_suppresses_already_exists(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.create_group = AsyncMock(
        side_effect=entity_already_exists("CreateGroup")
    )
    await iam_client.create_group("researchers", exists_ok=True)  # should not raise


@pytest.mark.asyncio
async def test_create_group_exists_ok_false_raises_already_exists(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.create_group = AsyncMock(
        side_effect=entity_already_exists("CreateGroup")
    )
    with pytest.raises(ClientError):
        await iam_client.create_group("researchers", exists_ok=False)


@pytest.mark.asyncio
async def test_create_group_exists_ok_other_error_reraises(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.create_group = AsyncMock(
        side_effect=other_error("CreateGroup")
    )
    with pytest.raises(ClientError):
        await iam_client.create_group("researchers", exists_ok=True)


@pytest.mark.asyncio
async def test_delete_group_cleans_up_members_and_policies(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.get_paginator = MagicMock(
        side_effect=lambda name: {
            "get_group": make_paginator(
                [{"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}]
            ),
            "list_group_policies": make_paginator([{"PolicyNames": ["group"]}]),
        }[name]
    )

    await iam_client.delete_group("researchers")

    assert mock_iam_boto_client.remove_user_from_group.call_count == 2
    mock_iam_boto_client.delete_group_policy.assert_called_once_with(
        GroupName="researchers", PolicyName="group"
    )
    mock_iam_boto_client.delete_group.assert_called_once_with(GroupName="researchers")


@pytest.mark.asyncio
async def test_group_exists_true(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_group = AsyncMock(
        return_value={"Group": {"GroupName": "researchers"}, "Users": []}
    )
    assert await iam_client.group_exists("researchers") is True


@pytest.mark.asyncio
async def test_group_exists_false(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_group = AsyncMock(side_effect=no_such_entity("GetGroup"))
    assert await iam_client.group_exists("researchers") is False


@pytest.mark.asyncio
async def test_group_exists_other_error_reraises(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_group = AsyncMock(side_effect=other_error("GetGroup"))
    with pytest.raises(ClientError):
        await iam_client.group_exists("researchers")


@pytest.mark.asyncio
async def test_list_groups(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_paginator = MagicMock(
        return_value=make_paginator(
            [{"Groups": [{"GroupName": "alpha"}, {"GroupName": "beta"}]}]
        )
    )
    result = await iam_client.list_groups()
    assert result == ["alpha", "beta"]
    mock_iam_boto_client.get_paginator.return_value.paginate.assert_called_once_with(
        PathPrefix="/mms/"
    )


@pytest.mark.asyncio
async def test_add_user_to_group(iam_client, mock_iam_boto_client):
    await iam_client.add_user_to_group("alice", "researchers")
    mock_iam_boto_client.add_user_to_group.assert_called_once_with(
        UserName="alice", GroupName="researchers"
    )


@pytest.mark.asyncio
async def test_remove_user_from_group(iam_client, mock_iam_boto_client):
    await iam_client.remove_user_from_group("alice", "researchers")
    mock_iam_boto_client.remove_user_from_group.assert_called_once_with(
        UserName="alice", GroupName="researchers"
    )


@pytest.mark.asyncio
async def test_list_users_in_group(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_paginator = MagicMock(
        return_value=make_paginator(
            [{"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}]
        )
    )
    result = await iam_client.list_users_in_group("researchers")
    assert result == ["alice", "bob"]


@pytest.mark.asyncio
async def test_list_groups_for_user(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.get_paginator = MagicMock(
        return_value=make_paginator(
            [{"Groups": [{"GroupName": "alpha"}, {"GroupName": "beta"}]}]
        )
    )
    result = await iam_client.list_groups_for_user("alice")
    assert result == ["alpha", "beta"]
    mock_iam_boto_client.get_paginator.return_value.paginate.assert_called_once_with(
        UserName="alice"
    )


# =============================================================================
# Policies
# =============================================================================


@pytest.mark.asyncio
async def test_get_user_policy_dict(iam_client, mock_iam_boto_client):
    """Ceph returns pre-parsed dicts."""
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}
    mock_iam_boto_client.get_user_policy = AsyncMock(
        return_value={"PolicyDocument": policy}
    )
    result = await iam_client.get_user_policy("alice", "home")
    assert result == policy


@pytest.mark.asyncio
async def test_get_user_policy_url_encoded(iam_client, mock_iam_boto_client):
    """AWS returns URL-encoded JSON strings."""
    policy = {"Version": "2012-10-17", "Statement": []}
    mock_iam_boto_client.get_user_policy = AsyncMock(
        return_value={"PolicyDocument": quote(json.dumps(policy))}
    )
    result = await iam_client.get_user_policy("alice", "home")
    assert result == policy


@pytest.mark.asyncio
async def test_get_user_policy_absent_except_if_absent_true_raises(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.get_user_policy = AsyncMock(
        side_effect=no_such_entity("GetUserPolicy")
    )
    with pytest.raises(ClientError):
        await iam_client.get_user_policy("alice", "home", except_if_absent=True)


@pytest.mark.asyncio
async def test_get_user_policy_absent_except_if_absent_false_returns_none(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.get_user_policy = AsyncMock(
        side_effect=no_such_entity("GetUserPolicy")
    )
    result = await iam_client.get_user_policy("alice", "home", except_if_absent=False)
    assert result is None


@pytest.mark.asyncio
async def test_get_user_policy_absent_other_error_always_reraises(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.get_user_policy = AsyncMock(
        side_effect=other_error("GetUserPolicy")
    )
    with pytest.raises(ClientError):
        await iam_client.get_user_policy("alice", "home", except_if_absent=False)


@pytest.mark.asyncio
async def test_set_user_policy(iam_client, mock_iam_boto_client):
    policy = {"Version": "2012-10-17", "Statement": []}
    await iam_client.set_user_policy("alice", "home", policy)
    mock_iam_boto_client.put_user_policy.assert_called_once_with(
        UserName="alice",
        PolicyName="home",
        PolicyDocument=json.dumps(policy),
    )


@pytest.mark.asyncio
async def test_get_group_policy(iam_client, mock_iam_boto_client):
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}
    mock_iam_boto_client.get_group_policy = AsyncMock(
        return_value={"PolicyDocument": policy}
    )
    result = await iam_client.get_group_policy("researchers", "group")
    assert result == policy


@pytest.mark.asyncio
async def test_get_group_policy_absent_except_if_absent_true_raises(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.get_group_policy = AsyncMock(
        side_effect=no_such_entity("GetGroupPolicy")
    )
    with pytest.raises(ClientError):
        await iam_client.get_group_policy("researchers", "group", except_if_absent=True)


@pytest.mark.asyncio
async def test_get_group_policy_absent_except_if_absent_false_returns_none(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.get_group_policy = AsyncMock(
        side_effect=no_such_entity("GetGroupPolicy")
    )
    result = await iam_client.get_group_policy(
        "researchers", "group", except_if_absent=False
    )
    assert result is None


@pytest.mark.asyncio
async def test_get_group_policy_absent_other_error_always_reraises(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.get_group_policy = AsyncMock(
        side_effect=other_error("GetGroupPolicy")
    )
    with pytest.raises(ClientError):
        await iam_client.get_group_policy(
            "researchers", "group", except_if_absent=False
        )


@pytest.mark.asyncio
async def test_set_group_policy(iam_client, mock_iam_boto_client):
    policy = {"Version": "2012-10-17", "Statement": []}
    await iam_client.set_group_policy("researchers", "group", policy)
    mock_iam_boto_client.put_group_policy.assert_called_once_with(
        GroupName="researchers",
        PolicyName="group",
        PolicyDocument=json.dumps(policy),
    )


# =============================================================================
# Access keys
# =============================================================================


@pytest.mark.asyncio
async def test_rotate_access_key_no_existing_keys(iam_client, mock_iam_boto_client):
    """First key creation for a new user — no cleanup needed."""
    now = datetime.now(timezone.utc)
    mock_iam_boto_client.create_access_key = AsyncMock(
        return_value={
            "AccessKey": {"AccessKeyId": "NEW123", "SecretAccessKey": "newsecret"}
        }
    )
    mock_iam_boto_client.list_access_keys = AsyncMock(
        return_value={
            "AccessKeyMetadata": [
                {"AccessKeyId": "NEW123", "Status": "Active", "CreateDate": now}
            ]
        }
    )

    key_id, secret = await iam_client.rotate_access_key("alice")

    assert key_id == "NEW123"
    assert secret == "newsecret"
    mock_iam_boto_client.update_access_key.assert_not_called()
    mock_iam_boto_client.delete_access_key.assert_not_called()


@pytest.mark.asyncio
async def test_rotate_access_key_inactivates_existing_active_key(
    iam_client, mock_iam_boto_client
):
    """Existing active key is inactivated after new key is created."""
    now = datetime.now(timezone.utc)
    old_key = {
        "AccessKeyId": "OLD123",
        "Status": "Active",
        "CreateDate": now - timedelta(days=30),
    }
    mock_iam_boto_client.create_access_key = AsyncMock(
        return_value={
            "AccessKey": {"AccessKeyId": "NEW123", "SecretAccessKey": "newsecret"}
        }
    )
    mock_iam_boto_client.list_access_keys = AsyncMock(
        return_value={
            "AccessKeyMetadata": [
                old_key,
                {"AccessKeyId": "NEW123", "Status": "Active", "CreateDate": now},
            ]
        }
    )

    await iam_client.rotate_access_key("alice")

    mock_iam_boto_client.update_access_key.assert_called_once_with(
        UserName="alice", AccessKeyId="OLD123", Status="Inactive"
    )


@pytest.mark.asyncio
async def test_rotate_access_key_at_limit_deletes_oldest_and_retries(
    iam_client, mock_iam_boto_client
):
    """When at the key limit, delete the oldest key and retry creation."""
    now = datetime.now(timezone.utc)
    old_key = {
        "AccessKeyId": "OLD123",
        "Status": "Active",
        "CreateDate": now - timedelta(days=30),
    }
    mock_iam_boto_client.create_access_key = AsyncMock(
        side_effect=[
            limit_exceeded(),
            {
                "AccessKey": {
                    "AccessKeyId": "NEW123",
                    "SecretAccessKey": "newsecret",
                }
            },
        ]
    )
    # First list_access_keys call: inside the except block to find oldest
    # Second call: after successful create, to find keys to inactivate/delete
    mock_iam_boto_client.list_access_keys = AsyncMock(
        side_effect=[
            {"AccessKeyMetadata": [old_key]},
            {
                "AccessKeyMetadata": [
                    {"AccessKeyId": "NEW123", "Status": "Active", "CreateDate": now}
                ]
            },
        ]
    )

    key_id, _ = await iam_client.rotate_access_key("alice")

    assert key_id == "NEW123"
    # Should have deleted the oldest key to make room
    mock_iam_boto_client.delete_access_key.assert_called_with(
        UserName="alice", AccessKeyId="OLD123"
    )


@pytest.mark.asyncio
async def test_rotate_access_key_trims_excess_old_keys(iam_client, mock_iam_boto_client):
    """Old keys beyond max_keys-1 are deleted after rotation (iam_client has max_keys=2)."""
    now = datetime.now(timezone.utc)
    older_key = {
        "AccessKeyId": "OLD1",
        "Status": "Active",
        "CreateDate": now - timedelta(days=60),
    }
    newer_key = {
        "AccessKeyId": "OLD2",
        "Status": "Active",
        "CreateDate": now - timedelta(days=30),
    }
    mock_iam_boto_client.create_access_key = AsyncMock(
        return_value={
            "AccessKey": {"AccessKeyId": "NEW123", "SecretAccessKey": "newsecret"}
        }
    )
    mock_iam_boto_client.list_access_keys = AsyncMock(
        return_value={
            "AccessKeyMetadata": [
                older_key,
                newer_key,
                {"AccessKeyId": "NEW123", "Status": "Active", "CreateDate": now},
            ]
        }
    )

    await iam_client.rotate_access_key("alice")

    # With max_keys=2, only 1 old key slot remains — oldest (OLD1) must be deleted
    mock_iam_boto_client.delete_access_key.assert_called_once_with(
        UserName="alice", AccessKeyId="OLD1"
    )


@pytest.mark.asyncio
async def test_rotate_access_key_non_limit_error_reraises(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.create_access_key = AsyncMock(
        side_effect=other_error("CreateAccessKey")
    )
    with pytest.raises(ClientError):
        await iam_client.rotate_access_key("alice")


@pytest.mark.asyncio
async def test_delete_access_key_no_such_entity_is_noop(
    iam_client, mock_iam_boto_client
):
    mock_iam_boto_client.delete_access_key = AsyncMock(
        side_effect=no_such_entity("DeleteAccessKey")
    )
    # Should not raise
    await iam_client._delete_access_key("alice", "KEYID1")


@pytest.mark.asyncio
async def test_delete_access_key_other_error_reraises(iam_client, mock_iam_boto_client):
    mock_iam_boto_client.delete_access_key = AsyncMock(
        side_effect=other_error("DeleteAccessKey")
    )
    with pytest.raises(ClientError):
        await iam_client._delete_access_key("alice", "KEYID1")
