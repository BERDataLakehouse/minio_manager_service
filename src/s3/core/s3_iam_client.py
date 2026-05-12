"""Async IAM client for S3-compatible services (CEPH RadosGW) using aiobotocore."""

import json
import logging
from typing import Any, NamedTuple, Self
from urllib.parse import unquote

import aiobotocore.session
from botocore.exceptions import ClientError

from s3.exceptions import IamGroupNotFoundError, IamPolicyNotFoundError

logger = logging.getLogger(__name__)


class IamUserInfo(NamedTuple):
    """Name and IAM path of a user."""

    username: str
    path: str


class IamGroupInfo(NamedTuple):
    """Name and IAM path of a group."""

    group_name: str
    path: str


def _parse_policy(doc: str | dict) -> dict:
    """Parse a policy document returned by IAM, handling both URL-encoded strings
    (AWS) and pre-parsed dicts (CEPH)."""
    if isinstance(doc, dict):
        return doc
    return json.loads(unquote(doc))


class S3IAMClient:
    """
    Async client for managing IAM users and groups on an S3-compatible service.

    All users and groups are created under the configured path prefix, which can
    be used to distinguish service-managed accounts from others.

    Usage:
        async with S3IAMClient(endpoint, access_key, secret_key, "/myservice/") as client:
            await client.create_user("alice")
    """

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        path_prefix: str = "/",
        max_keys: int = 2,
        region_name: str = "default",
    ):
        """
        endpoint_url: the URL of the S3-compatible IAM endpoint.
        access_key: the access key ID for authentication.
        secret_key: the secret access key for authentication.
        path_prefix: IAM path prefix applied to all created users and groups,
            used to distinguish service-managed accounts from others. Defaults to "/".
        max_keys: maximum number of access keys allowed per user (active + inactive).
            Defaults to 2, matching the AWS IAM limit. See:
            https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
        region_name: AWS region name. Ignored by MinIO and Ceph but required by the
            boto3 client. Defaults to "default".
        """
        if max_keys < 2:  # note CEPH allows 4
            raise ValueError(f"max_keys must be at least 2, got {max_keys}")
        if not path_prefix.startswith("/"):
            path_prefix = "/" + path_prefix
        if not path_prefix.endswith("/"):
            path_prefix = path_prefix + "/"
        self._endpoint_url = endpoint_url
        self._access_key = access_key
        self._secret_key = secret_key
        self._path_prefix = path_prefix
        self._max_keys = max_keys
        self._region_name = region_name
        self._client = None
        self._context = None

    @classmethod
    async def create(
        cls,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        path_prefix: str = "/",
        max_keys: int = 2,
        region_name: str = "default",
    ) -> Self:
        """
        Construct and connect the client without using a context manager.
        Arguments are identical to __init__. Call close() when done.
        """
        self = cls(
            endpoint_url, access_key, secret_key, path_prefix, max_keys, region_name
        )
        await self._open()
        return self

    async def _open(self) -> None:
        session = aiobotocore.session.get_session()
        self._context = session.create_client(
            "iam",
            endpoint_url=self._endpoint_url,
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            region_name=self._region_name,
        )
        self._client = await self._context.__aenter__()
        # validate connectivity and credentials at startup so the server fails fast
        try:
            await self._client.get_user()
        except Exception:
            await self._context.__aexit__(None, None, None)
            raise

    async def close(self) -> None:
        """Close the underlying connection. Use when not using a context manager."""
        await self._context.__aexit__(None, None, None)

    async def __aenter__(self) -> Self:
        await self._open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # ── Users ────────────────────────────────────────────────────────────────

    async def create_user(self, username: str, exists_ok: bool = False) -> None:
        """
        Create an IAM user under the configured path prefix.

        exists_ok: if True, silently succeed if the user already exists.
        """
        try:
            await self._client.create_user(UserName=username, Path=self._path_prefix)
        except ClientError as e:
            if exists_ok and e.response["Error"]["Code"] == "EntityAlreadyExists":
                return
            raise
        logger.info("Created IAM user: %s", username)

    async def delete_user(self, username: str) -> None:
        """
        Delete an IAM user, first removing all group memberships, inline policies,
        and access keys, which IAM requires to be absent before the user can be deleted.
        """
        paginator = self._client.get_paginator("list_groups_for_user")
        async for page in paginator.paginate(UserName=username):
            for group in page["Groups"]:
                await self._client.remove_user_from_group(
                    UserName=username, GroupName=group["GroupName"]
                )

        paginator = self._client.get_paginator("list_user_policies")
        async for page in paginator.paginate(UserName=username):
            for policy_name in page["PolicyNames"]:
                await self._client.delete_user_policy(
                    UserName=username, PolicyName=policy_name
                )

        resp = await self._client.list_access_keys(UserName=username)
        for key in resp["AccessKeyMetadata"]:
            await self._delete_access_key(username, key["AccessKeyId"])

        await self._client.delete_user(UserName=username)
        logger.info("Deleted IAM user: %s", username)

    async def user_exists(self, username: str) -> bool:
        """Return True if the IAM user exists, False otherwise."""
        try:
            await self._client.get_user(UserName=username)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    async def get_user(self, username: str) -> IamUserInfo:
        """Return the name and IAM path of a user. Raises ClientError if not found."""
        resp = await self._client.get_user(UserName=username)
        user = resp["User"]
        return IamUserInfo(username=user["UserName"], path=user["Path"])

    async def list_users(self) -> list[str]:
        """Return the usernames of all IAM users under the configured path prefix."""
        users = []
        paginator = self._client.get_paginator("list_users")
        async for page in paginator.paginate(PathPrefix=self._path_prefix):
            users.extend(u["UserName"] for u in page["Users"])
        logger.debug("Listed %d IAM users under path %s", len(users), self._path_prefix)
        return users

    # ── Groups ───────────────────────────────────────────────────────────────

    async def create_group(self, group_name: str, exists_ok: bool = False) -> None:
        """
        Create an IAM group under the configured path prefix.

        exists_ok: if True, silently succeed if the group already exists.
        """
        try:
            await self._client.create_group(
                GroupName=group_name, Path=self._path_prefix
            )
        except ClientError as e:
            if exists_ok and e.response["Error"]["Code"] == "EntityAlreadyExists":
                return
            raise
        logger.info("Created IAM group: %s", group_name)

    async def delete_group(self, group_name: str) -> None:
        """
        Delete an IAM group, first removing all users and inline policies,
        which IAM requires to be absent before the group can be deleted.
        """
        paginator = self._client.get_paginator("get_group")
        async for page in paginator.paginate(GroupName=group_name):
            for user in page["Users"]:
                await self._client.remove_user_from_group(
                    UserName=user["UserName"], GroupName=group_name
                )

        paginator = self._client.get_paginator("list_group_policies")
        async for page in paginator.paginate(GroupName=group_name):
            for policy_name in page["PolicyNames"]:
                await self._client.delete_group_policy(
                    GroupName=group_name, PolicyName=policy_name
                )

        await self._client.delete_group(GroupName=group_name)
        logger.info("Deleted IAM group: %s", group_name)

    async def group_exists(self, group_name: str) -> bool:
        """Return True if the IAM group exists, False otherwise."""
        try:
            await self._client.get_group(GroupName=group_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    async def get_group(self, group_name: str) -> IamGroupInfo:
        """Return the name and IAM path of a group. Raises ClientError if not found."""
        resp = await self._client.get_group(GroupName=group_name)
        group = resp["Group"]
        return IamGroupInfo(group_name=group["GroupName"], path=group["Path"])

    async def list_groups(self) -> list[str]:
        """Return the names of all IAM groups under the configured path prefix."""
        groups = []
        paginator = self._client.get_paginator("list_groups")
        async for page in paginator.paginate(PathPrefix=self._path_prefix):
            groups.extend(g["GroupName"] for g in page["Groups"])
        logger.debug(
            "Listed %d IAM groups under path %s", len(groups), self._path_prefix
        )
        return groups

    async def add_user_to_group(self, username: str, group_name: str) -> None:
        """Add a user to a group."""
        await self._client.add_user_to_group(UserName=username, GroupName=group_name)
        logger.info("Added user %s to group %s", username, group_name)

    async def remove_user_from_group(self, username: str, group_name: str) -> None:
        """Remove a user from a group."""
        await self._client.remove_user_from_group(
            UserName=username, GroupName=group_name
        )
        logger.info("Removed user %s from group %s", username, group_name)

    async def list_users_in_group(self, group_name: str) -> list[str]:
        """Return the usernames of all users in a group.

        Raises:
            IamGroupNotFoundError: if the group does not exist.
        """
        try:
            users = []
            paginator = self._client.get_paginator("get_group")
            async for page in paginator.paginate(GroupName=group_name):
                users.extend(u["UserName"] for u in page["Users"])
            return users
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                raise IamGroupNotFoundError(group_name) from e
            raise

    async def list_groups_for_user(self, username: str) -> list[str]:
        """Return the names of all groups the user belongs to."""
        groups = []
        paginator = self._client.get_paginator("list_groups_for_user")
        async for page in paginator.paginate(UserName=username):
            groups.extend(g["GroupName"] for g in page["Groups"])
        return groups

    # ── Policies ─────────────────────────────────────────────────────────────

    async def get_user_policy(
        self,
        username: str,
        policy_name: str,
        except_if_absent: bool = True,
    ) -> dict[str, Any] | None:
        """
        Return the named inline policy document for a user.

        username: the IAM username.
        policy_name: the name of the inline policy to retrieve.
        except_if_absent: if False, return None when the policy does not exist
            instead of raising. Defaults to True (raises on absence).
        """
        try:
            resp = await self._client.get_user_policy(
                UserName=username, PolicyName=policy_name
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                if not except_if_absent:
                    return None
                raise IamPolicyNotFoundError(
                    f"Policy '{policy_name}' not found for user '{username}'"
                ) from e
            raise
        return _parse_policy(resp["PolicyDocument"])

    async def set_user_policy(
        self, username: str, policy_name: str, policy: dict[str, Any]
    ) -> None:
        """
        Set the named inline policy document for a user.

        username: the IAM username.
        policy_name: the name of the inline policy to create or replace.
        policy: the policy document as a dict.
        """
        await self._client.put_user_policy(
            UserName=username,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy),
        )
        logger.debug("Set inline policy '%s' for user %s", policy_name, username)

    async def get_group_policy(
        self,
        group_name: str,
        policy_name: str,
        except_if_absent: bool = True,
    ) -> dict[str, Any] | None:
        """
        Return the named inline policy document for a group.

        group_name: the IAM group name.
        policy_name: the name of the inline policy to retrieve.
        except_if_absent: if False, return None when the policy does not exist
            instead of raising. Defaults to True (raises on absence).
        """
        try:
            resp = await self._client.get_group_policy(
                GroupName=group_name, PolicyName=policy_name
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                if not except_if_absent:
                    return None
                raise IamPolicyNotFoundError(
                    f"Policy '{policy_name}' not found for group '{group_name}'"
                ) from e
            raise
        return _parse_policy(resp["PolicyDocument"])

    async def set_group_policy(
        self, group_name: str, policy_name: str, policy: dict[str, Any]
    ) -> None:
        """
        Set the named inline policy document for a group.

        group_name: the IAM group name.
        policy_name: the name of the inline policy to create or replace.
        policy: the policy document as a dict.
        """
        await self._client.put_group_policy(
            GroupName=group_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy),
        )
        logger.debug("Set inline policy '%s' for group %s", policy_name, group_name)

    # ── Access keys ──────────────────────────────────────────────────────────

    async def list_access_key_ids(self, username: str) -> list[str]:
        """Return the active access key IDs for a user, most recently created first."""
        resp = await self._client.list_access_keys(UserName=username)
        keys = [k for k in resp["AccessKeyMetadata"] if k["Status"] == "Active"]
        keys.sort(key=lambda k: k["CreateDate"], reverse=True)
        return [k["AccessKeyId"] for k in keys]

    async def _delete_access_key(self, username: str, key_id: str) -> None:
        # make it a noop if the key doesn't exist
        try:
            await self._client.delete_access_key(UserName=username, AccessKeyId=key_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    async def rotate_access_key(self, username: str) -> tuple[str, str]:
        """
        Create a new access key for the user, inactivate all other active keys,
        and delete the oldest keys beyond max_keys.

        Can be called on a new user with no keys to generate their first key,
        or on an existing user to rotate their key.

        Returns (access_key_id, secret_access_key). The secret is only available
        at creation time and cannot be retrieved again.
        """
        # Optimistic create: try to create the key, and if the server rejects it due to
        # hitting the key limit, delete the oldest existing key and retry. This avoids
        # the pre-check race condition (another process creating a key between our list
        # and create calls). The residual race — two processes repeatedly deleting each
        # other's keys in perfect lockstep — is theoretically possible but vanishingly
        # unlikely in practice.
        while True:
            try:
                resp = await self._client.create_access_key(UserName=username)
                break
            except ClientError as e:
                if e.response["Error"]["Code"] != "LimitExceeded":
                    raise
                logger.warning(
                    f"Access key limit reached for user {username}; "
                    + "deleting oldest key to make room"
                )
                list_resp = await self._client.list_access_keys(UserName=username)
                existing = list_resp["AccessKeyMetadata"]
                oldest = min(existing, key=lambda k: k["CreateDate"])
                await self._delete_access_key(username, oldest["AccessKeyId"])

        new_key = resp["AccessKey"]
        new_key_id = new_key["AccessKeyId"]

        list_resp = await self._client.list_access_keys(UserName=username)
        existing = [
            k for k in list_resp["AccessKeyMetadata"] if k["AccessKeyId"] != new_key_id
        ]

        for key in existing:
            if key["Status"] != "Inactive":
                await self._client.update_access_key(
                    UserName=username, AccessKeyId=key["AccessKeyId"], Status="Inactive"
                )

        existing.sort(key=lambda k: k["CreateDate"])
        for key in existing[: max(0, len(existing) - (self._max_keys - 1))]:
            await self._delete_access_key(username, key["AccessKeyId"])

        logger.info("Rotated access key for user %s", username)
        return new_key_id, new_key["SecretAccessKey"]
