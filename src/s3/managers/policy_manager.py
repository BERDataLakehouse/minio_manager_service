"""Policy manager for S3-compatible IAM (Ceph RadosGW)."""

import logging
from typing import Callable, Optional

from service.exceptions import PolicyOperationError
from s3.exceptions import IamPolicyNotFoundError
from s3.core.distributed_lock import DistributedLockManager
from s3.core.policy_builder import PolicyBuilder
from s3.core.policy_creator import PolicyCreator
from s3.core.s3_iam_client import S3IAMClient
from s3.models.policy import (
    PolicyDocument,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyTarget,
    PolicyType,
)
from s3.models.s3_config import S3Config

logger = logging.getLogger(__name__)

# Fixed names for inline IAM policies stored on each user/group object.
# these names are local to the user or group they belong to.
_USER_HOME_IAM_POLICY = "home"
_USER_SYSTEM_IAM_POLICY = "system"
_GROUP_IAM_POLICY = "group"


def _policy_to_dict(policy_model: PolicyModel) -> dict:
    """Serialize a PolicyModel to the dict form expected by the IAM client."""
    return policy_model.policy_document.to_dict()


class PolicyManager:
    """
    Policy manager for handliong S3 policies..

    Policies are stored as inline IAM policies directly on user and group
    objects

    Each user has two fixed inline policies:
      - "home"   — access to the user's personal S3 paths
      - "system" — access to system resources (logs, etc.)

    Each group has one inline policy:
      - "group"  — access to the group's shared S3 paths

    Path access modifications (add/remove) acquire a distributed lock to
    prevent lost updates from concurrent read-modify-write operations.
    """

    def __init__(
        self,
        iam_client: S3IAMClient,
        config: S3Config,
        lock_manager: Optional[DistributedLockManager] = None,
    ) -> None:
        """
        Initialize the PolicyManager.

        iam_client:   IAM client.
        config:       S3 configuration (bucket names, path prefixes, etc.).
        lock_manager: Distributed lock manager. Required for operations that
                      modify an existing policy's contents (add/remove path
                      access). Read-only operations do not need it.
        """
        self._iam_client = iam_client
        self._config = config
        self._lock_manager = lock_manager

    # ── Read-modify-write policy updates (under lock) ────────────────────────

    async def add_path_access_for_target(
        self,
        target_type: PolicyTarget,
        target_name: str,
        path: str,
        permission_level: PolicyPermissionLevel,
    ) -> None:
        """
        Grant path access to a target (user or group) using a safe read-modify-write.

        Acquires the distributed lock for the target's policy, reloads the
        latest policy while holding the lock, applies the change, and persists.

        target_type:      Whether to update a user or group policy.
        target_name:      Username or group name.
        path:             S3 path prefix to grant access to (e.g., "s3a://bucket/data/project/").
        permission_level: READ, WRITE, or ADMIN level access.
        """
        await self._update_policy_for_target_with_transform(
            target_type,
            target_name,
            lambda current: self._add_path_access_to_policy(
                current, path, permission_level
            ),
        )

    async def remove_path_access_for_target(
        self,
        target_type: PolicyTarget,
        target_name: str,
        path: str,
    ) -> None:
        """
        Revoke path access from a target (user or group) using a safe read-modify-write.

        Acquires the distributed lock for the target's policy, reloads the
        latest policy while holding the lock, applies the change, and persists.

        target_type: Whether to update a user or group policy.
        target_name: Username or group name.
        path:        S3 path prefix to revoke (e.g., "s3a://bucket/data/project/").
        """
        await self._update_policy_for_target_with_transform(
            target_type,
            target_name,
            lambda current: self._remove_path_access_from_policy(current, path),
        )

    async def _load_policy_for_target(
        self, target_type: PolicyTarget, target_name: str
    ) -> PolicyModel:
        """
        Load the current PolicyModel for a target from IAM.
        Note:
            - USER targets map to user home policy
            - GROUP targets map to group home policy
            - User System policy are not used for path access updates
        """
        if target_type == PolicyTarget.USER:
            return await self.get_user_home_policy(target_name)
        elif target_type == PolicyTarget.GROUP:
            return await self.get_group_policy(target_name)
        else:
            raise PolicyOperationError(
                f"Unsupported target type for path access update: {target_type}"
            )

    async def _store_policy_for_target(
        self, target_type: PolicyTarget, target_name: str, policy_model: PolicyModel
    ) -> None:
        """Persist a PolicyModel back to IAM for a target."""
        if target_type == PolicyTarget.USER:
            await self._iam_client.set_user_policy(
                target_name, _USER_HOME_IAM_POLICY, _policy_to_dict(policy_model)
            )
        elif target_type == PolicyTarget.GROUP:
            await self._iam_client.set_group_policy(
                target_name, _GROUP_IAM_POLICY, _policy_to_dict(policy_model)
            )
        else:
            raise PolicyOperationError(
                f"Unsupported target type for path access update: {target_type}"
            )

    async def _update_policy_for_target_with_transform(
        self,
        target_type: PolicyTarget,
        target_name: str,
        transform: Callable[[PolicyModel], PolicyModel],
    ) -> None:
        """
        Acquire the distributed lock for a target's policy, reload the latest
        policy document, apply the transformation, and persist.
        """
        if target_type == PolicyTarget.USER:
            lock_key = f"user-{target_name}"
        elif target_type == PolicyTarget.GROUP:
            lock_key = f"group-{target_name}"
        else:
            raise PolicyOperationError(
                f"Unsupported target type for path access update: {target_type}"
            )
        if not self._lock_manager:
            raise PolicyOperationError("Distributed lock manager not initialized")
        async with self._lock_manager.policy_update_lock(lock_key):
            # Re-load inside the lock for latest
            current = await self._load_policy_for_target(target_type, target_name)
            updated = transform(current)
            await self._store_policy_for_target(target_type, target_name, updated)

    # ── User/group policy management ─────────────────────────────────────────

    async def ensure_user_policies(
        self, username: str
    ) -> tuple[PolicyModel, PolicyModel]:
        """
        Ensure both home and system inline policies exist for a user.

        WARNING: This method is NOT ATOMIC. The existence of policies are checked in one
        operation and then updated if they do not exist in another operation. If another
        policy altering operation interleaves, any changes it makes will be lost.

        If a policy already exists it is returned as-is. If it doesn't exist
        it is created with default permissions. Safe to call multiple times.

        username: The user whose policies to ensure.
        """
        home_policy = await self._ensure_user_policy(
            username, PolicyType.USER_HOME, _USER_HOME_IAM_POLICY
        )
        system_policy = await self._ensure_user_policy(
            username, PolicyType.USER_SYSTEM, _USER_SYSTEM_IAM_POLICY
        )
        return home_policy, system_policy

    async def _ensure_user_policy(
        self, username: str, policy_type: PolicyType, iam_name: str
    ) -> PolicyModel:
        doc = await self._iam_client.get_user_policy(
            username, iam_name, except_if_absent=False
        )
        if doc is None:
            policy_model = self._create_policy_model(policy_type, username)
            await self._iam_client.set_user_policy(
                username, iam_name, _policy_to_dict(policy_model)
            )
            logger.info(f"Created {policy_type.value} policy for user {username}")
            return policy_model
        logger.info(f"User {policy_type.value} policy already exists for {username}")
        return PolicyModel(policy_document=PolicyDocument.from_dict(doc))

    def _create_policy_model(
        self,
        policy_type: PolicyType,
        target_name: str,
        path_target_name: str | None = None,
    ) -> PolicyModel:
        """Create a default PolicyModel for the given type and target."""
        try:
            built = (
                PolicyCreator(
                    policy_type=policy_type,
                    target_name=target_name,
                    config=self._config,
                    path_target_name=path_target_name,
                )
                .create_default_policy()
                .build()
            )
            return PolicyModel(policy_document=built.policy_document)
        except Exception as e:
            policy_desc = policy_type.value.replace("_", " ")
            logger.error(
                f"Failed to create {policy_desc} policy for {target_name}: {e}"
            )
            raise PolicyOperationError(
                f"Failed to create {policy_desc} policy for {target_name}: {e}"
            ) from e

    async def regenerate_user_home_policy(self, username: str) -> PolicyModel:
        """
        Unconditionally overwrite the user's home inline policy with a freshly
        generated default.

        Unlike ensure_user_policies(), this always writes — it is used during
        migrations to push new path statements (e.g. Iceberg paths) to all
        pre-existing users.

        username: The user whose home policy to regenerate.
        """
        fresh = self._create_policy_model(PolicyType.USER_HOME, username)
        await self._iam_client.set_user_policy(
            username, _USER_HOME_IAM_POLICY, _policy_to_dict(fresh)
        )
        logger.info(f"Regenerated user home policy for user {username}")
        return fresh

    async def regenerate_group_home_policy(
        self,
        group_name: str,
        read_only: bool = False,
        path_target: str | None = None,
    ) -> PolicyModel:
        """
        Unconditionally overwrite the group's inline policy with a freshly
        generated default.

        Unlike ensure_group_policy(), this always writes — it is used during
        migrations to push new path statements to all pre-existing groups.

        group_name:  Group name (and path if path_target is not given).
        read_only:   If True, generate a read-only policy (GROUP_HOME_RO).
        path_target: Override the name used for S3 path generation; useful for
                     RO shadow groups whose paths should point at the base group.
        """
        policy_type = PolicyType.GROUP_HOME_RO if read_only else PolicyType.GROUP_HOME
        fresh = self._create_policy_model(
            policy_type, group_name, path_target_name=path_target
        )
        await self._iam_client.set_group_policy(
            group_name, _GROUP_IAM_POLICY, _policy_to_dict(fresh)
        )
        suffix = " (read-only)" if read_only else ""
        logger.info(f"Regenerated group home policy{suffix} for group {group_name}")
        return fresh

    async def ensure_group_policy(
        self, group_name: str, read_only: bool = False, path_target: str | None = None
    ) -> PolicyModel:
        """
        Ensure the group inline policy exists.

        WARNING: This method is NOT ATOMIC. The existence of policies are checked in one
        operation and then updated if they do not exist in another operation. If another
        policy altering operation interleaves, any changes it makes will be lost.

        If the policy already exists it is returned as-is. If it doesn't exist
        it is created with default permissions. Safe to call multiple times.

        group_name:  Name of the group.
        read_only:   If True, generate a read-only policy.
        path_target: Override the name used for S3 path generation; useful for
                     RO shadow groups whose paths should point at the base group.
        """
        suffix = " (read-only)" if read_only else ""
        doc = await self._iam_client.get_group_policy(
            group_name, _GROUP_IAM_POLICY, except_if_absent=False
        )
        if doc is None:
            policy_type = (
                PolicyType.GROUP_HOME_RO if read_only else PolicyType.GROUP_HOME
            )
            policy_model = self._create_policy_model(
                policy_type, group_name, path_target_name=path_target
            )
            await self._iam_client.set_group_policy(
                group_name, _GROUP_IAM_POLICY, _policy_to_dict(policy_model)
            )
            logger.info(f"Created group policy{suffix} for group {group_name}")
            return policy_model
        logger.info(f"Group policy{suffix} already exists for group {group_name}")
        return PolicyModel(policy_document=PolicyDocument.from_dict(doc))

    async def get_user_home_policy(self, username: str) -> PolicyModel:
        """
        Retrieve the user's home inline policy from IAM.

        username: The user whose home policy to fetch.
        """
        try:
            doc = await self._iam_client.get_user_policy(
                username, _USER_HOME_IAM_POLICY
            )
        except IamPolicyNotFoundError as e:
            raise PolicyOperationError(
                f"User home policy not found for user {username}"
            ) from e
        return PolicyModel(policy_document=PolicyDocument.from_dict(doc))

    async def get_user_system_policy(self, username: str) -> PolicyModel:
        """
        Retrieve the user's system inline policy from IAM.

        username: The user whose system policy to fetch.
        """
        try:
            doc = await self._iam_client.get_user_policy(
                username, _USER_SYSTEM_IAM_POLICY
            )
        except IamPolicyNotFoundError as e:
            raise PolicyOperationError(
                f"User system policy not found for user {username}"
            ) from e
        return PolicyModel(policy_document=PolicyDocument.from_dict(doc))

    async def get_group_policy(self, group_name: str) -> PolicyModel:
        """
        Retrieve the group's inline policy from IAM.

        group_name: Name of the group.
        """
        try:
            doc = await self._iam_client.get_group_policy(group_name, _GROUP_IAM_POLICY)
        except IamPolicyNotFoundError as e:
            raise PolicyOperationError(
                f"Group policy not found for group {group_name}"
            ) from e
        return PolicyModel(policy_document=PolicyDocument.from_dict(doc))

    # ── Policy document manipulation ──────────────────────────────────────────

    def _add_path_access_to_policy(
        self,
        policy_model: PolicyModel,
        path: str,
        permission_level: PolicyPermissionLevel,
    ) -> PolicyModel:
        try:
            return (
                PolicyBuilder(policy_model, self._config.default_bucket)
                .add_path_access(path, permission_level)
                .build()
            )
        except Exception as e:
            raise PolicyOperationError(f"Failed to add path access {path}: {e}") from e

    def _remove_path_access_from_policy(
        self, policy_model: PolicyModel, path: str
    ) -> PolicyModel:
        try:
            return (
                PolicyBuilder(policy_model, self._config.default_bucket)
                .remove_path_access(path)
                .build()
            )
        except Exception as e:
            raise PolicyOperationError(
                f"Failed to remove path access {path}: {e}"
            ) from e
