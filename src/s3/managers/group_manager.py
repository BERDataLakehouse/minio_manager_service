"""Group manager for S3-compatible IAM (Ceph RadosGW)."""

import logging

from service.exceptions import GroupNotFoundError, GroupOperationError
from s3.core.s3_client import S3Client
from s3.core.s3_iam_client import S3IAMClient
from s3.managers.policy_manager import PolicyManager
from s3.models.group import GroupModel
from s3.models.s3_config import S3Config
from s3.utils.validators import validate_group_name

logger = logging.getLogger(__name__)


class GroupManager:
    """
    Group manager for S3 IAM groups.

    Each tenant group has:
      - A main read/write group (<group_name>) with a "group" inline policy.
      - A read-only shadow group (<group_name>ro) with a read-only "group" inline policy
        whose S3 paths point at the main group's workspace.

    Groups have a shared S3 workspace under the tenant warehouse prefixes:
      - s3a://<bucket>/tenant-general-warehouse/<group_name>/
      - s3a://<bucket>/tenant-sql-warehouse/<group_name>/
    """

    def __init__(
        self,
        iam_client: S3IAMClient,
        s3_client: S3Client,
        policy_manager: PolicyManager,
        config: S3Config,
    ) -> None:
        self._iam_client = iam_client
        self._s3_client = s3_client
        self._policy_manager = policy_manager
        self._config = config

    async def group_exists(self, group_name: str) -> bool:
        """Return True if the IAM group exists."""
        return await self._iam_client.group_exists(group_name)

    async def list_groups(self) -> list[str]:
        """Return the names of all IAM groups."""
        return await self._iam_client.list_groups()

    async def delete_group(self, group_name: str) -> None:
        """
        Delete a group and its RO shadow group, including S3 workspace cleanup.

        S3 cleanup is best-effort and will not raise on failure.

        group_name: Name of the group to delete.
        """
        ro_group_name = f"{group_name}ro"

        if await self._iam_client.group_exists(ro_group_name):
            await self._iam_client.delete_group(ro_group_name)

        await self._iam_client.delete_group(group_name)
        await self._delete_group_shared_directory(group_name)

    # ── Compatibility shims ──────────────────────────────────────────────────

    async def list_resources(self) -> list[str]:
        # TODO: Delete this method and update callers to use list_groups() when
        # minio.managers.group_manager is removed.
        return await self.list_groups()

    async def delete_resource(self, group_name: str) -> bool:
        # TODO: Delete this method and update callers to use delete_group() when
        # minio.managers.group_manager is removed.
        try:
            await self.delete_group(group_name)
            return True
        except Exception as e:
            logger.error("Failed to delete group %s: %s", group_name, e)
            return False

    # ── Core group operations ────────────────────────────────────────────────

    async def create_group(
        self, group_name: str, creator: str
    ) -> tuple[GroupModel, GroupModel]:
        """
        Create a group with complete setup: policy, RO shadow group, and S3 workspace.

        WARNING - this method is NOT ATOMIC. In some stages of the workflow, changes to a group
        policy may be lost if those changes interleave this method at the wrong time.

        This method performs a comprehensive, idempotent group creation workflow:
        1. Verifies that the creator exists as a user
        2. Creates the group in IAMs with the creator as the initial member
        3. Creates the group policy
        4. Creates the read-only group ({group_name}ro) with read-only policy
        5. Sets up the group's shared directory structure
        6. Creates a welcome file with workspace instructions

        Idempotent — safe to call if the group already exists.

        group_name: Name of the group to create.
        creator:    Username of the creating user; added as the initial member of
                    both the main and RO groups.

        Returns a (main_group, ro_group) tuple.
        """
        group_name = validate_group_name(group_name)
        ro_group_name = f"{group_name}ro"

        if not await self._iam_client.user_exists(creator):
            raise GroupOperationError(f"User {creator} does not exist")

        # Main group
        await self._iam_client.create_group(group_name, exists_ok=True)
        await self._policy_manager.ensure_group_policy(group_name)
        await self._iam_client.add_user_to_group(creator, group_name)

        # Read-only shadow group
        await self._iam_client.create_group(ro_group_name, exists_ok=True)
        await self._policy_manager.ensure_group_policy(
            ro_group_name, read_only=True, path_target=group_name
        )
        await self._iam_client.add_user_to_group(creator, ro_group_name)

        # S3 shared workspace
        await self._create_group_shared_directory(group_name)

        logger.info(
            "Created group %s and RO group %s",
            group_name,
            ro_group_name,
        )
        return (
            GroupModel(group_name=group_name, members=[creator]),
            GroupModel(group_name=ro_group_name, members=[creator]),
        )

    async def add_user_to_group(self, username: str, group_name: str) -> None:
        """
        Add a user to a group.

        Validates that both the group and user exist first.
        Adding a user who is already a member is a no-op.

        username:   Username to add.
        group_name: Group to add the user to.
        """
        if not await self._iam_client.group_exists(group_name):
            raise GroupNotFoundError(f"Group {group_name} not found")
        if not await self._iam_client.user_exists(username):
            raise GroupOperationError(f"User {username} does not exist")
        await self._iam_client.add_user_to_group(username, group_name)
        logger.info("Added user %s to group %s", username, group_name)

    async def remove_user_from_group(self, username: str, group_name: str) -> None:
        """
        Remove a user from a group.

        Validates that the group exists first.
        Removing a user who is not a member is a no-op.

        username:   Username to remove.
        group_name: Group to remove the user from.
        """
        if not await self._iam_client.group_exists(group_name):
            raise GroupNotFoundError(f"Group {group_name} not found")
        await self._iam_client.remove_user_from_group(username, group_name)
        logger.info("Removed user %s from group %s", username, group_name)

    async def get_group_members(self, group_name: str) -> list[str]:
        """
        Return the list of usernames in a group.

        group_name: Name of the group.
        """
        if not await self._iam_client.group_exists(group_name):
            raise GroupNotFoundError(f"Group {group_name} not found")
        return await self._iam_client.list_users_in_group(group_name)

    async def get_group_info(self, group_name: str) -> GroupModel:
        """
        Return a GroupModel with current members for a group.

        group_name: Name of the group.
        """
        if not await self._iam_client.group_exists(group_name):
            raise GroupNotFoundError(f"Group {group_name} not found")
        members = await self._iam_client.list_users_in_group(group_name)
        return GroupModel(group_name=group_name, members=members)

    async def is_user_in_group(self, username: str, group_name: str) -> bool:
        """
        Return True if the user is a member of the group.

        username:   Username to check.
        group_name: Group to check membership in.
        """
        try:
            members = await self.get_group_members(group_name)
            return username in members
        except Exception as e:
            raise GroupOperationError(
                f"Failed to check if user {username} is in group {group_name}"
            ) from e

    async def get_user_groups(self, username: str) -> list[str]:
        """
        Return the sorted list of group names the user belongs to.

        username: Username to look up.
        """
        return sorted(await self._iam_client.list_groups_for_user(username))

    # ── S3 workspace helpers ─────────────────────────────────────────────────

    async def _create_group_shared_directory(self, group_name: str) -> None:
        bucket = self._config.default_bucket
        await self._s3_client.create_bucket(bucket, exists_ok=True)

        keys = [
            f"{self._config.tenant_sql_warehouse_prefix}/{group_name}/.s3keep",
            f"{self._config.tenant_general_warehouse_prefix}/{group_name}/.s3keep",
            f"{self._config.tenant_general_warehouse_prefix}/{group_name}/shared/.s3keep",
            f"{self._config.tenant_general_warehouse_prefix}/{group_name}/datasets/.s3keep",
            f"{self._config.tenant_general_warehouse_prefix}/{group_name}/projects/.s3keep",
        ]
        for key in keys:
            await self._s3_client.put_object(bucket, key, b"Group directory marker")

        welcome_key = (
            f"{self._config.tenant_general_warehouse_prefix}/{group_name}/README.txt"
        )
        welcome_content = f"""Welcome to the {group_name} group shared workspace!

This is a shared space for all members of the {group_name} group.
All group members have full read/write access to this space.

Directory structure:
- shared/: General shared files and documents
- datasets/: Shared datasets for the group
- projects/: Collaborative project workspaces

Happy collaborating!
""".encode()
        await self._s3_client.put_object(bucket, welcome_key, welcome_content)

    async def _delete_group_shared_directory(self, group_name: str) -> None:
        bucket = self._config.default_bucket
        for prefix in [
            f"{self._config.tenant_general_warehouse_prefix}/{group_name}/",
            f"{self._config.tenant_sql_warehouse_prefix}/{group_name}/",
        ]:
            try:
                # TODO this may cause memory / speed issues since it could fetch millions of
                #       objects, implement batching
                objects = await self._s3_client.list_objects(
                    bucket, prefix, list_all=True
                )
                for key in objects:
                    await self._s3_client.delete_object(bucket, key)
                logger.info("Deleted %d objects from %s", len(objects), prefix)
            except Exception as e:
                logger.warning(
                    "Failed to delete group directory %s for %s: %s",
                    prefix,
                    group_name,
                    e,
                )
