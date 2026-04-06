"""User manager for S3-compatible IAM (Ceph RadosGW)."""

import logging
import re
from collections import defaultdict
from typing import Any

from service.exceptions import UserOperationError
from s3.core.policy_creator import SYSTEM_RESOURCE_CONFIG
from s3.core.s3_client import S3Client
from s3.core.s3_iam_client import S3IAMClient
from s3.managers.group_manager import GroupManager
from s3.managers.policy_manager import PolicyManager
from s3.models.s3_config import S3Config
from s3.models.user import UserModel
from s3.utils.validators import validate_username

logger = logging.getLogger(__name__)

# All users are automatically added to this group on creation.
GLOBAL_USER_GROUP = "globalusers"


class UserManager:
    """
    User manager for IAM user lifecycle and S3 workspace management.

    Handles user creation (IAM user + policies + S3 directories + group
    membership), retrieval, listing, deletion, credential rotation, and
    path-access queries.
    """

    def __init__(
        self,
        iam_client: S3IAMClient,
        s3_client: S3Client,
        policy_manager: PolicyManager,
        group_manager: GroupManager,
        config: S3Config,
    ) -> None:
        """
        Initialize the UserManager.

        iam_client:     IAM client for user/group/key operations.
        s3_client:      S3 client for bucket/object operations.
        policy_manager: Policy manager for user and group policy management.
        group_manager:  Group manager for global group setup.
        config:         S3 configuration (bucket names, path prefixes, etc.).
        """
        self._iam_client = iam_client
        self._s3_client = s3_client
        self._policy_manager = policy_manager
        self._group_manager = group_manager
        self.config = config
        self.users_general_warehouse_prefix = config.users_general_warehouse_prefix
        self.users_sql_warehouse_prefix = config.users_sql_warehouse_prefix

    async def list_users(self) -> list[str]:
        """Return the usernames of all managed IAM users."""
        return await self._iam_client.list_users()

    async def delete_user(self, username: str) -> None:
        """
        Delete a user, removing their IAM account (including all group
        memberships, inline policies, and access keys) and their S3 workspace
        directories.

        S3 directory cleanup failures are logged as warnings and do not cause
        the method to raise, since the IAM account has already been removed.

        username: The username to delete.
        """
        await self._iam_client.delete_user(username)

        try:
            await self._delete_user_home_directory(username)
        except Exception as e:
            logger.warning(
                "Failed to delete S3 home directory for user %s: %s", username, e
            )

        try:
            await self._delete_user_system_directory(username)
        except Exception as e:
            logger.warning(
                "Failed to delete S3 system directory for user %s: %s", username, e
            )

    async def user_exists(self, username: str) -> bool:
        """Return True if the IAM user exists, False otherwise."""
        return await self._iam_client.user_exists(username)

    # ── Compatibility shims (delete when minio.managers.UserManager is removed) ─

    async def list_resources(self) -> list[str]:
        # TODO: Delete this method and update callers to use list_users() when
        # minio.managers.user_manager is removed.
        return await self.list_users()

    async def delete_resource(self, username: str) -> bool:
        # TODO: Delete this method and update callers to use delete_user() when
        # minio.managers.user_manager is removed.
        try:
            await self.delete_user(username)
            return True
        except Exception as e:
            logger.error("Failed to delete user %s: %s", username, e)
            return False

    async def resource_exists(self, username: str) -> bool:
        # TODO: Delete this method and update callers to use user_exists() when
        # minio.managers.user_manager is removed.
        return await self.user_exists(username)

    # ── Core user operations ─────────────────────────────────────────────────

    async def create_user(self, username: str) -> UserModel:
        """
        Create a new user with full setup: IAM user, policies, S3 directories,
        and global group membership.

        WARNING - this method is NOT ATOMIC. In some stages of the workflow, changes to a user
        policy may be lost if those changes interleave this method at the wrong time.

        This method performs a user creation workflow:
        1. Validates the username format
        2. Creates the user account in IAM if it doesn't exist
        3. Creates the user policy if it doesn't exist
        4. Creates an access key and secret key for the user
        5. Sets up user home directories in both SQL and general warehouses
        6. Creates a welcome file with workspace instructions

        The user will receive access to:
        - Personal SQL warehouse directory: `s3a://bucket/users-sql-warehouse/{username}/`
        - Personal general warehouse directory: `s3a://bucket/users-general-warehouse/{username}/`
        - Subdirectories: data/, notebooks/, shared/

        Idempotent — safe to call if the user already exists; previously
        completed steps are skipped.

        username: The username to create (validated against username rules).


        Returns complete user information including credentials and policy

        Raises UserOperationError: If user creation fails or username is invalid
        """
        validate_username(username)

        # Ensure IAM user exists
        await self._iam_client.create_user(username, exists_ok=True)

        # Ensure both inline policies exist on the user
        home_policy, system_policy = await self._policy_manager.ensure_user_policies(
            username
        )

        # Generate access credentials
        access_key_id, secret_key = await self._iam_client.rotate_access_key(username)

        # Create S3 workspace directories
        await self._create_user_home_directory(username)
        await self._create_user_system_directory(username)

        # Add to the global user group (idempotent — creates group+policy if needed)
        if not await self._group_manager.group_exists(GLOBAL_USER_GROUP):
            await self._group_manager.create_group(GLOBAL_USER_GROUP, username)
        await self._group_manager.add_user_to_group(username, GLOBAL_USER_GROUP)

        return UserModel(
            username=username,
            access_key=access_key_id,
            secret_key=secret_key,
            home_paths=self._get_user_home_paths(username),
            groups=[],
            user_policies=[home_policy, system_policy],
            group_policies=[],
            total_policies=2,
            accessible_paths=self._get_user_home_paths(username),
        )

    async def get_user(self, username: str) -> UserModel:
        """
        Return comprehensive information about a user including all policies
        and accessible paths.

        username: The username to retrieve.
        """
        if not await self._iam_client.user_exists(username):
            raise UserOperationError(f"User {username} not found")

        user_groups = await self._group_manager.get_user_groups(username)
        home_policy = await self._policy_manager.get_user_home_policy(username)
        system_policy = await self._policy_manager.get_user_system_policy(username)
        access_key_ids = await self._iam_client.list_access_key_ids(username)

        all_paths: set[str] = set()
        all_paths.update(home_policy.get_accessible_paths())
        all_paths.update(system_policy.get_accessible_paths())

        group_policies = []
        for group_name in user_groups:
            group_policy = await self._policy_manager.get_group_policy(group_name)
            group_policies.append(group_policy)
            all_paths.update(group_policy.get_accessible_paths())

        return UserModel(
            username=username,
            access_key=access_key_ids[0] if access_key_ids else "",
            secret_key="<redacted>",  # Don't return secret in GET requests
            home_paths=self._get_user_home_paths(username),
            groups=user_groups,
            user_policies=[home_policy, system_policy],
            group_policies=group_policies,
            total_policies=2 + len(group_policies),
            accessible_paths=sorted(all_paths),
        )

    async def get_or_rotate_user_credentials(self, username: str) -> tuple[str, str]:
        """
        Rotate the user's IAM access key and return the new credentials.

        username: The username whose credentials to rotate.

        Returns (access_key_id, secret_access_key).
        """
        if not await self._iam_client.user_exists(username):
            raise UserOperationError(f"User {username} not found")
        access_key_id, secret_key = await self._iam_client.rotate_access_key(username)
        logger.info("Rotated credentials for user %s", username)
        return access_key_id, secret_key

    async def get_user_policies(self, username: str) -> dict[str, Any]:
        """
        Return all policies that apply to a user: home policy, system policy,
        and all inherited group policies.

        username: The username to retrieve policies for.
        """
        if not await self._iam_client.user_exists(username):
            raise UserOperationError(f"User {username} not found")

        home_policy = await self._policy_manager.get_user_home_policy(username)
        system_policy = await self._policy_manager.get_user_system_policy(username)

        user_groups = await self._group_manager.get_user_groups(username)
        group_policies = [
            await self._policy_manager.get_group_policy(g) for g in user_groups
        ]

        return {
            "user_home_policy": home_policy,
            "user_system_policy": system_policy,
            "group_policies": group_policies,
        }

    async def can_user_share_path(self, path: str, username: str) -> bool:
        """
        Return True if the user is allowed to share the given S3 path.

        A user may share any path that falls within their personal home
        directories (SQL or general warehouse).

        path:     The S3 path to check (e.g. "s3a://bucket/users-general-warehouse/alice/data/").
        username: The username requesting sharing permission.


        Note:
            Currently implements simplified logic based on home directory (SQL or general
             warehouse) ownership.
            Future versions may implement more sophisticated permission checking.
        """
        return self._is_path_in_user_home(path, username)

    async def get_user_accessible_paths(self, username: str) -> list[str]:
        """
        Return a sorted list of all S3 paths accessible to a user via their
        home, system, and group policies.

        username: The username to calculate accessible paths for.
        """
        if not await self._iam_client.user_exists(username):
            raise UserOperationError(f"User {username} not found")

        all_paths: set[str] = set()

        home_policy = await self._policy_manager.get_user_home_policy(username)
        system_policy = await self._policy_manager.get_user_system_policy(username)
        all_paths.update(home_policy.get_accessible_paths())
        all_paths.update(system_policy.get_accessible_paths())

        for group_name in await self._group_manager.get_user_groups(username):
            group_policy = await self._policy_manager.get_group_policy(group_name)
            all_paths.update(group_policy.get_accessible_paths())

        return sorted(all_paths)

    # ── Private helpers ──────────────────────────────────────────────────────

    def _is_path_in_user_home(self, path: str, username: str) -> bool:
        general_prefix = f"{self.users_general_warehouse_prefix}/{username}/"
        sql_prefix = f"{self.users_sql_warehouse_prefix}/{username}/"
        clean = re.sub(r"^s3a?://", "", path)
        if "/" not in clean:
            return False
        key = clean.split("/", 1)[1]
        return key.startswith(general_prefix) or key.startswith(sql_prefix)

    def _get_user_home_paths(self, username: str) -> list[str]:
        bucket = self.config.default_bucket
        return [
            f"s3a://{bucket}/{self.users_general_warehouse_prefix}/{username}/",
            f"s3a://{bucket}/{self.users_sql_warehouse_prefix}/{username}/",
        ]

    async def _create_user_home_directory(self, username: str) -> None:
        bucket = self.config.default_bucket
        await self._s3_client.create_bucket(bucket, exists_ok=True)

        keys = [
            f"{self.users_sql_warehouse_prefix}/{username}/.s3keep",
            f"{self.users_general_warehouse_prefix}/{username}/.s3keep",
            f"{self.users_general_warehouse_prefix}/{username}/data/.s3keep",
            f"{self.users_general_warehouse_prefix}/{username}/notebooks/.s3keep",
            f"{self.users_general_warehouse_prefix}/{username}/shared/.s3keep",
        ]
        for key in keys:
            await self._s3_client.put_object(bucket, key, b"User directory marker")

        await self._create_welcome_file(username, bucket)

    async def _create_welcome_file(self, username: str, bucket: str) -> None:
        """Create a welcome file for the new user."""
        welcome_content = f"""Welcome to your MinIO workspace, {username}!

This is your personal data directory. You have full read/write access to this space.

Directory structure:
- data/: Store your datasets here
- notebooks/: Store your Jupyter notebooks here  
- shared/: Files shared with you by other users

Happy data science!
""".encode()

        welcome_key = f"{self.users_general_warehouse_prefix}/{username}/README.txt"
        await self._s3_client.put_object(bucket, welcome_key, welcome_content)

    async def _create_user_system_directory(self, username: str) -> None:
        for bucket, prefixes in self._get_user_system_paths(username).items():
            await self._s3_client.create_bucket(bucket, exists_ok=True)
            for prefix in prefixes:
                await self._s3_client.put_object(
                    bucket, f"{prefix}/.s3keep", b"User system directory marker"
                )
                logger.info(f"Created system directory: s3a://{bucket}/{prefix}/")

    async def _delete_user_home_directory(self, username: str) -> None:
        bucket = self.config.default_bucket
        for dir_prefix in [
            f"{self.users_general_warehouse_prefix}/{username}/",
            f"{self.users_sql_warehouse_prefix}/{username}/",
        ]:
            objects = await self._s3_client.list_objects(
                bucket, dir_prefix, list_all=True
            )
            for key in objects:
                await self._s3_client.delete_object(bucket, key)
            logger.info(f"Deleted {len(objects)} objects from {dir_prefix}")

    async def _delete_user_system_directory(self, username: str) -> None:
        for bucket, prefixes in self._get_user_system_paths(
            username, user_scoped_only=True
        ).items():
            if not await self._s3_client.bucket_exists(bucket):
                continue
            for prefix in prefixes:
                # TODO this may cause memory / speed issues since it could fetch millions of
                # objects implement batching
                objects = await self._s3_client.list_objects(
                    bucket, prefix, list_all=True
                )
                for key in objects:
                    await self._s3_client.delete_object(bucket, key)
                logger.info(
                    f"Deleted {len(objects)} objects from s3a://{bucket}/{prefix}/"
                )

    def _get_user_system_paths(
        self, username: str, user_scoped_only: bool = False
    ) -> dict[str, list[str]]:
        """Get system resource paths for a user using the global configuration.

        username: The username to get paths for
        user_scoped_only: If True, only returns user-scoped paths (ending with /{username}).
                          If False, returns all system paths for directory creation.
        """
        paths: dict[str, list[str]] = defaultdict(list)
        for resource_config in SYSTEM_RESOURCE_CONFIG.values():
            bucket = resource_config["bucket"]
            base_prefix = resource_config["base_prefix"]
            user_scoped = resource_config.get("user_scoped", True)
            if user_scoped_only and not user_scoped:
                continue
            prefix = f"{base_prefix}/{username}" if user_scoped else base_prefix
            paths[bucket].append(prefix)
        return dict(paths)
