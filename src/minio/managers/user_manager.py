import json
import logging
import re
import secrets
import string
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from ...service.exceptions import UserOperationError
from ..core.minio_client import MinIOClient
from ..core.policy_creator import SYSTEM_RESOURCE_CONFIG
from ..models.command import UserAction
from ..models.minio_config import MinIOConfig
from ..models.user import UserModel
from ..utils.validators import validate_username
from .resource_manager import ResourceManager

logger = logging.getLogger(__name__)

RESOURCE_TYPE: str = "user"

# This is a global group that all users are automatically added to
# This group can be used to apply policies, share paths, etc. to all users
GLOBAL_USER_GROUP = "globalusers"


class UserManager(ResourceManager[UserModel]):
    """UserManager for basic user operations with patterns and generic CRUD."""

    def __init__(self, client: MinIOClient, config: MinIOConfig) -> None:
        super().__init__(client, config)
        self.users_general_warehouse_prefix = config.users_general_warehouse_prefix
        self.users_sql_warehouse_prefix = config.users_sql_warehouse_prefix

        # Lazy initialization of dependent managers to avoid circular imports
        self._policy_manager = None
        self._group_manager = None

    @property
    def policy_manager(self):
        """
        Get the PolicyManager instance for policy-related operations.

        This property provides lazy initialization of the PolicyManager to avoid
        circular import dependencies. The PolicyManager handles all user policy
        creation, management, and attachment operations.

        Returns:
            PolicyManager: Initialized PolicyManager instance for policy operations
        """
        if self._policy_manager is None:
            from .policy_manager import PolicyManager

            self._policy_manager = PolicyManager(self.client, self.config)
        return self._policy_manager

    @property
    def group_manager(self):
        """
        Get the GroupManager instance for group-related operations.

        This property provides lazy initialization of the GroupManager to avoid
        circular import dependencies. The GroupManager handles user-group membership
        operations and group policy management.

        Returns:
            GroupManager: Initialized GroupManager instance for group operations
        """
        if self._group_manager is None:
            from .group_manager import GroupManager

            self._group_manager = GroupManager(self.client, self.config)
        return self._group_manager

    # === ResourceManager Abstract Method Implementations ===

    def _get_resource_type(self) -> str:
        """Get the resource type name."""
        return RESOURCE_TYPE

    def _validate_resource_name(self, name: str) -> str:
        """Validate and normalize a username."""
        return validate_username(name)

    def _build_exists_command(self, name: str) -> List[str]:
        """Build command to check if user exists."""
        return self._command_builder.build_user_command(UserAction.INFO, name)

    def _build_list_command(self) -> List[str]:
        """Build command to list all users."""
        return self._command_builder.build_user_list_command(json_format=True)

    def _build_delete_command(self, name: str) -> List[str]:
        """Build command to delete a user."""
        return self._command_builder.build_user_command(UserAction.REMOVE, name)

    def _parse_list_output(self, stdout: str) -> List[str]:
        """Parse user list command output."""
        try:
            # The mc command outputs a stream of JSON objects, one per line
            json_lines = stdout.strip().split("\n")
            users_data = [json.loads(line) for line in json_lines if line]

            # Extract the accessKey which corresponds to the username
            usernames = [
                user["accessKey"] for user in users_data if "accessKey" in user
            ]
            return usernames
        except Exception as e:
            raise UserOperationError(
                f"Failed to parse user list command output: {stdout}"
            ) from e

    # === Pre/Post Delete Cleanup Overrides ===

    async def _pre_delete_cleanup(self, name: str, force: bool = False) -> None:
        """Clean up user resources before deletion."""
        await self.policy_manager.detach_user_policies(name)
        await self.policy_manager.delete_user_policies(name)

    async def _post_delete_cleanup(self, name: str) -> None:
        """Clean up user resources after deletion."""
        # Delete user home and system directories
        await self._delete_user_home_directory(name)
        await self._delete_user_system_directory(name)

    # CORE USER OPERATIONS

    async def create_user(
        self,
        username: str,
        password: Optional[str] = None,
    ) -> UserModel:
        """
        Create a new MinIO user with complete setup including credentials, policy, and workspace.

        This method performs a user creation workflow:
        1. Validates the username format
        2. Generates a secure password if not provided
        3. Creates or retrieves the user policy
        4. Creates the user account in MinIO if it doesn't exist
        5. Attaches the user policy if not already attached
        6. Sets up user home directories in both SQL and general warehouses
        7. Creates a welcome file with workspace instructions

        The user will receive access to:
        - Personal SQL warehouse directory: `s3a://bucket/users-sql-warehouse/{username}/`
        - Personal general warehouse directory: `s3a://bucket/users-general-warehouse/{username}/`
        - Subdirectories: data/, notebooks/, shared/

        This method is safe to run multiple times and will only perform previously incomplete operations.

        Group memberships can be added later using separate group management endpoints.

        Args:
            username: The username for the new user (must be valid per MinIO requirements)
            password: Optional password for the user (auto-generated if not provided)

        Returns:
            UserModel: Complete user information including credentials and policy

        Raises:
            UserOperationError: If user creation fails or username is invalid
        """
        async with self.operation_context("create_user"):
            validate_username(username)
            if password is None:
                password = self._generate_secure_password()

            # Create user policies (home and system)
            home_policy, system_policy = await self.policy_manager.ensure_user_policies(
                username
            )

            # Create the user
            if not await self.resource_exists(username):
                cmd_args = self._command_builder.build_user_command(
                    UserAction.ADD, username, password
                )
                result = await self._executor._execute_command(cmd_args)
                if not result.success:
                    raise UserOperationError(
                        f"Failed to create MinIO user: {result.stderr}"
                    )

            # Attach both user policies (home and system) if not already attached
            if not await self.policy_manager.is_policies_attached_to_user(username):
                await self.policy_manager.attach_user_policies(username)

            # Create user home and system directory structures
            await self._create_user_home_directory(username)
            await self._create_user_system_directory(username)
            home_paths = self._get_user_home_paths(username)

            if not await self.group_manager.resource_exists(GLOBAL_USER_GROUP):
                await self.group_manager.create_group(GLOBAL_USER_GROUP, username)
            await self.group_manager.add_user_to_group(username, GLOBAL_USER_GROUP)

            return UserModel(
                username=username,
                access_key=username,  # access key is always the username
                secret_key=password,
                home_paths=home_paths,
                groups=[],  # No groups assigned during creation
                user_policies=[home_policy, system_policy],
                group_policies=[],  # No group policies during creation
                total_policies=2,  # Home and system policies
                accessible_paths=home_paths,  # user home path is accessible via newly created policy
            )

    async def get_user(self, username: str) -> UserModel:
        """
        Retrieve comprehensive information about an existing user including all policies and access rights.

        This method gathers complete user information by:
        1. Verifying the user exists in MinIO
        2. Collecting all group memberships
        3. Loading the user's direct policy
        4. Loading all group policies the user inherits
        5. Calculating all accessible paths from all policies
        6. Building a complete UserModel with all permissions

        The returned model provides a complete view of the user's access rights
        and can be used for authorization decisions and administrative purposes.

        Args:
            username: The username to retrieve information for
        """
        async with self.operation_context("get_user"):

            user_exists = await self.resource_exists(username)
            if not user_exists:
                raise UserOperationError(f"User {username} not found")

            # Gather user information
            user_groups = await self.group_manager.get_user_groups(username)
            user_policy = await self.policy_manager.get_user_home_policy(username)
            system_policy = await self.policy_manager.get_user_system_policy(username)

            # Calculate accessible paths
            all_accessible_paths = set()
            all_accessible_paths.update(
                self.policy_manager.get_accessible_paths_from_policy(user_policy)
            )
            all_accessible_paths.update(
                self.policy_manager.get_accessible_paths_from_policy(system_policy)
            )

            # Process group policies safely
            group_policies = []
            for group_name in user_groups:
                group_policy = await self.policy_manager.get_group_policy(group_name)
                group_policies.append(group_policy)
                all_accessible_paths.update(
                    self.policy_manager.get_accessible_paths_from_policy(group_policy)
                )

            return UserModel(
                username=username,
                access_key=username,  # access key is always the username
                secret_key="<redacted>",  # Don't return secret in GET requests
                home_paths=self._get_user_home_paths(username),
                groups=user_groups,
                user_policies=[user_policy, system_policy],
                group_policies=group_policies,
                # home policy + system policy + group policies
                total_policies=2 + len(group_policies),
                accessible_paths=sorted(list(all_accessible_paths)),
            )

    async def get_or_rotate_user_credentials(self, username: str) -> Tuple[str, str]:
        """
        Generate fresh credentials for a user by rotating their password/secret key.

        This method implements a unified credential system where:
        - Access key is always the username (consistent identifier)
        - Secret key is a freshly generated secure password
        - The MinIO user password is updated to match the new secret key

        Args:
            username: The username to generate fresh credentials for
        """
        async with self.operation_context("get_or_rotate_user_credentials"):

            # For unified credentials approach:
            # - Access key is always the username
            # - Secret key is a fresh generated password that we set as the user's password
            access_key = username
            secret_key = self._generate_secure_password()

            # Update the user's password in MinIO to match the secret key
            # Note: In MinIO, re-adding a user with a new password effectively updates it
            cmd_args = self._command_builder.build_user_command(
                UserAction.ADD, username, secret_key
            )

            user_exists = await self.resource_exists(username)
            if not user_exists:
                raise UserOperationError(f"User {username} not found")

            password_result = await self._executor._execute_command(cmd_args)
            if not password_result.success:
                raise UserOperationError(
                    f"Failed to update password for user {username}: {password_result.stderr}"
                )

            logger.info(f"Generated fresh credentials for user {username}")
            return access_key, secret_key

    # UTILITY METHODS

    async def get_user_policies(self, username: str) -> Dict[str, Any]:
        """
        Retrieve all policies that apply to a user, including user's home and system policies and all group policies.

        Args:
            username: The username to get policies for
        """
        async with self.operation_context("get_user_policies"):
            user_exists = await self.resource_exists(username)
            if not user_exists:
                raise UserOperationError(f"User {username} not found")

            # Get user's direct policy
            user_policy = await self.policy_manager.get_user_home_policy(username)
            system_policy = await self.policy_manager.get_user_system_policy(username)

            # Get user's group policies
            user_groups = await self.group_manager.get_user_groups(username)
            group_policies = []

            for group_name in user_groups:
                group_policy = await self.policy_manager.get_group_policy(group_name)
                if group_policy:
                    group_policies.append(group_policy)

            return {
                "user_home_policy": user_policy,
                "user_system_policy": system_policy,
                "group_policies": group_policies,
            }

    async def can_user_share_path(self, path: str, username: str) -> bool:
        """
        Determine if a user has permission to share a specific S3 path with others.

        Args:
            path: The S3 path to check sharing permissions for (e.g., "s3a://bucket/path")
            username: The username requesting sharing permission

        Returns:
            bool: True if the user can share this path, False otherwise

        Note:
            Currently implements simplified logic based on home directory (SQL or general warehouse) ownership.
            Future versions may implement more sophisticated permission checking.
        """
        return self._is_path_in_user_home(path, username)

    async def get_user_accessible_paths(self, username: str) -> List[str]:
        """
        Calculate all S3 paths that a user can access through their policies and group memberships.

        This method comprehensively analyzes all policies that apply to the user:
        1. Extracts accessible paths from the user's direct policy
        2. Extracts accessible paths from all inherited group policies
        3. Combines and deduplicates all paths
        4. Returns a sorted list of unique accessible paths

        Args:
            username: The username to calculate accessible paths for
        """
        async with self.operation_context("get_user_accessible_paths"):
            # Check if user exists
            if not await self.resource_exists(username):
                raise UserOperationError(f"User {username} not found")

            # Get all accessible paths from user policy and group policies
            all_accessible_paths = set()

            # Add paths from user policies (both home and system)
            user_policy = await self.policy_manager.get_user_home_policy(username)
            system_policy = await self.policy_manager.get_user_system_policy(username)
            all_accessible_paths.update(
                self.policy_manager.get_accessible_paths_from_policy(user_policy)
            )
            all_accessible_paths.update(
                self.policy_manager.get_accessible_paths_from_policy(system_policy)
            )

            # Add paths from group policies
            user_groups = await self.group_manager.get_user_groups(username)
            for group_name in user_groups:
                group_policy = await self.policy_manager.get_group_policy(group_name)
                all_accessible_paths.update(
                    self.policy_manager.get_accessible_paths_from_policy(group_policy)
                )

            return sorted(list(all_accessible_paths))

    # PRIVATE HELPER METHODS

    def _generate_secure_password(self, length: int = 8) -> str:
        """Generate a secure password for MinIO users."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _is_path_in_user_home(self, path: str, username: str) -> bool:
        """Check if a path is within the user's home directories (SQL or General warehouse)."""
        # Check both warehouse prefixes
        user_home_general_prefix = f"{self.users_general_warehouse_prefix}/{username}/"
        user_home_sql_prefix = f"{self.users_sql_warehouse_prefix}/{username}/"

        clean_path = re.sub(r"^s3a?://", "", path)
        # Remove bucket name
        if "/" in clean_path:
            path_without_bucket = clean_path.split("/", 1)[1]
            return path_without_bucket.startswith(
                user_home_general_prefix
            ) or path_without_bucket.startswith(user_home_sql_prefix)
        return False

    def _get_user_home_paths(self, username: str) -> list[str]:
        """Get the user's primary home path (general warehouse) and SQL warehouse path."""
        return [
            f"s3a://{self.config.default_bucket}/{self.users_general_warehouse_prefix}/{username}/",
            f"s3a://{self.config.default_bucket}/{self.users_sql_warehouse_prefix}/{username}/",
        ]

    async def _create_user_home_directory(self, username: str) -> None:
        """Create user home directory structure with async patterns."""
        bucket_name = self.config.default_bucket

        # Ensure bucket exists
        if not await self.client.bucket_exists(bucket_name):
            await self.client.create_bucket(bucket_name)

        # Create directory structure and welcome file in parallel
        await self._create_directory_structure(username, bucket_name)
        await self._create_welcome_file(username, bucket_name)

    async def _create_directory_structure(
        self, username: str, bucket_name: str
    ) -> None:
        """Create the user's directory structure."""
        home_paths = [
            f"{self.users_sql_warehouse_prefix}/{username}/",
            f"{self.users_general_warehouse_prefix}/{username}/",
            f"{self.users_general_warehouse_prefix}/{username}/data/",
            f"{self.users_general_warehouse_prefix}/{username}/notebooks/",
            f"{self.users_general_warehouse_prefix}/{username}/shared/",
        ]

        # Create directory markers
        for path in home_paths:
            # Create directory marker
            marker_key = f"{path}.keep"
            await self.client.put_object(
                bucket_name, marker_key, b"User directory marker"
            )

    async def _create_welcome_file(self, username: str, bucket_name: str) -> None:
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
        await self.client.put_object(bucket_name, welcome_key, welcome_content)

    async def _create_user_system_directory(self, username: str) -> None:
        """Create user system directory structure for system resources like Spark job logs."""

        # Get system paths for this user using the global configuration
        system_paths = self._get_user_system_paths(username)

        # Create directories for each system bucket and prefix
        for bucket_name, prefixes in system_paths.items():
            # Ensure system bucket exists
            if not await self.client.bucket_exists(bucket_name):
                await self.client.create_bucket(bucket_name)

            # Create directory markers for each prefix
            for prefix in prefixes:
                # Create directory marker
                marker_key = f"{prefix}/.keep"
                await self.client.put_object(
                    bucket_name, marker_key, b"User system directory marker"
                )
                logger.info(f"Created system directory: s3a://{bucket_name}/{prefix}/")

    async def _delete_user_home_directory(self, username: str) -> None:
        """Delete user home directories and all contents (both SQL and general warehouse)."""
        bucket_name = self.config.default_bucket

        # Delete both warehouse directories
        prefixes = [
            f"{self.users_general_warehouse_prefix}/{username}/",
            f"{self.users_sql_warehouse_prefix}/{username}/",
        ]

        for user_prefix in prefixes:
            # List all objects in user directory
            objects = await self.client.list_objects(
                bucket_name, user_prefix, list_all=True
            )

            # Delete objects
            for obj_key in objects:
                await self.client.delete_object(bucket_name, obj_key)

            logger.info(f"Deleted {len(objects)} objects from {user_prefix}")

    async def _delete_user_system_directory(self, username: str) -> None:
        """Delete user system directories and all contents (like Spark job logs)."""

        # Get only user-scoped system paths to avoid deleting global resources
        system_paths = self._get_user_system_paths(username, user_scoped_only=True)

        # Delete directories for each system bucket and prefix
        for bucket_name, prefixes in system_paths.items():
            if not await self.client.bucket_exists(bucket_name):
                continue  # Skip if bucket doesn't exist

            for prefix in prefixes:
                # List all objects in user system directory
                objects = await self.client.list_objects(
                    bucket_name, prefix, list_all=True
                )

                # Delete objects
                for obj_key in objects:
                    await self.client.delete_object(bucket_name, obj_key)

                logger.info(
                    f"Deleted {len(objects)} objects from s3a://{bucket_name}/{prefix}/"
                )

    def _get_user_system_paths(
        self, username: str, user_scoped_only: bool = False
    ) -> Dict[str, List[str]]:
        """Get system resource paths for a user using the global configuration.

        Args:
            username: The username to get paths for
            user_scoped_only: If True, only returns user-scoped paths (ending with /{username}).
                              If False, returns all system paths for directory creation.
        """
        user_paths = defaultdict(list)

        for _, resource_config in SYSTEM_RESOURCE_CONFIG.items():
            bucket = resource_config["bucket"]
            base_prefix = resource_config["base_prefix"]
            user_scoped = resource_config.get("user_scoped", True)

            # Skip global resources if only user-scoped paths are requested
            if user_scoped_only and not user_scoped:
                continue

            # Generate path based on whether resource is user-scoped
            path = f"{base_prefix}/{username}" if user_scoped else base_prefix
            user_paths[bucket].append(path)

        return dict(user_paths)
