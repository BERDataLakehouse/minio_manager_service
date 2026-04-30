import json
import logging
from typing import List, Optional

from service.cache import SingleFlightTTLCache
from service.exceptions import GroupNotFoundError, GroupOperationError
from s3.core.s3_client import S3Client
from minio.models.command import GroupAction, UserAction
from s3.models.group import GroupModel
from s3.models.s3_config import S3Config
from s3.models.policy import PolicyModel, PolicyType
from s3.utils.validators import validate_group_name, validate_username
from minio.managers.resource_manager import ResourceManager

logger = logging.getLogger(__name__)

RESOURCE_TYPE = "group"

# Per-replica TTL for read-side group caches. Short enough to bound
# staleness (operators don't usually wait minutes), long enough to
# absorb the bursty Tenants-page traffic pattern that historically
# starved an MMS pod with mc-storms. Mutations explicitly invalidate.
_GROUP_MEMBERS_CACHE_TTL_SECONDS = 60.0
_GROUPS_LIST_CACHE_TTL_SECONDS = 60.0

# Single sentinel key for the "all groups" cache; list_resources is
# parameterless from the cache's perspective (the optional name_filter
# is applied to the cached list, not the cache key).
_GROUPS_LIST_CACHE_KEY = "__all__"


class GroupManager(ResourceManager[GroupModel]):
    """GroupManager for basic group operations with patterns and generic CRUD."""

    def __init__(self, client: S3Client, config: S3Config):
        super().__init__(client, config)
        self.tenant_general_warehouse_prefix = config.tenant_general_warehouse_prefix
        self.tenant_sql_warehouse_prefix = config.tenant_sql_warehouse_prefix

        # Lazy initialization of dependent managers to avoid circular imports
        self._policy_manager = None
        self._user_manager = None

        # Per-replica caches for the read-heavy paths (list_tenants,
        # get_tenant_*, sharing checks). Mutations call self._invalidate_*
        # to guarantee in-pod read-after-write consistency; the TTL acts
        # only as a backstop for cross-pod / external mutations.
        self._members_cache: SingleFlightTTLCache[List[str]] = SingleFlightTTLCache(
            name="group_members",
            maxsize=1024,
            ttl_seconds=_GROUP_MEMBERS_CACHE_TTL_SECONDS,
        )
        self._groups_list_cache: SingleFlightTTLCache[List[str]] = SingleFlightTTLCache(
            name="groups_list",
            maxsize=1,
            ttl_seconds=_GROUPS_LIST_CACHE_TTL_SECONDS,
        )

    @property
    def user_manager(self):
        """
        Get the UserManager instance for user-related operations.

        This property provides lazy initialization of the UserManager to avoid
        circular import dependencies. The UserManager is used for user validation
        and existence checks during group membership operations.

        Returns:
            UserManager: Initialized UserManager instance for user operations
        """
        if self._user_manager is None:
            from minio.managers.user_manager import UserManager

            self._user_manager = UserManager(self.client, self.config)
        return self._user_manager

    @property
    def policy_manager(self):
        """
        Get the PolicyManager instance for policy-related operations.

        This property provides lazy initialization of the PolicyManager to avoid
        circular import dependencies. The PolicyManager handles all group policy
        creation, management, and attachment operations.

        Returns:
            PolicyManager: Initialized PolicyManager instance for policy operations
        """
        if self._policy_manager is None:
            from minio.managers.policy_manager import PolicyManager

            self._policy_manager = PolicyManager(self.client, self.config)
        return self._policy_manager

    # === ResourceManager Abstract Method Implementations ===

    def _get_resource_type(self) -> str:
        """Get the resource type name."""
        return RESOURCE_TYPE

    def _validate_resource_name(self, name: str) -> str:
        """Validate and normalize a group name."""
        return validate_group_name(name)

    def _build_exists_command(self, name: str) -> List[str]:
        """Build command to check if group exists."""
        return self._command_builder.build_group_command(GroupAction.INFO, name)

    def _build_list_command(self) -> List[str]:
        """Build command to list all groups."""
        return self._command_builder.build_group_list_command()

    def _build_delete_command(self, name: str) -> List[str]:
        """Build command to delete a group."""
        return self._command_builder.build_group_command(GroupAction.RM, name)

    def _parse_list_output(self, stdout: str) -> List[str]:
        """Parse group list command JSON output."""

        groups_data = json.loads(stdout)
        # Extract group names from JSON response - format: {"status":"success","groups":["group1","group2"]}
        try:
            return groups_data["groups"]
        except Exception as e:
            raise GroupOperationError(
                f"Failed to parse group list command output: {stdout}"
            ) from e

    # === Cached read-side overrides ===

    async def list_resources(self, name_filter: Optional[str] = None) -> List[str]:
        """List all groups, served from a per-process TTL cache.

        The unfiltered list is cached under a single sentinel key; the
        ``name_filter`` (when supplied) is applied to the cached copy
        so we do not multiply cache entries per filter substring.

        Mutations on this manager (group create/delete) explicitly
        invalidate the cache for read-after-write consistency in-pod.
        """
        all_groups = await self._groups_list_cache.get_or_load(
            _GROUPS_LIST_CACHE_KEY,
            lambda: super(GroupManager, self).list_resources(name_filter=None),
        )
        if not name_filter:
            return all_groups
        needle = name_filter.lower()
        return [name for name in all_groups if needle in name.lower()]

    # === Cache invalidation helpers ===

    def _invalidate_members(self, group_name: str) -> None:
        """Invalidate the cached membership of a single group."""
        self._members_cache.invalidate(group_name)

    def _invalidate_groups_list(self) -> None:
        """Invalidate the cached list of all groups."""
        self._groups_list_cache.invalidate(_GROUPS_LIST_CACHE_KEY)

    # === Single Group Creation Helper ===

    async def _create_single_group(
        self,
        group_name: str,
        members: list[str],
        read_only: bool = False,
        path_target: str | None = None,
    ) -> PolicyModel:
        """Create a single group with its policy.

        Handles: policy creation, group creation, and policy attachment.
        All operations are idempotent.

        Args:
            group_name: Name of the group to create
            members: Initial members for the group
            read_only: If True, create with read-only policy
            path_target: Target name for policy paths (defaults to group_name).
                         For RO groups, this should be the main group name.

        Returns:
            The policy model attached to the group
        """
        # Create group policy (ensure_group_policy is idempotent)
        policy_model = await self.policy_manager.ensure_group_policy(
            group_name, read_only=read_only, path_target=path_target
        )

        # Create the group if it doesn't exist
        if not await self.resource_exists(group_name):
            cmd_args = self._command_builder.build_group_command(
                GroupAction.ADD, group_name, members
            )
            result = await self._executor._execute_command(cmd_args)
            if not result.success:
                suffix = " (read-only)" if read_only else ""
                raise GroupOperationError(
                    f"Failed to create group{suffix}: {result.stderr}"
                )

            # Group set just changed: drop the cached "all groups" list,
            # and seed the membership cache with the initial members so a
            # follow-up read is a hit (also avoids one MC round-trip).
            self._invalidate_groups_list()
            self._invalidate_members(group_name)

        # Attach group policy only if not already attached
        if not await self.policy_manager.is_policy_attached_to_group(group_name):
            await self.policy_manager.attach_policy_to_group(
                policy_model.policy_name, group_name
            )

        return policy_model

    # === Pre/Post Delete Cleanup Overrides ===

    async def _pre_delete_cleanup(self, name: str, force: bool = False) -> None:
        """Clean up group resources before deletion.

        This also cleans up the associated read-only group ({name}ro) if it exists.
        """
        # Clean up main group policy
        policy_name = self.policy_manager.get_policy_name(PolicyType.GROUP_HOME, name)
        try:
            await self.policy_manager.detach_policy_from_group(policy_name, name)
        except Exception as e:
            self.logger.warning(f"Failed to detach policy from group: {e}")

        try:
            await self.policy_manager.delete_group_policy(name)
        except Exception as e:
            self.logger.warning(f"Failed to delete group policy: {e}")

        # Clean up read-only group if it exists
        ro_group_name = f"{name}ro"
        if await self.resource_exists(ro_group_name):
            # Detach read-only policy from read-only group
            # RO policies now use standard group-policy- naming
            ro_policy_name = self.policy_manager.get_policy_name(
                PolicyType.GROUP_HOME_RO, ro_group_name
            )
            try:
                await self.policy_manager.detach_policy_from_group(
                    ro_policy_name, ro_group_name
                )
            except Exception as e:
                self.logger.warning(
                    f"Failed to detach read-only policy from group: {e}"
                )

            # Delete the read-only policy
            try:
                await self.policy_manager.delete_group_policy(
                    ro_group_name, read_only=True
                )
            except Exception as e:
                self.logger.warning(f"Failed to delete read-only group policy: {e}")

            # Delete the read-only group itself
            try:
                cmd_args = self._command_builder.build_group_command(
                    GroupAction.RM, ro_group_name
                )
                result = await self._executor._execute_command(cmd_args)
                if result.success:
                    self.logger.info(f"Deleted read-only group: {ro_group_name}")
                    # Drop the RO group's cached membership; the
                    # base group's caches are dropped in
                    # _post_delete_cleanup once the base group itself
                    # has been removed.
                    self._invalidate_members(ro_group_name)
                else:
                    self.logger.warning(
                        f"Failed to delete read-only group {ro_group_name}: {result.stderr}"
                    )
            except Exception as e:
                self.logger.warning(f"Failed to delete read-only group: {e}")

    async def _post_delete_cleanup(self, name: str) -> None:
        """Clean up group resources after deletion."""
        # Drop cached state for the deleted group: its membership and
        # the global group-list. Done unconditionally so that even if
        # the shared-directory cleanup below raises, the next reader
        # sees the post-delete state.
        self._invalidate_members(name)
        self._invalidate_groups_list()

        try:
            await self._delete_group_shared_directory(name)
        except Exception as e:
            self.logger.warning(f"Failed to delete group shared directory: {e}")

    # === Group-Specific Operations ===

    async def create_group(
        self,
        group_name: str,
        creator: str,
    ) -> tuple[GroupModel, GroupModel]:
        """
        Create a new MinIO group with complete setup including policy and shared workspace.

        This method performs a comprehensive, idempotent group creation workflow:
        1. Verifies that the creator exists as a user
        2. Creates or retrieves the group policy (read/write)
        3. Creates the group in MinIO with the creator as the initial member
        4. Attaches the group policy (only if not already attached)
        5. Creates the read-only group ({group_name}ro) with read-only policy
        6. Sets up the group's shared directory structure
        7. Creates a welcome file with workspace instructions

        This method is safe to run multiple times and will only perform previously incomplete operations.

        The creator is automatically added as the initial group member of both groups.
        Additional members can be added later using add_user_to_group().

        The groups will have access to:
        - Shared workspace directory: `s3a://bucket/groups-general-warehouse/{group_name}/`
        - Subdirectories: shared/, datasets/, projects/

        Args:
            group_name: The name for the new group (must be valid per MinIO requirements)
            creator: Username of the user creating the group (becomes initial member)

        Returns:
            tuple[GroupModel, GroupModel]: A tuple containing:
                - The main group model with read/write access
                - The read-only group model with read-only access
        """
        async with self.operation_context("create_group"):
            # Normalize group name by stripping whitespace
            group_name = group_name.strip()
            ro_group_name = f"{group_name}ro"

            # Create group with initial members (MinIO requires at least one member)
            members = [creator]

            # Verify creator exists before creating group
            if not await self.user_manager.resource_exists(creator):
                raise GroupOperationError(f"User {creator} does not exist")

            # Create main group with read/write policy
            policy_model = await self._create_single_group(
                group_name, members, read_only=False
            )

            # Create read-only group ({group_name}ro) with access to main group paths
            ro_policy_model = await self._create_single_group(
                ro_group_name, members, read_only=True, path_target=group_name
            )

            # Create group shared directory structure (only once, for the main group)
            await self._create_group_shared_directory(group_name)

            # Return domain models for both groups
            group_model = GroupModel(
                group_name=group_name,
                members=members,
                policy_name=policy_model.policy_name,
            )

            ro_group_model = GroupModel(
                group_name=ro_group_name,
                members=members,
                policy_name=ro_policy_model.policy_name,
            )

            logger.info(
                f"Successfully created MinIO group {group_name} with policy {policy_model.policy_name} "
                f"and read-only group {ro_group_name} with policy {ro_policy_model.policy_name}"
            )
            return group_model, ro_group_model

    async def add_user_to_group(self, username: str, group_name: str) -> None:
        """
        Add an existing user to an existing MinIO group, granting them group access permissions.

        This method handles the complete user addition workflow:
        1. Validates that both the user and group exist
        2. Adds the user to the group in MinIO (idempotent - safe if already a member)
        3. The user automatically inherits the group's policy and access permissions

        Once added, the user will have access to the group's shared workspace
        and inherit all permissions defined in the group's policy.

        Note:
            This operation is idempotent - adding a user who is already a member
            of the group will succeed without any changes or errors.

        Args:
            username: The username to add to the group
            group_name: The name of the group to add the user to
        """
        async with self.operation_context("add_user_to_group"):
            # Check if group exists
            if not await self.resource_exists(group_name):
                raise GroupNotFoundError(f"Group {group_name} not found")

            # Check if user exists
            if not await self.user_manager.resource_exists(username):
                raise GroupOperationError(f"User {username} does not exist")

            # MinIO group add is idempotent - adding an existing member is a no-op
            # so we don't need to check if user is already in the group

            # Add user to group
            cmd_args = self._command_builder.build_group_command(
                GroupAction.ADD, group_name, [username]
            )
            result = await self._executor._execute_command(cmd_args)
            if not result.success:
                raise GroupOperationError(
                    f"Failed to add user to group: {result.stderr}"
                )

            # Membership of this group just changed; bust the cache so
            # subsequent reads in this pod see the new member.
            self._invalidate_members(group_name)
            logger.info(f"Added user {username} to group {group_name}")

    async def remove_user_from_group(self, username: str, group_name: str) -> None:
        """
        Remove a user from a MinIO group, revoking their group access permissions.

        This method handles the complete user removal workflow:
        1. Validates that the group exists
        2. Removes the user from the group in MinIO (idempotent - safe if not a member)
        3. The user loses access to group policies and shared workspace

        After removal, the user will no longer have access to the group's shared
        workspace or inherit the group's permissions, but retains their individual
        user permissions.

        Note:
            This operation is idempotent - removing a user who is not a member
            of the group will succeed without any changes or errors.

        Args:
            username: The username to remove from the group
            group_name: The name of the group to remove the user from
        """
        async with self.operation_context("remove_user_from_group"):
            # Check if group exists
            if not await self.resource_exists(group_name):
                raise GroupNotFoundError(f"Group {group_name} not found")

            # MinIO group remove is idempotent - removing a non-member is a no-op
            # so we don't need to check if user is actually in the group

            # Remove user from group
            cmd_args = self._command_builder.build_group_command(
                GroupAction.RM, group_name, [username]
            )
            result = await self._executor._execute_command(cmd_args)
            if not result.success:
                raise GroupOperationError(
                    f"Failed to remove user from group: {result.stderr}"
                )

            # Membership of this group just changed; bust the cache so
            # subsequent reads in this pod see the removal.
            self._invalidate_members(group_name)
            logger.info(f"Removed user {username} from group {group_name}")

    async def get_group_members(self, group_name: str) -> List[str]:
        """
        Retrieve a list of all usernames that are members of the specified group.

        Reads are served from a per-process TTL cache with single-flight
        protection: concurrent misses for the same group share one MC
        subprocess call, and mutations on this manager
        (``add_user_to_group``, ``remove_user_from_group``) explicitly
        invalidate the relevant key for read-after-write consistency
        within the pod.

        Args:
            group_name: The name of the group to get members for
        """
        return await self._members_cache.get_or_load(
            group_name, lambda: self._fetch_group_members(group_name)
        )

    async def _fetch_group_members(self, group_name: str) -> List[str]:
        """Uncached MC fetch backing :meth:`get_group_members`.

        Kept private so the cache layer is the only entry point for
        callers; tests can still target this directly to exercise the
        underlying MC call without cache interference.

        Implementation note: this used to issue *two* MC subprocess
        calls per invocation — first ``resource_exists()`` (which
        itself runs ``mc admin group info <group>``) and then
        ``mc admin group info <group> --json``. Both ran the same MC
        sub-command; the first throwaway call was used purely to
        distinguish "group not found" from "transient error". We now
        make a single ``--json`` call and infer the not-found case
        from the MC error string in stderr. Halves the underlying MC
        call volume on every cache miss.
        """
        async with self.operation_context("get_group_members"):
            cmd_args = self._command_builder.build_group_command(
                GroupAction.INFO, group_name, json_format=True
            )
            result = await self._executor._execute_command(cmd_args)
            if not result.success:
                # mc returns a non-zero exit when the group does not
                # exist; surface that as GroupNotFoundError to mirror
                # the prior behavior of the resource_exists()-based
                # pre-check. Other failures stay as GroupOperationError
                # so callers can distinguish transient/network issues.
                stderr_lower = result.stderr.lower()
                if "does not exist" in stderr_lower or "not found" in stderr_lower:
                    raise GroupNotFoundError(f"Group {group_name} not found")
                raise GroupOperationError(f"Failed to get group info: {result.stderr}")

            members = await self._parse_group_members(result.stdout)
            logger.info(f"Found {len(members)} members in group {group_name}")
            return members

    async def get_group_info(self, group_name: str) -> GroupModel:
        """
        Retrieve comprehensive information about an existing group including members and policy details.

        This method gathers complete group information by:
        1. Verifying the group exists in MinIO
        2. Collecting all current group members
        3. Loading the group's policy information
        4. Building a complete GroupModel with all details

        The returned model provides a complete view of the group's configuration
        and can be used for administrative purposes and access management.

        Args:
            group_name: The name of the group to retrieve information for
        """
        async with self.operation_context("get_group_info"):
            # Check if group exists
            if not await self.resource_exists(group_name):
                raise GroupNotFoundError(f"Group {group_name} not found")

            # Get group members
            members = await self.get_group_members(group_name)

            # Get group policy
            group_policy_model = await self.policy_manager.get_group_policy(group_name)
            policy_name = group_policy_model.policy_name

            # Create domain model
            group_model = GroupModel(
                group_name=group_name,
                members=members,
                policy_name=policy_name,
            )

            logger.info(f"Retrieved info for group {group_name}")
            return group_model

    async def is_user_in_group(self, username: str, group_name: str) -> bool:
        """
        Check if a specific user is a member of a specific group.

        This method queries the group membership to determine if the user
        is currently a member. It's useful for authorization checks and
        membership validation before performing group operations.

        Args:
            username: The username to check for membership
            group_name: The name of the group to check membership in
        """
        try:
            members = await self.get_group_members(group_name)
            return username in members
        except Exception as e:
            raise GroupOperationError(
                f"Failed to check if user {username} is in group {group_name}"
            ) from e

    async def get_user_groups(self, username: str) -> List[str]:
        """
        Retrieve all group names that a specific user is a member of.

        Implementation note: this issues a single ``mc admin user info <user> --json``
        call and reads the ``memberOf`` field from the response. Older versions
        of this method iterated every group in the system and called
        ``get_group_members`` per group, which made the call cost grow as
        ``O(num_groups * mc_subprocesses)``. The rewrite is O(1) MC calls.

        Args:
            username: The username to get group memberships for

        Raises:
            GroupNotFoundError: if the user does not exist in MinIO.
            GroupOperationError: if the MC command fails for any other reason
                or the response cannot be parsed.
        """
        async with self.operation_context("get_user_groups"):
            validate_username(username)

            cmd_args = self._command_builder.build_user_command(
                UserAction.INFO, username, json_format=True
            )
            result = await self._executor._execute_command(cmd_args)

            if not result.success:
                # mc returns a non-zero exit when the user does not exist; we
                # surface that as GroupNotFoundError to mirror the prior
                # behavior of resource_exists() returning False.
                stderr_lower = result.stderr.lower()
                if "does not exist" in stderr_lower or "not found" in stderr_lower:
                    raise GroupNotFoundError(f"User {username} not found")
                raise GroupOperationError(
                    f"Failed to get user info for {username}: {result.stderr}"
                )

            try:
                user_info = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise GroupOperationError(
                    f"Failed to parse user info for {username}: {result.stdout}"
                ) from e

            # `memberOf` is an array (or absent for users with no groups).
            user_groups = sorted(user_info.get("memberOf", []) or [])
            logger.info(f"User {username} is a member of {len(user_groups)} groups")
            return user_groups

    # Private helper methods

    async def _parse_group_members(self, group_info_output: str) -> List[str]:
        """Parse group members from 'mc admin group info --json' output.

        Example JSON responses:
        - With members: {"status":"success","groupName":"global-user-group","members":["user1"],"groupStatus":"enabled","groupPolicy":"group-policy-global-user-group"}
        - Empty group: {"status":"success","groupName":"global-user-group","groupStatus":"enabled","groupPolicy":"group-policy-global-user-group"}

        Returns:
            List of member usernames, or empty list if group has no members.
        """
        try:
            group_info = json.loads(group_info_output)
            return group_info.get("members", [])
        except Exception as e:
            raise GroupOperationError(
                f"Failed to parse group members: {group_info_output}"
            ) from e

    async def _create_group_shared_directory(self, group_name: str) -> None:
        """Create group shared directory structure similar to user home directory."""
        bucket_name = self.config.default_bucket

        # Ensure bucket exists
        if not await self.client.bucket_exists(bucket_name):
            await self.client.create_bucket(bucket_name)

        # Create group directory structure
        await self._create_group_directory_structure(group_name, bucket_name)
        await self._create_group_welcome_file(group_name, bucket_name)

    async def _create_group_directory_structure(
        self, group_name: str, bucket_name: str
    ) -> None:
        """Create the group's shared directory structure."""
        group_paths = [
            f"{self.tenant_sql_warehouse_prefix}/{group_name}/",
            f"{self.tenant_general_warehouse_prefix}/{group_name}/",
            f"{self.tenant_general_warehouse_prefix}/{group_name}/shared/",
            f"{self.tenant_general_warehouse_prefix}/{group_name}/datasets/",
            f"{self.tenant_general_warehouse_prefix}/{group_name}/projects/",
        ]

        # Create directory markers
        for path in group_paths:
            # Create directory marker
            marker_key = f"{path}.s3keep"
            await self.client.put_object(
                bucket_name, marker_key, b"Group directory marker"
            )

    async def _create_group_welcome_file(
        self, group_name: str, bucket_name: str
    ) -> None:
        """Create a welcome file for the new group."""
        welcome_content = f"""Welcome to the {group_name} group shared workspace!

This is a shared space for all members of the {group_name} group.
All group members have full read/write access to this space.

Directory structure:
- shared/: General shared files and documents
- datasets/: Shared datasets for the group  
- projects/: Collaborative project workspaces

Happy collaborating!
""".encode()

        welcome_key = f"{self.tenant_general_warehouse_prefix}/{group_name}/README.txt"
        await self.client.put_object(bucket_name, welcome_key, welcome_content)

    async def _delete_group_shared_directory(self, group_name: str) -> None:
        """Delete group shared directories and all contents (both SQL and general warehouse)."""
        bucket_name = self.config.default_bucket

        # Delete both warehouse directories
        prefixes = [
            f"{self.tenant_general_warehouse_prefix}/{group_name}/",
            f"{self.tenant_sql_warehouse_prefix}/{group_name}/",
        ]

        for group_prefix in prefixes:
            try:
                # List all objects in group directory
                objects = await self.client.list_objects(
                    bucket_name, group_prefix, list_all=True
                )

                # Delete objects
                for obj_key in objects:
                    await self.client.delete_object(bucket_name, obj_key)

                logger.info(f"Deleted {len(objects)} objects from {group_prefix}")
            except Exception as e:
                logger.warning(
                    f"Failed to delete group directory {group_prefix} for {group_name}: {e}"
                )
