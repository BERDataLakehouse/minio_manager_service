import json
import logging
import tempfile
import uuid
from pathlib import Path
from typing import Callable, List, Optional

from ...service.exceptions import PolicyOperationError
from ..core.distributed_lock import DistributedLockManager
from ..core.minio_client import MinIOClient
from ..core.policy_builder import PolicyBuilder
from ..core.policy_creator import PolicyCreator
from ..models.command import PolicyAction as CommandPolicyAction
from ..models.minio_config import MinIOConfig
from ..models.policy import (
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
    PolicyTarget,
    PolicyType,
)
from ..utils.validators import (
    DATA_GOVERNANCE_POLICY_PREFIXES,
    GROUP_POLICY_PREFIX,
    USER_HOME_POLICY_PREFIX,
    USER_SYSTEM_POLICY_PREFIX,
    validate_policy_name,
)
from .resource_manager import ResourceManager

logger = logging.getLogger(__name__)

RESOURCE_TYPE = "policy"


class PolicyManager(ResourceManager[PolicyModel]):
    """
    PolicyManager for core policy CRUD operations with generic CRUD patterns.

    This manager handles:
    - Creating, reading, updating, deleting policies
    - Policy attachment/detachment to users/groups
    - Low-level policy manipulation and validation
    - Policy templates and document generation
    """

    def __init__(
        self,
        client: MinIOClient,
        config: MinIOConfig,
        lock_manager: Optional[DistributedLockManager] = None,
    ) -> None:
        """
        Initialize the PolicyManager.

        Args:
            client: MinIO client instance used for executing commands and object ops.
            config: MinIO configuration for bucket and path conventions.
            lock_manager: Optional distributed lock manager. Required for any
                operations that modify an existing policy's contents (e.g.,
                add_path_access_for_target, remove_path_access_for_target),
                which acquire a lock to ensure safe read-modify-write across instances.

        Notes:
            - Read-only operations (listing, loading policies, computing accessible
              paths, generating names) do not require a lock manager.
            - If a modifying method is called without a lock manager, a
              PolicyOperationError will be raised.
        """
        super().__init__(client, config)
        self._lock_manager = lock_manager

    # === ResourceManager Abstract Method Implementations ===

    def _get_resource_type(self) -> str:
        """Get the resource type name."""
        return RESOURCE_TYPE

    def _validate_resource_name(self, name: str) -> str:
        """Validate and normalize a policy name."""
        return validate_policy_name(name)

    def _build_exists_command(self, name: str) -> List[str]:
        """Build command to check if policy exists."""
        return self._command_builder.build_policy_command(
            CommandPolicyAction.INFO, name
        )

    def _build_list_command(self) -> List[str]:
        """Build command to list all policies."""
        return self._command_builder.build_policy_command(
            CommandPolicyAction.LIST, json_format=True
        )

    def _build_delete_command(self, name: str) -> List[str]:
        """Build command to delete a policy."""
        return self._command_builder.build_policy_command(
            CommandPolicyAction.DELETE, name
        )

    def _parse_list_output(self, stdout: str) -> List[str]:
        """Parse policy list command JSON output."""
        try:
            policy_names = []
            # Each line is a separate JSON object with format: {"status":"success","policy":"policyname",...}
            for line in stdout.strip().split("\n"):
                if line.strip():
                    policy_data = json.loads(line)
                    policy_names.append(policy_data["policy"])
            return policy_names
        except Exception as e:
            raise PolicyOperationError(
                f"Failed to parse policy list command output: {stdout}"
            ) from e

    # === Read-modify-write policy updates (under lock) ===

    async def add_path_access_for_target(
        self,
        target_type: PolicyTarget,
        target_name: str,
        path: str,
        permission_level: PolicyPermissionLevel,
    ) -> None:
        """
        Grant path access to a target (user or group) using a safe read-modify-write.

        The method acquires the distributed lock for the target's policy, reloads the
        latest policy while holding the lock, applies the change (add path access), and
        persists via the shadow-policy update flow.

        Args:
            target_type: The policy target type (user or group).
            target_name: The username or group name.
            path: The S3 path to grant (e.g., "s3a://bucket/data/project/").
            permission_level: The access level to grant for the path.
        """
        async with self.operation_context("add_path_access_for_target"):
            await self._update_policy_for_target_with_transform(
                target_type,
                target_name,
                lambda current: self.add_path_access_to_policy(
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

        The method acquires the distributed lock for the target's policy, reloads the
        latest policy while holding the lock, applies the change (remove path access),
        and persists via the shadow-policy update flow.

        Args:
            target_type: The policy target type (user or group).
            target_name: The username or group name.
            path: The S3 path to revoke (e.g., "s3a://bucket/data/project/").
        """
        async with self.operation_context("remove_path_access_for_target"):
            await self._update_policy_for_target_with_transform(
                target_type,
                target_name,
                lambda current: self.remove_path_access_from_policy(current, path),
            )

    def _get_policy_name_for_target(
        self, target_type: PolicyTarget, target_name: str
    ) -> str:
        """
        Resolve the MinIO policy name for a given target.

        Note:
            - USER targets map to user home policy
            - GROUP targets map to group home policy
            - User System policy are not used for path access updates
        """
        if target_type == PolicyTarget.USER:
            return self.get_policy_name(PolicyType.USER_HOME, target_name)
        elif target_type == PolicyTarget.GROUP:
            return self.get_policy_name(PolicyType.GROUP_HOME, target_name)
        else:
            raise PolicyOperationError(
                f"Unsupported target type for path access update: {target_type}"
            )

    async def _load_policy_for_target(
        self, target_type: PolicyTarget, target_name: str
    ) -> PolicyModel:
        """
        Load the current PolicyModel for a target from MinIO.

        Note:
            - USER targets map to user home policy
            - GROUP targets map to group home policy
            - User System policy are not used for path access updates
        """
        if target_type == PolicyTarget.USER:
            policy_model = await self.get_user_home_policy(target_name)
        elif target_type == PolicyTarget.GROUP:
            policy_model = await self.get_group_policy(target_name)
        else:
            raise PolicyOperationError(
                f"Unsupported target type for path access update: {target_type}"
            )

        return policy_model

    async def _update_policy_for_target_with_transform(
        self,
        target_type: PolicyTarget,
        target_name: str,
        transform: Callable[[PolicyModel], PolicyModel],
    ) -> None:
        """
        This helper ensures consistency by acquiring the distributed lock for the
        resolved policy, reloading the latest policy document while holding the lock,
        applying the provided transformation function to produce a new PolicyModel,
        and then persisting the change using the shadow-policy flow.
        """
        policy_name = self._get_policy_name_for_target(target_type, target_name)
        if not self._lock_manager:
            raise PolicyOperationError("Distributed lock manager not initialized")
        async with self._lock_manager.policy_update_lock(policy_name):
            # Re-load inside the lock for latest
            current_policy_model = await self._load_policy_for_target(
                target_type, target_name
            )
            updated_policy = transform(current_policy_model)
            await self._update_minio_policy(updated_policy)

    # === USER/GROUP POLICY MANAGEMENT ===

    async def ensure_user_policies(
        self, username: str
    ) -> tuple[PolicyModel, PolicyModel]:
        """
        Ensure both home and system policies exist for a user.

        This method guarantees that the user has both required policies:
        - Home policy: Access to user's personal warehouses
        - System policy: Access to system resources (logs, etc.)

        If policies already exist, they are returned as-is. If they don't exist,
        they are created with default permissions. This method is safe to call
        multiple times and will not fail if policies already exist.

        Args:
            username: Username to ensure policies for
        """
        async with self.operation_context("create_user_policy"):
            # Create both policy models
            home_policy = self._create_user_home_policy(username)
            system_policy = self._create_user_system_policy(username)

            # Check if home policy already exists
            # NOTE: Race condition possible - policy could be created between this check and creation
            home_exists = await self.resource_exists(home_policy.policy_name)
            if home_exists:
                logger.info(
                    f"User home policy already exists: {home_policy.policy_name}"
                )
                # Load existing policy to return
                home_policy = await self._load_minio_policy(home_policy.policy_name)
            else:
                # Create home policy
                # NOTE: _create_minio_policy will overwrite existing policies
                await self._create_minio_policy(home_policy)
                logger.info(f"Created user home policy: {home_policy.policy_name}")

            # Check if system policy already exists
            # NOTE: Race condition possible - policy could be created between this check and creation
            system_exists = await self.resource_exists(system_policy.policy_name)
            if system_exists:
                logger.info(
                    f"User system policy already exists: {system_policy.policy_name}"
                )
                # Load existing policy to return
                system_policy = await self._load_minio_policy(system_policy.policy_name)
            else:
                # Create system policy
                # NOTE: _create_minio_policy will overwrite existing policies
                await self._create_minio_policy(system_policy)
                logger.info(f"Created system policy: {system_policy.policy_name}")

            return home_policy, system_policy  # type: ignore

    def _create_policy_model(
        self, policy_type: PolicyType, target_name: str
    ) -> PolicyModel:
        """Create a policy model for the given type and target."""
        try:
            builder = PolicyCreator(
                policy_type=policy_type,
                target_name=target_name,
                config=self.config,
            )
            return builder.create_default_policy().build()
        except Exception as e:
            policy_desc = policy_type.value.replace("_", " ")
            logger.error(
                f"Failed to create {policy_desc} policy for {target_name}: {e}"
            )
            raise PolicyOperationError(
                f"Failed to create {policy_desc} policy: {e}"
            ) from e

    def _create_user_home_policy(self, username: str) -> PolicyModel:
        """Create user home policy"""
        return self._create_policy_model(PolicyType.USER_HOME, username)

    def _create_user_system_policy(self, username: str) -> PolicyModel:
        """Create user system policy"""
        return self._create_policy_model(PolicyType.USER_SYSTEM, username)

    async def ensure_group_policy(
        self, group_name: str, read_only: bool = False
    ) -> PolicyModel:
        """
        Ensure group policy exists for a group.

        This method guarantees that the group has a policy for shared workspace access.
        The policy provides access to the group's shared directory structure.

        If the policy already exists, it is returned as-is. If it doesn't exist,
        it is created with default group permissions. This method is safe to call
        multiple times and will not fail if the policy already exists.

        Args:
            group_name: Group name to ensure policy for
            read_only: If True, create policy with READ-only permissions
        """
        op_name = (
            "create_group_policy_read_only" if read_only else "create_group_policy"
        )
        async with self.operation_context(op_name):
            policy_type = (
                PolicyType.GROUP_HOME_RO if read_only else PolicyType.GROUP_HOME
            )
            policy_name = self.get_policy_name(policy_type, group_name)

            # Check if policy already exists
            policy_exists = await self.resource_exists(policy_name)
            if policy_exists:
                suffix = " (read-only)" if read_only else ""
                logger.info(f"Group policy{suffix} already exists: {policy_name}")
                return await self._load_minio_policy(policy_name)  # type: ignore

            # Create policy with appropriate permissions
            policy = self._create_group_home_policy(group_name, read_only=read_only)

            await self._create_minio_policy(policy)
            suffix = " (read-only)" if read_only else ""
            logger.info(f"Created group policy{suffix}: {policy_name}")

            return policy

    def _create_group_home_policy(
        self, group_name: str, read_only: bool = False
    ) -> PolicyModel:
        """Create group home policy.

        Args:
            group_name: Group name
            read_only: If True, create read-only policy with READ permissions
        """
        policy_type = PolicyType.GROUP_HOME_RO if read_only else PolicyType.GROUP_HOME
        return self._create_policy_model(policy_type, group_name)

    async def get_user_home_policy(self, username: str) -> PolicyModel:
        """
        Retrieve the user's home policy from MinIO.

        Args:
            username: Username to get home policy for
        """
        async with self.operation_context("get_user_home_policy"):
            policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
            result = await self._load_minio_policy(policy_name)
            if result is None:
                raise PolicyOperationError(
                    f"User home policy {policy_name} not found or unsupported"
                )
            return result

    async def get_user_system_policy(self, username: str) -> PolicyModel:
        """
        Retrieve the user's system policy from MinIO.

        Args:
            username: Username to get system policy for
        """
        async with self.operation_context("get_user_system_policy"):
            policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)
            result = await self._load_minio_policy(policy_name)
            if result is None:
                raise PolicyOperationError(
                    f"User system policy {policy_name} not found or unsupported"
                )
            return result

    async def get_group_policy(
        self, group_name: str, read_only: bool = False
    ) -> PolicyModel:
        """
        Retrieve the existing policy for a specific group with proper error handling.

        Args:
            group_name: Group name to get policy for
            read_only: If True, get read-only policy instead of write policy
        """
        async with self.operation_context("get_group_policy"):
            policy_type = (
                PolicyType.GROUP_HOME_RO if read_only else PolicyType.GROUP_HOME
            )
            policy_name = self.get_policy_name(policy_type, group_name)
            result = await self._load_minio_policy(policy_name)
            if result is None:
                raise PolicyOperationError(
                    f"Group policy {policy_name} not found or unsupported"
                )
            return result

    async def delete_user_policies(self, username: str) -> None:
        """
        Delete both home and system policies for a user.

        Args:
            username: Username to delete policies for

        Raises:
            PolicyOperationError: If policy deletion fails
        """
        async with self.operation_context("delete_user_policy"):
            home_policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
            system_policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)

            errors = []

            # Try to delete home policy
            try:
                success = await self.delete_resource(home_policy_name)
                if success:
                    logger.info(f"Deleted user home policy: {home_policy_name}")
                else:
                    errors.append(f"Failed to delete home policy: {home_policy_name}")
            except Exception as e:
                logger.error(f"Error deleting home policy {home_policy_name}: {e}")
                errors.append(f"Error deleting home policy: {e}")

            # Try to delete system policy
            try:
                success = await self.delete_resource(system_policy_name)
                if success:
                    logger.info(f"Deleted system policy: {system_policy_name}")
                else:
                    errors.append(
                        f"Failed to delete system policy: {system_policy_name}"
                    )
            except Exception as e:
                logger.error(f"Error deleting system policy {system_policy_name}: {e}")
                errors.append(f"Error deleting system policy: {e}")

            # Raise error if any deletions failed
            if errors:
                error_msg = "; ".join(errors)
                raise PolicyOperationError(
                    f"Failed to delete user policies: {error_msg}"
                )

    async def delete_group_policy(
        self, group_name: str, read_only: bool = False
    ) -> None:
        """
        Delete a group's policy from MinIO with proper cleanup.

        Args:
            group_name: Group name to delete policy for
            read_only: If True, delete the read-only policy; otherwise delete main policy
        """
        op_name = (
            "delete_group_policy_read_only" if read_only else "delete_group_policy"
        )
        async with self.operation_context(op_name):
            policy_type = (
                PolicyType.GROUP_HOME_RO if read_only else PolicyType.GROUP_HOME
            )
            policy_name = self.get_policy_name(policy_type, group_name)
            suffix = " (read-only)" if read_only else ""

            try:
                success = await self.delete_resource(policy_name)
                if success:
                    logger.info(f"Deleted group policy{suffix}: {policy_name}")
                else:
                    raise PolicyOperationError(
                        f"Failed to delete group policy{suffix}: {policy_name}"
                    )
            except PolicyOperationError:
                raise
            except Exception as e:
                logger.error(f"Error deleting group policy{suffix} {policy_name}: {e}")
                raise PolicyOperationError(f"Error deleting group policy{suffix}: {e}")

    # === POLICY ATTACHMENT OPERATIONS ===

    async def attach_user_policies(self, username: str) -> None:
        """
        Attach both home and system policies to a user.


        Args:
            username: Username to attach policies to

        Raises:
            PolicyOperationError: If policy attachment fails or policies don't exist

        """
        async with self.operation_context("attach_user_policies"):
            home_policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
            system_policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)

            # Check current attachment status
            attachment_status = await self._check_user_policy_attachment_status(
                username, home_policy_name, system_policy_name
            )

            # Skip if both policies are already attached
            if attachment_status["both_attached"]:
                logger.info(f"Both policies already attached to user {username}")
                return

            # Validate policies exist
            await self._validate_user_policies_exist(
                home_policy_name, system_policy_name
            )

            # Attach policies with rollback on failure
            await self._attach_user_policies(
                username, home_policy_name, system_policy_name, attachment_status
            )

    async def _check_user_policy_attachment_status(
        self, username: str, home_policy_name: str, system_policy_name: str
    ) -> dict[str, bool]:
        """Check current attachment status of user policies."""
        home_already_attached = await self._is_policy_attached_to_target(
            home_policy_name, PolicyTarget.USER, username
        )
        system_already_attached = await self._is_policy_attached_to_target(
            system_policy_name, PolicyTarget.USER, username
        )

        return {
            "home_attached": home_already_attached,
            "system_attached": system_already_attached,
            "both_attached": home_already_attached and system_already_attached,
        }

    async def _validate_user_policies_exist(
        self, home_policy_name: str, system_policy_name: str
    ) -> None:
        """Validate that both user policies exist before attachment."""
        try:
            home_policy = await self._load_minio_policy(home_policy_name)
            system_policy = await self._load_minio_policy(system_policy_name)
            if home_policy is None or system_policy is None:
                raise PolicyOperationError(
                    "One or both policies do not exist or are unsupported"
                )
        except Exception as e:
            raise PolicyOperationError(
                f"Cannot attach policies - one or both policies do not exist: {e}"
            ) from e

    async def _attach_user_policies(
        self,
        username: str,
        home_policy_name: str,
        system_policy_name: str,
        attachment_status: dict[str, bool],
    ) -> None:
        """Attach user policies."""
        home_was_attached_before = attachment_status["home_attached"]
        system_was_attached_before = attachment_status["system_attached"]

        try:
            # Attach home policy if not already attached
            if not home_was_attached_before:
                await self.attach_policy_to_user(home_policy_name, username)
                logger.info(
                    f"Attached home policy {home_policy_name} to user {username}"
                )

            # Attach system policy if not already attached
            if not system_was_attached_before:
                await self.attach_policy_to_user(system_policy_name, username)
                logger.info(
                    f"Attached system policy {system_policy_name} to user {username}"
                )

        except Exception as e:
            raise PolicyOperationError(f"Failed to attach user policies: {e}") from e

    async def detach_user_policies(self, username: str) -> None:
        """
        Detach both home and system policies from a user.

        Args:
            username: Username to detach policies from

        Raises:
            PolicyOperationError: If policy detachment fails
        """
        async with self.operation_context("detach_user_policies"):
            home_policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
            system_policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)

            errors = []

            # Try to detach home policy
            try:
                await self.detach_policy_from_user(home_policy_name, username)
                logger.info(
                    f"Detached home policy {home_policy_name} from user {username}"
                )
            except Exception as e:
                logger.error(f"Error detaching home policy {home_policy_name}: {e}")
                errors.append(f"Error detaching home policy: {e}")

            # Try to detach system policy
            try:
                await self.detach_policy_from_user(system_policy_name, username)
                logger.info(
                    f"Detached system policy {system_policy_name} from user {username}"
                )
            except Exception as e:
                logger.error(f"Error detaching system policy {system_policy_name}: {e}")
                errors.append(f"Error detaching system policy: {e}")

            # Raise error if any detachments failed
            if errors:
                error_msg = "; ".join(errors)
                raise PolicyOperationError(
                    f"Failed to detach user policies: {error_msg}"
                )

    async def attach_policy_to_user(self, policy_name: str, username: str) -> None:
        """
        Attach an existing policy to a user, granting them the policy's permissions.

        Args:
            policy_name: The name of the policy to attach
            username: The username to attach the policy to
        """
        await self._attach_detach_policy(
            policy_name, PolicyTarget.USER, username, attach=True
        )

    async def detach_policy_from_user(self, policy_name: str, username: str) -> None:
        """
        Detach a policy from a user, removing the policy's permissions from the user.

        Args:
            policy_name: The name of the policy to detach
            username: The username to detach the policy from
        """
        await self._attach_detach_policy(
            policy_name, PolicyTarget.USER, username, attach=False
        )

    async def attach_policy_to_group(self, policy_name: str, group_name: str) -> None:
        """
        Attach an existing policy to a group, granting all group members the policy's permissions.

        Args:
            policy_name: The name of the policy to attach
            group_name: The group name to attach the policy to
        """
        await self._attach_detach_policy(
            policy_name, PolicyTarget.GROUP, group_name, attach=True
        )

    async def detach_policy_from_group(self, policy_name: str, group_name: str) -> None:
        """
        Detach a policy from a group, removing the policy's permissions from all group members.

        Args:
            policy_name: The name of the policy to detach
            group_name: The group name to detach the policy from
        """
        await self._attach_detach_policy(
            policy_name, PolicyTarget.GROUP, group_name, attach=False
        )

    async def is_policy_attached_to_group(self, group_name: str) -> bool:
        """
        Check if the group's policy is attached to the group.

        Args:
            group_name: The name of the group to check

        Returns:
            bool: True if the group's policy is attached to the group, False otherwise
        """
        policy_name = self.get_policy_name(PolicyType.GROUP_HOME, group_name)
        return await self._is_policy_attached_to_target(
            policy_name, PolicyTarget.GROUP, group_name
        )

    async def is_policies_attached_to_user(self, username: str) -> bool:
        """
        Check if both user policies (home and system) are attached to the user.

        Args:
            username: The name of the user to check

        Returns:
            bool: True if BOTH user policies are attached to the user, False otherwise
        """
        home_policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
        system_policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)

        home_attached = await self._is_policy_attached_to_target(
            home_policy_name, PolicyTarget.USER, username
        )
        system_attached = await self._is_policy_attached_to_target(
            system_policy_name, PolicyTarget.USER, username
        )

        return home_attached and system_attached

    async def _attach_detach_policy(
        self,
        policy_name: str,
        target_type: PolicyTarget,
        target_name: str,
        attach: bool,
    ) -> None:
        """Generic method to attach or detach a policy to/from a user or group."""
        operation = "attach" if attach else "detach"
        operation_context = f"{operation}_policy_to_{target_type.value}"

        async with self.operation_context(operation_context):
            if attach:
                cmd_args = self._command_builder.build_policy_attach_command(
                    policy_name, target_type.value, target_name
                )
            else:
                cmd_args = self._command_builder.build_policy_detach_command(
                    policy_name, target_type.value, target_name
                )

            result = await self._executor._execute_command(cmd_args)

            if not result.success:
                raise PolicyOperationError(
                    f"Failed to {operation} policy {policy_name} {'to' if attach else 'from'} {target_type.value} {target_name}: {result.stderr}"
                )
            logger.info(
                f"{'Attached' if attach else 'Detached'} policy {policy_name} {'to' if attach else 'from'} {target_type.value} {target_name}"
            )

    async def _is_policy_attached_to_target(
        self, policy_name: str, target_type: PolicyTarget, target_name: str
    ) -> bool:
        """Check if a specific policy is attached to a target (user or group)."""
        entities = await self._get_policy_attached_entities(policy_name)
        return target_name in entities[target_type]

    async def _get_policy_attached_entities(
        self, policy_name: str
    ) -> dict[PolicyTarget, list[str]]:
        """Get all entities (users and groups) that have a specific policy attached."""
        cmd_args = self._command_builder.build_policy_entities_command(policy_name)
        result = await self._executor._execute_command(cmd_args)

        if not result.success:
            raise PolicyOperationError(
                f"Failed to get entities for policy {policy_name}: {result.stderr}"
            )

        return self._parse_policy_entities_output(result.stdout)

    def _parse_policy_entities_output(
        self, output: str
    ) -> dict[PolicyTarget, list[str]]:
        """Parse the JSON output of 'mc admin policy entities --json' command."""

        entities = {PolicyTarget.USER: [], PolicyTarget.GROUP: []}

        # Parse the JSON output
        data = json.loads(output.strip())

        # Extract policy mappings from result
        result = data.get("result", {})
        policy_mappings = result.get("policyMappings", [])

        # Process each policy mapping
        for mapping in policy_mappings:
            # Extract users
            users = mapping.get("users", [])
            if users:
                entities[PolicyTarget.USER].extend(users)

            # Extract groups
            groups = mapping.get("groups", [])
            if groups:
                entities[PolicyTarget.GROUP].extend(groups)

        return entities

    # === POLICY DOCUMENT MANIPULATION ===

    def add_path_access_to_policy(
        self,
        policy_model: PolicyModel,
        path: str,
        permission_level: PolicyPermissionLevel,
    ) -> PolicyModel:
        """
        Add access permissions for a specific path to an existing policy model.

        This method uses the PolicyBuilder pattern to create a new policy model
        with the added path access. The original policy model is not modified.

        Args:
            policy_model: The policy model to base modifications on
            path: The S3 path to grant access to (e.g., "s3a://bucket/path/to/data")
            permission_level: The level of access to grant (READ, WRITE, or ADMIN)

        Note:
            This method only modifies the policy model in memory. Call update_policy()
            to persist the changes to MinIO.
        """
        try:
            builder = PolicyBuilder(policy_model, self.config.default_bucket)
            return builder.add_path_access(path, permission_level).build()
        except Exception as e:
            logger.error(
                f"Failed to add path access {path} to policy {policy_model.policy_name}: {e}"
            )
            raise PolicyOperationError(f"Failed to add path access: {e}") from e

    def remove_path_access_from_policy(
        self, policy_model: PolicyModel, path: str
    ) -> PolicyModel:
        """
        Remove access permissions for a specific path from an existing policy model.

        This method uses the PolicyBuilder pattern to create a new policy model
        with the path access removed. The original policy model is not modified.

        Args:
            policy_model: The policy model to base modifications on
            path: The S3 path to revoke access from (e.g., "s3a://bucket/path/to/data")

        Note:
            This method only modifies the policy model in memory. Call update_policy()
            to persist the changes to MinIO.
        """
        try:
            builder = PolicyBuilder(policy_model, self.config.default_bucket)
            return builder.remove_path_access(path).build()
        except Exception as e:
            logger.error(
                f"Failed to remove path access {path} from policy {policy_model.policy_name}: {e}"
            )
            raise PolicyOperationError(f"Failed to remove path access: {e}") from e

    # === POLICY ANALYSIS METHODS ===

    def get_accessible_paths_from_policy(self, policy_model: PolicyModel) -> list[str]:
        """
        Extract all S3 paths that are accessible through the given policy.

        This method analyzes all statements in the policy and extracts the S3 paths
        that the policy grants access to. It converts internal ARN formats back to
        user-friendly s3a:// URLs.

        Args:
            policy_model: The policy model to analyze
        """
        paths: set[str] = set()

        for statement in policy_model.policy_document.statement:
            if statement.effect == PolicyEffect.ALLOW:
                extracted_paths = self._extract_paths_from_statement(statement)
                paths.update(extracted_paths)

        return sorted(paths)

    def _extract_paths_from_statement(self, statement: PolicyStatement) -> set[str]:
        """Extract accessible paths from a policy statement."""
        paths: set[str] = set()
        resources = self._normalize_resources_to_list(statement.resource)

        for resource in resources:
            if path := self._extract_path_from_resource_arn(resource):
                paths.add(path)

        return paths

    def _normalize_resources_to_list(self, resource: str | list[str]) -> list[str]:
        """Normalize resource field to a list of strings."""
        return resource if isinstance(resource, list) else [resource]

    def _extract_path_from_resource_arn(self, resource: str) -> str | None:
        """Extract s3a:// path from ARN resource string."""
        if (
            not isinstance(resource, str)
            or "arn:aws:s3:::" not in resource
            or "/*" not in resource
        ):
            return None

        arn_content = resource.split("arn:aws:s3:::")[1]
        if not arn_content.endswith("/*"):
            return None

        path_without_wildcard = arn_content.removesuffix("/*")
        path_parts = path_without_wildcard.split("/")

        if len(path_parts) < 2:
            return None

        bucket, *path_segments = path_parts
        path = "/".join(path_segments)
        return f"s3a://{bucket}/{path}/"

    # === LISTING AND UTILITY METHODS ===

    def get_policy_name(self, policy_type: PolicyType, target_name: str) -> str:
        """
        Generate a standardized policy name for a user or group.

        Args:
            policy_type: The policy type (USER_HOME/USER_SYSTEM/GROUP_HOME)
            target_name: The username or group name
        """

        try:
            builder = PolicyCreator(
                policy_type=policy_type,
                target_name=target_name,
                config=self.config,
            )
            return builder._generate_policy_name()
        except Exception as e:
            raise PolicyOperationError(f"Failed to generate policy name: {e}") from e

    async def list_all_policies(self) -> List[PolicyModel]:
        """
        Retrieve all policies from MinIO as complete PolicyModel objects.

        This method fetches all policies from the MinIO server and loads their
        complete policy documents including statements, permissions, and conditions.
        This is useful for administrative operations and policy auditing.

        Returns:
            List[PolicyModel]: A list of all policies with complete policy documents

        Raises:
            PolicyOperationError: If listing policies fails

        Note:
            This operation can be expensive if there are many policies, as it loads
            the complete policy document for each policy.
        """
        try:
            # Get policy names using generic implementation
            policy_names = await self.list_resources()

            # Load full PolicyModel objects for each policy
            policies = []
            for policy_name in policy_names:
                policy_model = await self._load_minio_policy(policy_name)
                if policy_model:
                    policies.append(policy_model)

            return policies
        except Exception:
            raise PolicyOperationError("Failed to list all policies")

    # === MinIO POLICY OPERATIONS ===

    async def _create_minio_policy(self, policy_model: PolicyModel) -> None:
        """Create policy in MinIO with retry logic."""
        policy_json = policy_model.to_minio_policy_json()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as temp_file:
            temp_file.write(policy_json)
            temp_file_path = temp_file.name

        try:
            # Use command building pattern
            # NOTE: If policy already exists, it will be overwritten.
            cmd_args = self._command_builder.build_policy_command(
                CommandPolicyAction.CREATE, policy_model.policy_name, temp_file_path
            )
            result = await self._executor._execute_command(cmd_args)

            if not result.success:
                raise PolicyOperationError(
                    f"Failed to create MinIO policy: {result.stderr}"
                )
        finally:
            # Clean up temporary file
            try:
                Path(temp_file_path).unlink()
            except Exception as e:
                logger.warning(f"Failed to cleanup temporary policy file: {e}")

    def _generate_shadow_policy_name(self, original_name: str) -> str:
        """Generate a unique shadow policy name."""
        return f"{original_name}-shadow-{uuid.uuid4().hex[:8]}"

    async def _create_shadow_policy(self, original_policy: PolicyModel) -> str:
        """Create a shadow policy with the updated content."""
        shadow_name = self._generate_shadow_policy_name(original_policy.policy_name)
        shadow_policy = PolicyModel(
            policy_name=shadow_name,
            policy_document=original_policy.policy_document,
        )

        logger.info(f"Creating shadow policy: {shadow_name}")
        await self._create_minio_policy(shadow_policy)
        logger.info(f"Successfully created shadow policy: {shadow_name}")

        return shadow_name

    def _parse_policy_info(self, policy_name: str) -> tuple[str, PolicyType]:
        """Parse policy name to extract target name and policy type."""
        if self.is_user_home_policy(policy_name):
            target_name = policy_name.replace(USER_HOME_POLICY_PREFIX, "")
            policy_type = PolicyType.USER_HOME
        elif self.is_user_system_policy(policy_name):
            target_name = policy_name.replace(USER_SYSTEM_POLICY_PREFIX, "")
            policy_type = PolicyType.USER_SYSTEM
        elif self.is_group_policy(policy_name):
            target_name = policy_name.replace(GROUP_POLICY_PREFIX, "")
            policy_type = PolicyType.GROUP_HOME
        else:
            raise PolicyOperationError(
                f"Unknown policy naming pattern: {policy_name}. "
                f"Expected {USER_HOME_POLICY_PREFIX}, {USER_SYSTEM_POLICY_PREFIX}, or {GROUP_POLICY_PREFIX} prefix."
            )
        return target_name, policy_type

    async def _execute_shadow_policy_update(
        self, policy_model: PolicyModel, target_name: str, policy_type: PolicyType
    ) -> str:
        """Execute the shadow policy update workflow."""
        # Step 1: Create shadow policy with new content
        shadow_name = await self._create_shadow_policy(policy_model)

        # Step 2: Attach shadow policy (user/group now has BOTH old and new access)
        await self._attach_shadow_policy(shadow_name, target_name, policy_type)

        # Step 3: Replace original policy with updated content
        await self._replace_original_policy(policy_model, target_name, policy_type)

        # Step 4: Cleanup shadow policy
        await self._detach_and_delete_shadow_policy(
            shadow_name, target_name, policy_type
        )

        return shadow_name

    async def _attach_shadow_policy(
        self, shadow_name: str, target_name: str, policy_type: PolicyType
    ) -> None:
        """Attach shadow policy to user or group."""
        if policy_type in [PolicyType.USER_HOME, PolicyType.USER_SYSTEM]:
            logger.info(f"Attaching shadow policy {shadow_name} to user {target_name}")
            await self.attach_policy_to_user(shadow_name, target_name)
            logger.info(
                f"User {target_name} now has access via both original and shadow policies"
            )
        elif policy_type == PolicyType.GROUP_HOME:
            logger.info(f"Attaching shadow policy {shadow_name} to group {target_name}")
            await self.attach_policy_to_group(shadow_name, target_name)
            logger.info(
                f"Group {target_name} now has access via both original and shadow policies"
            )

    async def _replace_original_policy(
        self, policy_model: PolicyModel, target_name: str, policy_type: PolicyType
    ) -> None:
        """Replace original policy with updated content."""
        policy_name = policy_model.policy_name

        # Detach original policy (user/group still has access via shadow)
        if policy_type in [PolicyType.USER_HOME, PolicyType.USER_SYSTEM]:
            logger.info(
                f"Detaching original policy {policy_name} from user {target_name}"
            )
            await self.detach_policy_from_user(policy_name, target_name)
        elif policy_type == PolicyType.GROUP_HOME:
            logger.info(
                f"Detaching original policy {policy_name} from group {target_name}"
            )
            await self.detach_policy_from_group(policy_name, target_name)

        # Delete original policy
        logger.info(f"Deleting original policy {policy_name}")
        await self.delete_resource(policy_name)

        # Create new policy with original name and updated content
        logger.info(f"Creating updated policy with original name {policy_name}")
        await self._create_minio_policy(policy_model)

        # Attach new policy with original name
        if policy_type in [PolicyType.USER_HOME, PolicyType.USER_SYSTEM]:
            logger.info(f"Attaching updated policy {policy_name} to user {target_name}")
            await self.attach_policy_to_user(policy_name, target_name)
        elif policy_type == PolicyType.GROUP_HOME:
            logger.info(
                f"Attaching updated policy {policy_name} to group {target_name}"
            )
            await self.attach_policy_to_group(policy_name, target_name)

    async def _detach_and_delete_shadow_policy(
        self, shadow_name: str, target_name: str, policy_type: PolicyType
    ) -> None:
        """Detach and delete shadow policy."""
        # Detach shadow policy
        if policy_type in [PolicyType.USER_HOME, PolicyType.USER_SYSTEM]:
            logger.info(
                f"Detaching shadow policy {shadow_name} from user {target_name}"
            )
            await self.detach_policy_from_user(shadow_name, target_name)
        elif policy_type == PolicyType.GROUP_HOME:
            logger.info(
                f"Detaching shadow policy {shadow_name} from group {target_name}"
            )
            await self.detach_policy_from_group(shadow_name, target_name)

        # Delete shadow policy
        logger.info(f"Deleting shadow policy {shadow_name}")
        await self.delete_resource(shadow_name)

    async def _cleanup_shadow_policy(
        self, shadow_name: str, target_name: str, policy_type: PolicyType
    ) -> None:
        """Clean up shadow policy on failure."""
        try:
            logger.info(f"Cleaning up shadow policy: {shadow_name}")

            # Detach shadow policy if it was attached
            if policy_type in [PolicyType.USER_HOME, PolicyType.USER_SYSTEM]:
                try:
                    await self.detach_policy_from_user(shadow_name, target_name)
                except Exception:
                    pass  # Shadow might not be attached, ignore errors
            elif policy_type == PolicyType.GROUP_HOME:
                try:
                    await self.detach_policy_from_group(shadow_name, target_name)
                except Exception:
                    pass  # Shadow might not be attached, ignore errors

            # Delete shadow policy
            await self.delete_resource(shadow_name)
            logger.info(f"Successfully cleaned up shadow policy: {shadow_name}")

        except Exception as cleanup_error:
            logger.warning(
                f"Failed to cleanup shadow policy {shadow_name}: {cleanup_error}"
            )

    async def _update_minio_policy(self, policy_model: PolicyModel) -> None:
        """Update a policy in MinIO using shadow policy pattern to eliminate access downtime."""
        policy_name = policy_model.policy_name
        target_name, policy_type = self._parse_policy_info(policy_name)

        logger.info(
            f"Updating {policy_type} policy {policy_name} for {target_name} using shadow policy pattern"
        )

        shadow_name = None
        try:
            shadow_name = await self._execute_shadow_policy_update(
                policy_model, target_name, policy_type
            )
            logger.info(
                f"Successfully updated policy {policy_name} for {target_name} with zero downtime"
            )
        except Exception as e:
            logger.error(f"Shadow policy update failed for {policy_name}: {e}")
            if shadow_name:
                await self._cleanup_shadow_policy(shadow_name, target_name, policy_type)
            raise PolicyOperationError(
                f"Failed to update policy {policy_name} using shadow policy pattern: {e}"
            ) from e

    async def _load_minio_policy(self, policy_name: str) -> Optional[PolicyModel]:
        """Load a policy from MinIO using the command executor. Returns None for unsupported built-in policies."""
        # Skip MinIO policies (built-in policies) that are not data governance policies
        if not any(
            policy_name.startswith(prefix) for prefix in DATA_GOVERNANCE_POLICY_PREFIXES
        ):
            logger.debug(f"Skipping MinIO policy: {policy_name}")
            return None

        # Get policy info from MinIO
        cmd_args = self._command_builder.build_policy_command(
            CommandPolicyAction.INFO, policy_name
        )
        result = await self._executor._execute_command(cmd_args)
        if not result.success:
            raise PolicyOperationError(f"Failed to get policy info: {result.stderr}")

        policy_data = json.loads(result.stdout)

        # Extract the actual policy from MinIO response
        policy_json = policy_data.get("Policy", policy_data)

        # Create PolicyDocument from the policy JSON
        try:
            policy_document = PolicyDocument.from_dict(policy_json)
        except Exception as e:
            raise PolicyOperationError(
                f"Failed to load policy {policy_name}: {e}"
            ) from e

        return PolicyModel(
            policy_name=policy_name,
            policy_document=policy_document,
        )

    def is_user_system_policy(self, policy_name: str) -> bool:
        """
        Check if a policy is a system policy.

        Args:
            policy_name: Policy name to check

        Returns:
            True if policy is a system policy, False otherwise
        """
        return policy_name.startswith(USER_SYSTEM_POLICY_PREFIX)

    def is_user_home_policy(self, policy_name: str) -> bool:
        """
        Check if a policy is a user home policy.

        Args:
            policy_name: Policy name to check

        Returns:
            True if policy is a user home policy, False otherwise
        """
        return policy_name.startswith(USER_HOME_POLICY_PREFIX)

    def is_group_policy(self, policy_name: str) -> bool:
        """
        Check if a policy is a group policy.

        Args:
            policy_name: Policy name to check

        Returns:
            True if policy is a group policy, False otherwise
        """
        return policy_name.startswith(GROUP_POLICY_PREFIX)
