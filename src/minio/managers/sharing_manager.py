"""
Sharing Manager for high-level data sharing workflows.

This manager orchestrates sharing operations by coordinating between
PolicyManager, UserManager, GroupManager, and PermissionService to provide
a clean, high-level API for data sharing.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel

from ...service.exceptions import DataGovernanceError
from ..core.minio_client import MinIOClient
from ..models.minio_config import MinIOConfig
from ..models.policy import PolicyPermissionLevel, PolicyTarget
from ..utils.validators import (
    GROUP_POLICY_PREFIX,
    USER_HOME_POLICY_PREFIX,
    validate_s3_path,
)
from .group_manager import GroupManager
from .policy_manager import PolicyManager
from .user_manager import GLOBAL_USER_GROUP, UserManager

logger = logging.getLogger(__name__)


class PathAccessInfo(BaseModel):
    """Result type for get_path_access_info method."""

    users: List[str]
    groups: List[str]
    public: bool


class SharingOperation(Enum):
    """Enumeration for sharing operations."""

    ADD = "add"
    REMOVE = "remove"


@dataclass
class SharingResult:
    """Result of a sharing operation."""

    path: str
    shared_with_users: List[str] = field(default_factory=list)
    shared_with_groups: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    failed_users: List[str] = field(default_factory=list)
    failed_groups: List[str] = field(default_factory=list)

    def add_success(self, target_type: str, name: str) -> None:
        """Add a successful sharing target."""
        if target_type == PolicyTarget.USER:
            self.shared_with_users.append(name)
        else:
            self.shared_with_groups.append(name)

    def add_failure(self, target_type: str, name: str, error: str) -> None:
        """Add a failed sharing target."""
        self.errors.append(f"Error sharing with {target_type} {name}: {error}")
        if target_type == PolicyTarget.USER:
            self.failed_users.append(name)
        else:
            self.failed_groups.append(name)

    @property
    def success_count(self) -> int:
        """Total number of successful shares."""
        return len(self.shared_with_users) + len(self.shared_with_groups)

    @property
    def has_errors(self) -> bool:
        """Check if there are any errors."""
        return bool(self.errors)


@dataclass
class UnsharingResult:
    """Result of an unsharing operation."""

    path: str
    unshared_from_users: List[str] = field(default_factory=list)
    unshared_from_groups: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    failed_users: List[str] = field(default_factory=list)
    failed_groups: List[str] = field(default_factory=list)

    def add_success(self, target_type: str, name: str) -> None:
        """Add a successful unsharing target."""
        if target_type == PolicyTarget.USER:
            self.unshared_from_users.append(name)
        else:
            self.unshared_from_groups.append(name)

    def add_failure(self, target_type: str, name: str, error: str) -> None:
        """Add a failed unsharing target."""
        self.errors.append(f"Error unsharing from {target_type} {name}: {error}")
        if target_type == PolicyTarget.USER:
            self.failed_users.append(name)
        else:
            self.failed_groups.append(name)

    @property
    def success_count(self) -> int:
        """Total number of successful unshares."""
        return len(self.unshared_from_users) + len(self.unshared_from_groups)

    @property
    def has_errors(self) -> bool:
        """Check if there are any errors."""
        return bool(self.errors)


class SharingManager:
    """
    SharingManager for high-level data sharing workflows.
    """

    def __init__(
        self,
        client: MinIOClient,
        config: MinIOConfig,
        policy_manager: PolicyManager,
        user_manager: UserManager,
        group_manager: GroupManager,
    ):
        """
        Initialize SharingManager with dependency injection.

        Args:
            client: MinIO client instance
            config: MinIO configuration
        """
        self.client = client
        self.config = config

        self.policy_manager = policy_manager
        self.user_manager = user_manager
        self.group_manager = group_manager

    # === SHARING OPERATIONS ===

    async def share_path(
        self,
        path: str,
        requesting_user: str,
        with_users: Optional[List[str]] = None,
        with_groups: Optional[List[str]] = None,
        permission_level: PolicyPermissionLevel = PolicyPermissionLevel.WRITE,
    ) -> SharingResult:
        """
        Share an S3 path with specified users and/or groups, granting them access permissions.

        This method orchestrates the complete sharing workflow by:
        1. Validating the S3 path format and permissions
        2. Authorizing the requesting user has admin privileges for the path
        3. Adding path access to each target user's and group's policies
        4. Updating the policies in MinIO
        5. Collecting results and handling any errors gracefully

        The requesting user must have admin privileges for the path being shared.
        Target users and groups must already exist in the system before sharing.

        Args:
            path: The S3 path to share (e.g., "s3a://bucket/data/project1/")
            requesting_user: Username of the user requesting the share operation
            with_users: Optional list of usernames to grant access to the path
            with_groups: Optional list of group names to grant access to the path
            permission_level: Permission level to grant (READ or WRITE, default WRITE)
        """
        logger.info(
            f"Starting share operation for path: {path} with {permission_level.value} permission"
        )

        # Validate and authorize
        await self._validate_and_authorize_request(path, requesting_user)

        # Initialize result
        result = SharingResult(path=path)

        await self._update_targets_sharing(
            SharingOperation.ADD,
            PolicyTarget.USER,
            with_users or [],
            path,
            result,
            permission_level,
        )
        await self._update_targets_sharing(
            SharingOperation.ADD,
            PolicyTarget.GROUP,
            with_groups or [],
            path,
            result,
            permission_level,
        )

        logger.info(f"Sharing completed for {path}: {result.success_count} targets")
        return result

    async def unshare_path(
        self,
        path: str,
        requesting_user: str,
        from_users: Optional[List[str]] = None,
        from_groups: Optional[List[str]] = None,
    ) -> UnsharingResult:
        """
        Remove access permissions for an S3 path from specified users and/or groups.

        This method orchestrates the complete unsharing workflow by:
        1. Validating the S3 path format and permissions
        2. Authorizing the requesting user has admin privileges for the path
        3. Removing path access from each target user's and group's policies
        4. Updating the policies in MinIO (only if changes were made)
        5. Collecting results and handling any errors gracefully

        The requesting user must have admin privileges for the path being unshared.
        If a target user or group doesn't have access to the path, the operation
        will be logged as a warning but won't cause the entire operation to fail.

        Args:
            path: The S3 path to remove access from (e.g., "s3a://bucket/data/project1/")
            requesting_user: Username of the user requesting the unshare operation
            from_users: Optional list of usernames to revoke access from
            from_groups: Optional list of group names to revoke access from
        """
        logger.info(f"Starting unshare operation for path: {path}")

        # Validate and authorize if user specified
        await self._validate_and_authorize_request(path, requesting_user)

        # Initialize result
        result = UnsharingResult(path=path)

        # Process unsharing concurrently
        await self._update_targets_sharing(
            SharingOperation.REMOVE, PolicyTarget.USER, from_users or [], path, result
        )
        await self._update_targets_sharing(
            SharingOperation.REMOVE, PolicyTarget.GROUP, from_groups or [], path, result
        )

        logger.info(f"Unsharing completed for {path}: {result.success_count} targets")
        return result

    # === UTILITY METHODS ===

    async def _validate_and_authorize_request(
        self, path: str, requesting_user: str
    ) -> None:
        """Validate path and authorize requesting user."""
        validate_s3_path(path)

        can_share = await self.user_manager.can_user_share_path(path, requesting_user)
        if not can_share:
            raise DataGovernanceError(
                f"User {requesting_user} does not have admin privileges for path {path}"
            )

    # === SHARING WORKFLOW HELPERS ===

    async def _update_targets_sharing(
        self,
        operation: SharingOperation,
        target_type: PolicyTarget,
        names: List[str],
        path: str,
        result: Union[SharingResult, UnsharingResult],
        permission_level: PolicyPermissionLevel = PolicyPermissionLevel.WRITE,
    ) -> None:
        """Add or remove path sharing for multiple targets (users or groups)."""
        operation_verb = (
            "sharing with" if operation == SharingOperation.ADD else "unsharing from"
        )

        for name in names:
            try:
                await self._update_path_sharing(
                    operation, target_type, name, path, permission_level
                )
                result.add_success(target_type.value, name)
            except Exception as e:
                logger.error(
                    f"Unexpected error {operation_verb} {target_type.value} {name}: {e}"
                )
                result.add_failure(target_type.value, name, f"Unexpected error: {e}")

    async def _update_path_sharing(
        self,
        operation: SharingOperation,
        target_type: PolicyTarget,
        target_name: str,
        path: str,
        permission_level: PolicyPermissionLevel = PolicyPermissionLevel.WRITE,
    ) -> None:
        """Add or remove path sharing by updating the appropriate policy."""
        if operation == SharingOperation.ADD:
            await self.policy_manager.add_path_access_for_target(
                target_type, target_name, path, permission_level
            )
            log_message = f"Added path sharing: {path} to {target_type.value} {target_name} with {permission_level.value} permission"
            logger.debug(log_message)
        else:  # SharingOperation.REMOVE
            await self.policy_manager.remove_path_access_for_target(
                target_type, target_name, path
            )
            log_message = (
                f"Removed path sharing: {path} from {target_type.value} {target_name}"
            )
            logger.info(log_message)

    # === PUBLIC/PRIVATE ACCESS METHODS ===

    async def make_public(
        self,
        path: str,
        requesting_user: str,
    ) -> SharingResult:
        """
        Make an S3 path publicly accessible by adding it to the global user group.

        This method shares the path with the global user group (GLOBAL_USER_GROUP),
        which all users are automatically members of, effectively making the path
        accessible to all users in the system.

        Args:
            path: The S3 path to make public (e.g., "s3a://bucket/data/public-dataset/")
            requesting_user: Username of the user requesting the operation
        """
        logger.info(f"Making path public: {path}")

        await self._validate_and_authorize_request(path, requesting_user)

        # Share with the global user group (which all users are members of)
        result = await self.share_path(
            path=path,
            requesting_user=requesting_user,
            with_groups=[GLOBAL_USER_GROUP],
        )

        logger.info(f"Path made public: {path} - Success: {result.success_count > 0}")
        return result

    async def make_private(
        self,
        path: str,
        requesting_user: str,
    ) -> UnsharingResult:
        """
        Make an S3 path completely private by removing it from ALL policies that have access.

        This method finds all users and groups that currently have access to the specified
        path and removes the path from their policies, effectively making it completely
        private. Only the path owner (requesting user) will retain access through their
        home directory policy.

        Args:
            path: The S3 path to make private (e.g., "s3a://bucket/data/dataset/")
            requesting_user: Username of the user requesting the operation
        """
        logger.info(f"Making path completely private: {path}")

        await self._validate_and_authorize_request(path, requesting_user)

        # Find all current policies that have access to this path
        current_access = await self.get_path_access_info(path)

        users_to_remove = [
            user for user in current_access.users if user != requesting_user
        ]
        groups_to_remove = current_access.groups

        result = await self.unshare_path(
            path=path,
            requesting_user=requesting_user,
            from_users=users_to_remove,
            from_groups=groups_to_remove,
        )

        logger.info(f"Path made completely private: {path}")
        return result

    async def get_path_access_info(self, path: str) -> PathAccessInfo:
        """
        Get access information for a given S3 path.

        This method searches through all user and group policies to find which users
        and groups have access to the specified path or its parent paths.

        Args:
            path: The S3 path to search for (e.g., "s3a://bucket/data/project/")
        """
        logger.info(f"Getting path access info for: {path}")

        validate_s3_path(path)

        result = PathAccessInfo(
            users=[],
            groups=[],
            public=False,
        )

        all_policies = await self.policy_manager.list_resources()

        for policy_name in all_policies:
            policy_model = await self.policy_manager._load_minio_policy(policy_name)
            if policy_model is None:
                continue

            accessible_paths = self.policy_manager.get_accessible_paths_from_policy(
                policy_model
            )

            if self._path_matches_any_accessible_path(path, accessible_paths):
                if self.policy_manager.is_user_home_policy(policy_name):
                    username = policy_name.replace(USER_HOME_POLICY_PREFIX, "")
                    result.users.append(username)
                elif self.policy_manager.is_group_policy(policy_name):
                    group_name = policy_name.replace(GROUP_POLICY_PREFIX, "")
                    result.groups.append(group_name)
                    if group_name == GLOBAL_USER_GROUP:
                        result.public = True
                # Note: user-system-policy entries are not included as they represent
                # system access rather than user-controlled data access

        logger.info(
            f"Path access found - Users: {len(result.users)}, Groups: {len(result.groups)}, Public: {result.public}"
        )

        return result

    # === HELPER METHODS ===

    def _path_matches_any_accessible_path(
        self, target_path: str, accessible_paths: List[str]
    ) -> bool:
        """
        Check if the target path matches any of the accessible paths.

        Args:
            target_path: The path to check for access
            accessible_paths: List of paths that are accessible
        """
        target_normalized = target_path.rstrip("/")

        for accessible_path in accessible_paths:
            accessible_normalized = accessible_path.rstrip("/")

            if target_normalized.startswith(
                accessible_normalized
            ) or accessible_normalized.startswith(target_normalized):
                return True

        return False
