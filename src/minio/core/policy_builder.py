"""
Policy Builder module for modifying MinIO policy documents.
"""

import logging
import re

from ...service.exceptions import PolicyOperationError
from ..models.policy import (
    PolicyAction,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
)
from ..utils.validators import validate_s3_path

logger = logging.getLogger(__name__)


class PolicyBuilder:
    def __init__(self, policy_model: PolicyModel, bucket_name: str):
        """
        Initialize the PolicyBuilder with a policy model and bucket name.

        Args:
            policy_model: The base policy model to modify
            bucket_name: The S3 bucket name for path validation
        """
        self.policy_model = policy_model.model_copy(deep=True)
        self.bucket_name = bucket_name

    def add_path_access(
        self,
        path: str,
        permission_level: PolicyPermissionLevel,
        new_policy: bool = False,
    ) -> "PolicyBuilder":
        """
        Add access to a path with specified permission level.

        Args:
            path: The S3 path to grant access to (e.g., "s3a://bucket/path/to/data")
            permission_level: The level of access to grant (READ, WRITE, or ADMIN)
            new_policy: Whether to create a new policy or modify the existing one

        Returns:
            PolicyBuilder: A new builder instance with the path access added

        Raises:
            PolicyOperationError: If the path format is invalid
        """
        clean_path = self._extract_and_validate_path(path)

        # Create new builder with modifications
        new_builder = PolicyBuilder(self.policy_model, self.bucket_name)

        if not new_policy:
            # Remove any existing access to allow permission level changes
            new_builder._remove_path_access_internal(clean_path)

        # Re-add path access with new permission level
        new_builder._add_path_access_internal(clean_path, permission_level)

        return new_builder

    def remove_path_access(self, path: str) -> "PolicyBuilder":
        """
        Remove all access to a specific path.

        Args:
            path: The S3 path to revoke access from (e.g., "s3a://bucket/path/to/data")

        Returns:
            PolicyBuilder: A new builder instance with the path access removed

        Raises:
            PolicyOperationError: If the path format is invalid
        """
        clean_path = self._extract_and_validate_path(path)

        # Create new builder with modifications
        new_builder = PolicyBuilder(self.policy_model, self.bucket_name)
        new_builder._remove_path_access_internal(clean_path)
        return new_builder

    def build(self) -> PolicyModel:
        """
        Build the final policy model.

        Returns:
            PolicyModel: A deep copy of the modified policy model
        """
        return self.policy_model.model_copy(deep=True)

    def _add_path_access_internal(
        self, clean_path: str, permission_level: PolicyPermissionLevel
    ) -> None:
        """Internal method to add path access to the policy."""

        # Add bucket access permissions
        self._add_bucket_access_permissions(self.bucket_name)

        # Add ListBucket permissions with prefixes
        self._add_list_bucket_permissions(self.bucket_name, clean_path)

        # Add object-level permissions based on permission level
        self._add_object_level_permissions(
            self.bucket_name, clean_path, permission_level
        )

    def _remove_path_access_internal(self, clean_path: str) -> None:
        """Internal method to remove path access from the policy."""
        # Remove from ListBucket statement
        self._remove_from_list_bucket_statement(clean_path)

        # Remove object-level statements (automatically handles both folder and folder/* ARNs)
        folder_arn = f"arn:aws:s3:::{self.bucket_name}/{clean_path}"
        self._remove_object_statements(folder_arn)

    def _extract_and_validate_path(self, path: str) -> str:
        """
        Normalize S3 path to bucket-relative format.

        Handles both folder and folder/* input formats consistently:
        - 's3a://bucket/path/to/folder' → 'path/to/folder'
        - 's3a://bucket/path/to/folder/*' → 'path/to/folder'
        - 's3a://bucket/path/to/folder/' → 'path/to/folder'

        Args:
            path: The S3 path to normalize

        Returns:
            str: The normalized path (bucket-relative)

        Raises:
            PolicyOperationError: If the path format is invalid
        """
        path = validate_s3_path(path)

        # Extract bucket and path from validated S3 URL
        path_without_scheme = re.sub(r"^s3a?://", "", path)
        path_parts = path_without_scheme.split("/", 1)

        if len(path_parts) < 2:
            raise PolicyOperationError(
                f"S3 path must include a path component after bucket: {path}"
            )

        bucket_name, relative_path = path_parts

        # Validate bucket matches configuration
        if bucket_name != self.bucket_name:
            raise PolicyOperationError(
                f"Path bucket '{bucket_name}' does not match configured bucket '{self.bucket_name}'"
            )

        # Normalize path (remove trailing slashes and /* patterns for consistent handling)
        # But preserve governance wildcards (patterns ending with single *)
        normalized_path = relative_path.rstrip("/")

        # Only remove /* suffix if it's not a governance wildcard pattern
        # Governance patterns end with single * (like u_tgu2__*)
        # Path suffixes end with /* (like path/*)
        if normalized_path.endswith("/*"):
            normalized_path = normalized_path.removesuffix("/*")

        if not normalized_path:
            raise PolicyOperationError("Path cannot be empty after bucket name")

        return normalized_path

    def _find_list_bucket_statement(self) -> PolicyStatement | None:
        """Find the ListBucket statement with prefix conditions."""
        for stmt in self.policy_model.policy_document.statement:
            if (
                stmt.action == PolicyAction.LIST_BUCKET
                and stmt.condition
                and "StringLike" in stmt.condition
                and "s3:prefix" in stmt.condition["StringLike"]
            ):
                # There should only be one ListBucket statement
                return stmt
        return None

    def _add_to_list_bucket_statement(self, clean_path: str) -> None:
        """Add path prefixes to the ListBucket statement in place."""
        list_bucket_stmt = self._find_list_bucket_statement()
        if not list_bucket_stmt or not list_bucket_stmt.condition:
            raise PolicyOperationError("No ListBucket statement found to add path to")

        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        new_prefixes = self._create_list_bucket_prefixes(clean_path)

        for prefix in new_prefixes:
            if prefix not in prefixes:
                prefixes.append(prefix)

    def _remove_from_list_bucket_statement(self, clean_path: str) -> None:
        """Remove path prefixes from the ListBucket statement."""
        list_bucket_stmt = self._find_list_bucket_statement()
        if not list_bucket_stmt or not list_bucket_stmt.condition:
            raise PolicyOperationError("No ListBucket statement found to add path to")

        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        prefixes_to_remove = self._create_list_bucket_prefixes(clean_path)

        list_bucket_stmt.condition["StringLike"]["s3:prefix"] = [
            prefix for prefix in prefixes if prefix not in prefixes_to_remove
        ]

    def _remove_object_statements(self, target_resource: str) -> None:
        """
        Remove object-level statements that match the resource ARN.

        Automatically removes both folder and folder/* patterns.
        Since paths are normalized, target_resource is always a folder ARN (without /*).
        """
        # Always remove both folder and folder/* patterns for complete cleanup
        resources_to_remove = [target_resource, f"{target_resource}/*"]

        statements_to_keep = []

        for stmt in self.policy_model.policy_document.statement:
            # Check if statement contains any of the resources we want to remove
            contains_target = any(
                self._statement_matches_resource(stmt, resource)
                for resource in resources_to_remove
            )

            if not contains_target:
                # Statement doesn't contain any target resources, keep as-is
                statements_to_keep.append(stmt)
            else:
                # Statement contains target resources
                resources = (
                    stmt.resource
                    if isinstance(stmt.resource, list)
                    else [stmt.resource]
                )

                # Remove all target resources
                remaining_resources = [
                    r for r in resources if r not in resources_to_remove
                ]

                # Only keep statement if it has remaining resources
                if remaining_resources:
                    # Create new statement with remaining resources
                    updated_stmt = stmt.model_copy(
                        update={"resource": remaining_resources}
                    )
                    statements_to_keep.append(updated_stmt)

        self.policy_model.policy_document.statement = statements_to_keep

    def _statement_matches_resource(
        self, statement: PolicyStatement, target_resource: str
    ) -> bool:
        """Check if a statement matches a specific resource."""

        resources = (
            statement.resource
            if isinstance(statement.resource, list)
            else [statement.resource]
        )
        return target_resource in resources

    def _add_bucket_access_permissions(self, bucket_name: str) -> None:
        """Add bucket access permissions (GetBucketLocation)."""
        # Check if GetBucketLocation already exists for this bucket
        bucket_resource = f"arn:aws:s3:::{bucket_name}"
        for stmt in self.policy_model.policy_document.statement:
            if stmt.action == PolicyAction.GET_BUCKET_LOCATION and bucket_resource in (
                stmt.resource if isinstance(stmt.resource, list) else [stmt.resource]
            ):
                return  # Already exists

        # Add GetBucketLocation statement
        bucket_location_stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_BUCKET_LOCATION,
            resource=[bucket_resource],
            condition=None,
            principal=None,
        )
        self.policy_model.policy_document.statement.append(bucket_location_stmt)

    def _add_list_bucket_permissions(self, bucket_name: str, clean_path: str) -> None:
        """Add ListBucket permissions with proper prefixes."""
        prefixes_to_add = self._create_list_bucket_prefixes(clean_path)
        bucket_resource = f"arn:aws:s3:::{bucket_name}"

        # Find existing ListBucket statement for this bucket
        existing_stmt = None
        for stmt in self.policy_model.policy_document.statement:
            if stmt.action == PolicyAction.LIST_BUCKET and bucket_resource in (
                stmt.resource if isinstance(stmt.resource, list) else [stmt.resource]
            ):
                existing_stmt = stmt
                break

        if (
            existing_stmt
            and existing_stmt.condition
            and "StringLike" in existing_stmt.condition
        ):
            # Add to existing prefixes
            current_prefixes = existing_stmt.condition["StringLike"]["s3:prefix"]
            for prefix in prefixes_to_add:
                if prefix not in current_prefixes:
                    current_prefixes.append(prefix)
        else:
            # Create new ListBucket statement
            new_stmt = PolicyStatement(
                effect=PolicyEffect.ALLOW,
                action=PolicyAction.LIST_BUCKET,
                resource=[bucket_resource],
                condition={"StringLike": {"s3:prefix": prefixes_to_add.copy()}},
                principal=None,
            )
            self.policy_model.policy_document.statement.append(new_stmt)

    def _add_object_level_permissions(
        self, bucket_name: str, clean_path: str, permission_level: PolicyPermissionLevel
    ) -> None:
        """Add object-level permissions based on permission level."""
        # Create both folder and folder/* ARNs for comprehensive access
        folder_arn = f"arn:aws:s3:::{bucket_name}/{clean_path}"
        folder_contents_arn = f"arn:aws:s3:::{bucket_name}/{clean_path}/*"

        # For governance paths with wildcards, also add parent directory permissions
        parent_arns = []
        if clean_path.endswith("*"):
            path_parts = clean_path.split("/")
            if len(path_parts) > 1:
                parent_path = "/".join(path_parts[:-1])
                parent_folder_arn = f"arn:aws:s3:::{bucket_name}/{parent_path}"
                parent_contents_arn = f"arn:aws:s3:::{bucket_name}/{parent_path}/*"
                parent_arns = [parent_folder_arn, parent_contents_arn]

        # Add permissions based on level
        if permission_level in [
            PolicyPermissionLevel.READ,
            PolicyPermissionLevel.WRITE,
            PolicyPermissionLevel.ADMIN,
        ]:
            # For GET operations, need both folder and folder/* for listing and reading
            self._add_object_permission(folder_arn, PolicyAction.GET_OBJECT)
            self._add_object_permission(folder_contents_arn, PolicyAction.GET_OBJECT)
            # Add parent directory GET permissions for governance paths
            for parent_arn in parent_arns:
                self._add_object_permission(parent_arn, PolicyAction.GET_OBJECT)

        if permission_level in [
            PolicyPermissionLevel.WRITE,
            PolicyPermissionLevel.ADMIN,
        ]:
            # For PUT operations, need both folder and folder/* for creating folders and files
            self._add_object_permission(folder_arn, PolicyAction.PUT_OBJECT)
            self._add_object_permission(folder_contents_arn, PolicyAction.PUT_OBJECT)

            # For DELETE operations, only need folder/* to delete contents
            self._add_object_permission(folder_contents_arn, PolicyAction.DELETE_OBJECT)

    def _add_object_permission(self, resource_arn: str, action: PolicyAction) -> None:
        """Add a specific object permission."""
        # Check if we already have a statement with this action and resource
        for stmt in self.policy_model.policy_document.statement:
            if stmt.action == action:
                resources = (
                    stmt.resource
                    if isinstance(stmt.resource, list)
                    else [stmt.resource]
                )
                if resource_arn not in resources:
                    resources.append(resource_arn)
                return

        # Create new statement for this action
        new_stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=action,
            resource=[resource_arn],
            condition=None,
            principal=None,
        )
        self.policy_model.policy_document.statement.append(new_stmt)

    def _create_list_bucket_prefixes(self, normalized_path: str) -> list[str]:
        """Create list of prefixes for ListBucket operations."""
        prefixes = [normalized_path, f"{normalized_path}/*"]

        # For governance paths with wildcards, also add parent directory access
        # This allows users to navigate to paths like users-sql-warehouse/tgu2/u_tgu2__*
        # by granting access to the parent directory users-sql-warehouse/tgu2
        if normalized_path.endswith("*"):
            # Extract parent directory by removing the last path component
            path_parts = normalized_path.split("/")
            if len(path_parts) > 1:
                parent_path = "/".join(path_parts[:-1])
                if parent_path not in prefixes:
                    prefixes.append(parent_path)
                # Also add parent_path/* to allow listing directory contents
                parent_wildcard = f"{parent_path}/*"
                if parent_wildcard not in prefixes:
                    prefixes.append(parent_wildcard)

        return prefixes
