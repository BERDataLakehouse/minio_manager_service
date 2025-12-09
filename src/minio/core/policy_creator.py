"""
PolicyCreator module for creating new MinIO policy documents from scratch.

This module focuses on creating policies with organized sections.
For modifying existing policies, use PolicyBuilder.

POLICY TYPES CREATED:

1. USER HOME POLICIES (PolicyType.USER_HOME):
   - Policy Name: <USER_HOME_POLICY_PREFIX><username>
   - Grants ADMIN access to user's personal warehouses:
     * s3a://{bucket}/users-sql-warehouse/{username}/ (for Spark tables)
     * s3a://{bucket}/users-general-warehouse/{username}/ (for general files)
   - Includes full read/write/delete permissions for user's personal workspace
   - Enables directory listing and bucket location access
   - SHARING OPERATIONS: Only paths within user home policies can be shared/unshared
     with other users or groups via the sharing API endpoints

2. USER SYSTEM POLICIES (PolicyType.USER_SYSTEM):
   - Policy Name: <USER_SYSTEM_POLICY_PREFIX><username>
   - Grants access to system resources defined in SYSTEM_RESOURCE_CONFIG:
     * Currently: s3a://cdm-spark-job-logs/spark-job-logs/{username}/ (WRITE access)
     * Future: Additional system resources as configured
   - Permission levels vary by resource (READ/WRITE/ADMIN)
   - User-scoped resources include username in path, global resources don't

3. GROUP POLICIES (PolicyType.GROUP_HOME):
   - Policy Name: <GROUP_POLICY_PREFIX><groupname>
   - Grants WRITE access to group's shared workspaces:
     * s3a://{bucket}/tenant-sql-warehouse/{groupname}/ (for Spark tables)
     * s3a://{bucket}/tenant-general-warehouse/{groupname}/ (for general files)
   - Enables collaborative access for group members
   - Members inherit group permissions through policy attachment
"""

import logging
from collections import defaultdict
from typing import Dict, List

from ...service.exceptions import PolicyOperationError
from ..models.minio_config import MinIOConfig
from ..models.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyModel,
    PolicyPermissionLevel,
    PolicySectionType,
    PolicyStatement,
    PolicyType,
)
from ..utils.validators import (
    GROUP_POLICY_PREFIX,
    USER_HOME_POLICY_PREFIX,
    USER_SYSTEM_POLICY_PREFIX,
    validate_policy_name,
)
from .policy_builder import PolicyBuilder
from ..utils.governance import (
    generate_group_governance_prefix,
    generate_user_governance_prefix,
)

logger = logging.getLogger(__name__)

# Mapping from policy actions to their corresponding sections
_POLICY_ACTION_TO_POLICY_SECTION = {
    PolicyAction.LIST_ALL_MY_BUCKETS: PolicySectionType.GLOBAL_PERMISSIONS,
    PolicyAction.GET_BUCKET_LOCATION: PolicySectionType.GLOBAL_PERMISSIONS,
    PolicyAction.LIST_BUCKET: PolicySectionType.BUCKET_ACCESS,
    PolicyAction.GET_OBJECT: PolicySectionType.READ_PERMISSIONS,
    PolicyAction.PUT_OBJECT: PolicySectionType.WRITE_PERMISSIONS,
    PolicyAction.DELETE_OBJECT: PolicySectionType.DELETE_PERMISSIONS,
}

# Global system resource configuration
SYSTEM_RESOURCE_CONFIG = {
    # Spark-logs-related resources
    # Creates policy with access to s3a://cdm-spark-job-logs/spark-job-logs/username/
    "spark": {
        "bucket": "cdm-spark-job-logs",
        "base_prefix": "spark-job-logs",
        "user_scoped": True,  # Whether this resource is user-specific
        "permission_level": PolicyPermissionLevel.WRITE,
    },
    # Task-service-related resources
    # Creates policy with access to s3a://cdmts/logs/ and s3a://cdmts/io/
    "task_service_logs": {
        "bucket": "cts",
        "base_prefix": "logs",
        "user_scoped": False,
        "permission_level": PolicyPermissionLevel.READ,
    },
    "task_service_io": {
        "bucket": "cts",
        "base_prefix": "io",
        "user_scoped": False,
        "permission_level": PolicyPermissionLevel.WRITE,
    },
}


class PolicyCreator:
    """
    Creator for building new MinIO policies from scratch.
    """

    def __init__(
        self,
        policy_type: PolicyType,
        target_name: str,
        config: MinIOConfig,
        path_target_name: str | None = None,
    ):
        """
        Initialize the PolicyCreator for building a new policy from scratch.

        Args:
            policy_type: Type of policy being created (USER_HOME, USER_SYSTEM, GROUP_HOME)
            target_name: Name of the target (username or group name)
            config: MinIO configuration for bucket and path information
            path_target_name: Optional target name to use for path generation.
                              If not provided, target_name is used.
                              Useful when policy name should differ from path target (e.g. RO groups).
        """

        self.policy_type = policy_type
        self.target_name = target_name
        self.system_config = SYSTEM_RESOURCE_CONFIG

        # Use path_target_name if provided, otherwise default to target_name
        self.path_target = path_target_name or target_name

        self.config = config
        # user warehouse for spark tables
        self.user_sql_warehouse_path = f"s3a://{self.config.default_bucket}/{self.config.users_sql_warehouse_prefix}/{self.path_target}"
        # user warehouse for general files
        self.user_general_warehouse_path = f"s3a://{self.config.default_bucket}/{self.config.users_general_warehouse_prefix}/{self.path_target}"
        # tenant warehouse for spark tables
        self.tenant_sql_warehouse_path = f"s3a://{self.config.default_bucket}/{self.config.tenant_sql_warehouse_prefix}/{self.path_target}"
        # tenant warehouse for general files
        self.tenant_general_warehouse_path = f"s3a://{self.config.default_bucket}/{self.config.tenant_general_warehouse_prefix}/{self.path_target}"

        # Internal section management with Dict[PolicySectionType, List[PolicyStatement]]
        self._sections: Dict[PolicySectionType, List[PolicyStatement]] = {
            PolicySectionType.GLOBAL_PERMISSIONS: [],
            PolicySectionType.BUCKET_ACCESS: [],
            PolicySectionType.READ_PERMISSIONS: [],
            PolicySectionType.WRITE_PERMISSIONS: [],
            PolicySectionType.DELETE_PERMISSIONS: [],
        }

    def get_sections(self) -> Dict[PolicySectionType, List[PolicyStatement]]:
        """
        Get a copy of the current sections.

        Returns:
            Dict mapping section types to their statements
        """
        return {
            section_type: statements.copy()
            for section_type, statements in self._sections.items()
        }

    def _get_current_policy(self) -> PolicyModel:
        """
        Get the current policy model from sections.
        Used internally to work with PolicyBuilder.

        Returns:
            PolicyModel: Current policy constructed from sections
        """
        all_statements = self._combine_sections_with_ordering()

        policy_document = PolicyDocument(statement=all_statements)
        policy_name = self._generate_policy_name()

        return PolicyModel(
            policy_name=policy_name,
            policy_document=policy_document,
        )

    def build(self) -> PolicyModel:
        """
        Build the final policy model from all sections.

        Returns:
            PolicyModel with the constructed policy

        Raises:
            PolicyOperationError: If policy cannot be built or validation fails
        """
        try:
            # Combine all sections into a single statement list with proper ordering
            all_statements = self._combine_sections_with_ordering()

            # Create policy document
            policy_document = PolicyDocument(statement=all_statements)

            # Generate policy name
            policy_name = self._generate_policy_name()

            # Create and return policy model
            return PolicyModel(
                policy_name=policy_name,
                policy_document=policy_document,
            )

        except Exception as e:
            logger.error(
                f"Failed to build policy for {self.policy_type.value} '{self.target_name}': {e}"
            )
            raise PolicyOperationError(f"Policy build failed: {e}") from e

    def _combine_sections_with_ordering(self) -> List[PolicyStatement]:
        """
        Combine all sections into a single statement list with proper ordering.
        Order: Global -> Bucket Access -> Read -> Write -> Delete

        Returns:
            List of all policy statements in proper order
        """
        all_statements = []

        # Add statements in the specified order for better organization
        section_order = [
            PolicySectionType.GLOBAL_PERMISSIONS,
            PolicySectionType.BUCKET_ACCESS,
            PolicySectionType.READ_PERMISSIONS,
            PolicySectionType.WRITE_PERMISSIONS,
            PolicySectionType.DELETE_PERMISSIONS,
        ]

        for section_type in section_order:
            statements = self._sections[section_type]
            if statements:
                all_statements.extend(statements)

        return all_statements

    def _generate_policy_name(self) -> str:
        """
        Generate policy name based on policy type and target name using proper validation.

        Returns:
            Generated policy name following naming conventions

        Raises:
            PolicyOperationError: If generated policy name is invalid
        """
        if self.policy_type == PolicyType.USER_HOME:
            policy_name = f"{USER_HOME_POLICY_PREFIX}{self.target_name}"
        elif self.policy_type == PolicyType.USER_SYSTEM:
            policy_name = f"{USER_SYSTEM_POLICY_PREFIX}{self.target_name}"
        elif self.policy_type == PolicyType.GROUP_HOME:
            policy_name = f"{GROUP_POLICY_PREFIX}{self.target_name}"
        elif self.policy_type == PolicyType.GROUP_HOME_RO:
            # Use same naming pattern as GROUP_HOME: group-policy-{target_name}
            # Note: target_name will be the RO group name (e.g., 'testgroupro')
            policy_name = f"{GROUP_POLICY_PREFIX}{self.target_name}"
        else:
            raise PolicyOperationError(f"Unknown policy type: {self.policy_type}")

        # Validate the generated policy name
        try:
            return validate_policy_name(policy_name)
        except Exception as e:
            raise PolicyOperationError(f"Generated policy name is invalid: {e}") from e

    def create_default_policy(self) -> "PolicyCreator":
        """
        Create default policy based on policy type.

        Returns:
            Self with default permissions added for method chaining
        """
        if self.policy_type == PolicyType.USER_HOME:
            return self._create_default_user_home_policy()
        elif self.policy_type == PolicyType.USER_SYSTEM:
            return self._create_default_system_policy()
        elif self.policy_type == PolicyType.GROUP_HOME:
            return self._create_default_group_policy()
        elif self.policy_type == PolicyType.GROUP_HOME_RO:
            return self._create_default_group_policy(read_only=True)
        else:
            raise PolicyOperationError(f"Unknown policy type: {self.policy_type}")

    def _add_path_access_via_builder(
        self, bucket_name: str, path: str, permission_level: PolicyPermissionLevel
    ) -> None:
        """
        Add path access using PolicyBuilder and update internal sections.

        Args:
            path: The S3 path to grant access to
            permission_level: The level of access to grant
        """
        # Get current policy state
        current_policy = self._get_current_policy()

        # Use PolicyBuilder to add the path access
        builder = PolicyBuilder(current_policy, bucket_name)
        updated_policy = builder.add_path_access(
            path, permission_level, new_policy=True
        ).build()

        # Clear current sections and rebuild from updated policy
        self._rebuild_sections_from_policy(updated_policy)

    def _rebuild_sections_from_policy(self, policy: PolicyModel) -> None:
        """
        Rebuild internal sections from a policy model.

        Args:
            policy: Policy model to extract sections from
        """
        # Clear existing sections
        for section_type in self._sections:
            self._sections[section_type] = []

        # Categorize statements back into sections
        for stmt in policy.policy_document.statement:
            # Each statement now has exactly one action (enforced by type)
            action = stmt.action

            # Find the section for this action
            if action in _POLICY_ACTION_TO_POLICY_SECTION:
                target_section = _POLICY_ACTION_TO_POLICY_SECTION[action]
                self._sections[target_section].append(stmt)
            else:
                raise PolicyOperationError(f"Unsupported policy action: {action}")

    def _create_default_user_home_policy(self) -> "PolicyCreator":
        """Create default user home policy with SQL and general warehouse paths."""
        # Add access to user's SQL warehouse with table naming enforcement
        # Only allow tables/databases that follow u_username__* pattern
        governance_prefix = generate_user_governance_prefix(self.target_name)
        user_sql_warehouse_governed_path = (
            f"{self.user_sql_warehouse_path}/{governance_prefix}*"
        )
        self._add_path_access_via_builder(
            self.config.default_bucket,
            user_sql_warehouse_governed_path,
            PolicyPermissionLevel.ADMIN,
        )

        # Add access to user's general warehouse (no naming restrictions for general files)
        self._add_path_access_via_builder(
            self.config.default_bucket,
            self.user_general_warehouse_path,
            PolicyPermissionLevel.ADMIN,
        )

        return self

    def _create_default_system_policy(self) -> "PolicyCreator":
        """Create default system policy with system resource paths."""
        # Get system paths for this user using the global configuration
        system_paths = self._get_user_system_paths(self.target_name)

        for bucket_name, path_permission_pairs in system_paths.items():
            for path, permission_level in path_permission_pairs:
                system_path = f"s3a://{bucket_name}/{path}"
                self._add_path_access_via_builder(
                    bucket_name, system_path, permission_level
                )

        return self

    def _create_default_group_policy(self, read_only: bool = False) -> "PolicyCreator":
        """Create default group policy with group shared workspace paths.

        Args:
            read_only: If True, grant READ access only. If False, grant WRITE access.
        """
        permission = (
            PolicyPermissionLevel.READ if read_only else PolicyPermissionLevel.WRITE
        )

        # Add access to group's SQL warehouse with table naming enforcement
        # Only allow tables/databases that follow groupname_* pattern
        governance_prefix = generate_group_governance_prefix(self.target_name)
        tenant_sql_warehouse_governed_path = (
            f"{self.tenant_sql_warehouse_path}/{governance_prefix}*"
        )
        self._add_path_access_via_builder(
            self.config.default_bucket,
            tenant_sql_warehouse_governed_path,
            permission,
        )

        # Add access to group's general warehouse (no naming restrictions for general files)
        self._add_path_access_via_builder(
            self.config.default_bucket,
            self.tenant_general_warehouse_path,
            permission,
        )

        return self

    def _get_user_system_paths(
        self, username: str
    ) -> Dict[str, List[tuple[str, PolicyPermissionLevel]]]:
        """Get system resource paths and permission levels for a user using the global configuration."""
        user_paths = defaultdict(list)

        for resource_config in self.system_config.values():
            bucket = resource_config["bucket"]
            base_prefix = resource_config["base_prefix"]
            user_scoped = resource_config["user_scoped"]
            permission_level = resource_config["permission_level"]

            if user_scoped:
                # User-specific resource path
                path = f"{base_prefix}/{username}"
            else:
                # Global resource path (not user-specific)
                path = base_prefix

            path_with_permission = (path, permission_level)
            user_paths[bucket].append(path_with_permission)

        return user_paths
