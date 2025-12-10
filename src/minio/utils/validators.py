"""
MinIO Data Governance Service - Comprehensive Validation Utilities

This module contains all validation logic for the MinIO Manager Service,
organized by domain and focused on data governance requirements.
"""

import re

from ...service.arg_checkers import not_falsy
from ...service.exceptions import (
    BucketValidationError,
    GroupOperationError,
    PolicyValidationError,
    UserOperationError,
    ValidationError,
)

# Built-in policies that are not supported by the data governance service
BUILT_IN_POLICIES = [
    "readonly",
    "readwrite",
    "writeonly",
    "diagnostics",
    "public",
    "consoleAdmin",
]

# Individual policy prefix constants
USER_HOME_POLICY_PREFIX = "user-home-policy-"
USER_SYSTEM_POLICY_PREFIX = "user-system-policy-"
GROUP_POLICY_PREFIX = "group-policy-"

# Allowed policy prefixes for data governance policies
DATA_GOVERNANCE_POLICY_PREFIXES = [
    USER_HOME_POLICY_PREFIX,
    USER_SYSTEM_POLICY_PREFIX,
    GROUP_POLICY_PREFIX,
]

# =============================================================================
# USERNAME VALIDATION
# =============================================================================


def validate_username(username: str) -> str:
    """
    Validate username for MinIO data governance service.

    Requirements for data governance:
    - Must be unique and trackable
    - Safe for file paths and policies
    - Compatible with MinIO user management

    Args:
        username: Username to validate

    Returns:
        str: Validated and normalized username

    Raises:
        UserOperationError: If username validation fails
    """
    username = not_falsy(username, "Username")
    username = username.strip()

    # Length constraints for MinIO compatibility
    if len(username) < 2 or len(username) > 64:
        raise UserOperationError("Username must be between 2 and 64 characters")

    # Character constraints - allow alphanumeric, dots, hyphens, underscores
    # These are safe for S3 paths and MinIO policies
    if not re.match(r"^[a-zA-Z0-9._-]+$", username):
        raise UserOperationError(
            "Username can only contain letters, numbers, periods, hyphens, and underscores"
        )

    # Must start and end with alphanumeric for S3 compatibility
    if not (username[0].isalnum() and username[-1].isalnum()):
        raise UserOperationError("Username must start and end with a letter or number")

    # No consecutive special characters to avoid path issues
    if re.search(r"[._-]{2,}", username):
        raise UserOperationError(
            "Username cannot contain consecutive special characters"
        )

    # Reserved usernames for data governance
    reserved_usernames = {
        "admin",
        "root",
        "system",
        "minio",
        "service",
        "backup",
        "guest",
        "anonymous",
        "public",
        "shared",
        "warehouse",
    }
    if username.lower() in reserved_usernames:
        raise UserOperationError(f"Username '{username}' is reserved for system use")

    return username


# =============================================================================
# GROUP VALIDATION
# =============================================================================


def validate_group_name(group_name: str) -> str:
    """
    Validate group name for data governance workflows.

    Group names (tenants) are used to construct namespace prefixes in the format
    {tenant_name}_{namespace_name}. To prevent ambiguity with this separator,
    underscores are NOT allowed in tenant names.

    Additionally, group names must be lowercase only because Hive/Spark Metastore
    stores all database names in lowercase. Mixed case names (e.g., 'KBase' vs 'kbase')
    would create namespace collisions in Hive.

    Args:
        group_name: Group name to validate

    Returns:
        str: Validated and normalized group name

    Raises:
        GroupOperationError: If group name validation fails
    """
    group_name = not_falsy(group_name, "Group name")
    group_name = group_name.strip()

    # Length constraints for policy and path compatibility
    if len(group_name) < 2 or len(group_name) > 64:
        raise GroupOperationError("Group name must be between 2 and 64 characters")

    # Character constraints - lowercase alphanumeric only (NO underscores or uppercase)
    # - Underscores are reserved as the namespace separator: {tenant}_{namespace}
    # - Uppercase letters are forbidden because Hive stores names in lowercase,
    #   which would cause collisions: 'KBase' and 'kbase' → both become 'kbase_'
    if not re.match(r"^[a-z0-9]+$", group_name):
        raise GroupOperationError(
            "Group name can only contain lowercase letters and numbers. "
            "Uppercase letters and underscores are not allowed. "
            "(Hive stores all names in lowercase, so 'KBase' and 'kbase' would collide.)"
        )

    # Must start with letter for better readability
    if not group_name[0].isalpha():
        raise GroupOperationError("Group name must start with a letter")

    # Reserved group names for data governance
    reserved_groups = {
        "admin",
        "root",
        "system",
        "all",
        "everyone",
        "public",
        "default",
        "minio",
        "service",
        "backup",
        "warehouse",
    }
    if group_name.lower() in reserved_groups:
        raise GroupOperationError(
            f"Group name '{group_name}' is reserved for system use"
        )

    return group_name


# =============================================================================
# BUCKET VALIDATION
# =============================================================================


# copied from CTS - https://github.com/kbase/cdm-task-service/blob/main/cdmtaskservice/s3/paths.py#L98
def validate_bucket_name(bucket_name: str, index: int | None = None):
    """
    Validate an S3 bucket name.

    bucket_name - the bucket name to validate.
    index - the index of the bucket name in some external data structure.
        The index will be added to error messages.

    Returns a bucket name stripped of whitespace..
    """
    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    i = f" at index {index}" if index is not None else ""
    bn = bucket_name.strip()
    if not bn:
        raise BucketValidationError(f"Bucket name{i} cannot be whitespace only")
    if len(bn) < 3 or len(bn) > 63:
        raise BucketValidationError(
            f"Bucket name{i} must be > 2 and < 64 characters: {bn}"
        )
    if "." in bn:
        raise BucketValidationError(
            f"Bucket{i} has `.` in the name which is unsupported: {bn}"
        )
    if bn.startswith("-") or bn.endswith("-"):
        raise BucketValidationError(
            f"Bucket name{i} cannot start or end with '-': {bn}"
        )
    if not bn.replace("-", "").isalnum() or not bn.isascii() or not bn.islower():
        raise BucketValidationError(
            f"Bucket name{i} may only contain '-' and lowercase ascii alphanumerics: {bn}"
        )
    return bn


# =============================================================================
# S3 PATH VALIDATION
# =============================================================================


def validate_s3_path(path: str) -> str:
    """
    Validate S3 path for data governance operations with strict AWS compliance.

    Data governance always requires strict path validation for:
    - Security (prevent path traversal)
    - Consistency (standardized S3 URL formats)
    - Compliance (AWS S3 standards)
    - Cross-platform compatibility

    Args:
        path: S3 path to validate (must start with s3:// or s3a://)

    Returns:
        str: Validated S3 path

    Raises:
        PolicyValidationError: If path validation fails
    """
    path = not_falsy(path, "S3 path")
    path = path.strip()

    # Always enforce S3 URL format for data governance
    if not path.startswith(("s3://", "s3a://")):
        raise PolicyValidationError(
            "S3 path must start with 's3://' or 's3a://' protocol"
        )

    # Extract protocol, bucket, and key components
    protocol_len = 5 if path.startswith("s3://") else 6
    path_without_protocol = path[protocol_len:]

    if not path_without_protocol:
        raise PolicyValidationError("S3 path must include a bucket name")

    path_parts = path_without_protocol.split("/", 1)
    bucket = path_parts[0]

    # Validate bucket name using bucket validator
    validate_bucket_name(bucket)

    # Validate object key - it must be present for data governance operations
    if len(path_parts) < 2 or not path_parts[1]:
        raise PolicyValidationError(
            "S3 path must include an object key (path within bucket) for data governance operations"
        )

    key = path_parts[1]
    _validate_s3_object_key(key)

    return path


def _validate_s3_object_key(key: str) -> None:
    """Validate S3 object key according to AWS standards."""
    # AWS S3 object key restrictions
    if len(key) > 1024:
        raise PolicyValidationError("S3 object key cannot exceed 1024 characters")

    # Disallow non-ASCII characters to prevent Unicode evasion of path checks
    # This also blocks zero-width and suspicious Unicode whitespace characters
    if not key.isascii():
        raise PolicyValidationError(
            "S3 object key must use ASCII characters only to prevent Unicode-based path bypasses"
        )

    # Check for invalid characters in key
    invalid_chars = ["\n", "\r", "\0"]
    for char in invalid_chars:
        if char in key:
            raise PolicyValidationError(
                "S3 object key cannot contain control characters"
            )

    # Leading/trailing whitespace should be avoided
    if key != key.strip():
        raise PolicyValidationError(
            "S3 object key should not have leading or trailing whitespace"
        )

    # Empty key segments (double slashes) should be avoided
    if "//" in key:
        raise PolicyValidationError(
            "S3 object key should not contain empty path segments"
        )

    # Check for path traversal attacks
    if "../" in key or "/.." in key or key.startswith("../") or key.endswith("/.."):
        raise PolicyValidationError(
            "S3 object key contains path traversal sequences - this is a security violation"
        )

    # Check for URL-encoded path traversal attacks
    url_encoded_patterns = [
        "%2e%2e%2f",
        "%2e%2e/",
        "%2e%2e\\",
        "%2f%2e%2e",
        "..%2f",
        "%5c%2e%2e",
    ]
    key_lower = key.lower()
    for pattern in url_encoded_patterns:
        if pattern in key_lower:
            raise PolicyValidationError(
                "S3 object key contains encoded path traversal sequences - this is a security violation"
            )

    # Check for multiple dots and other evasion techniques
    if "...." in key or "..\\." in key or "..\\" in key:
        raise PolicyValidationError(
            "S3 object key contains suspicious path patterns - this is a security violation"
        )


def validate_path_prefix(prefix: str) -> str:
    """
    Validates a prefix to ensure it's a valid, non-empty path component.

    - Must not be empty or whitespace.
    - Must not contain path separators to prevent security issues.

    Args:
        prefix: The prefix string to validate.

    Returns:
        The validated, stripped prefix.

    Raises:
        ValidationError: If the prefix is invalid.
    """
    prefix = not_falsy(prefix, "Path prefix")
    stripped_prefix = prefix.strip()

    if "\\" in stripped_prefix or ".." in stripped_prefix:
        raise ValidationError(
            f"Path prefix '{stripped_prefix}' cannot contain path separators ('\\', '..')."
        )

    return stripped_prefix


# =============================================================================
# POLICY VALIDATION
# =============================================================================


def validate_policy_name(policy_name: str) -> str:
    """
    Validate IAM policy name for data governance with comprehensive MinIO compatibility.

    Policy names in data governance should be:
    - Descriptive and meaningful
    - Compatible with MinIO policy system
    - Consistent naming convention
    - Safe for policy operations and attachment

    Args:
        policy_name: Policy name to validate

    Returns:
        str: Validated and normalized policy name

    Raises:
        PolicyValidationError: If policy name validation fails
    """
    policy_name = not_falsy(policy_name, "Policy name")
    policy_name = policy_name.strip()

    # Length constraints for MinIO compatibility (stricter than original for consistency)
    if len(policy_name) < 2 or len(policy_name) > 128:
        raise PolicyValidationError("Policy name must be between 2 and 128 characters")

    # Character constraints - allow alphanumeric, periods, hyphens, underscores
    if not re.match(r"^[a-zA-Z0-9._-]+$", policy_name):
        raise PolicyValidationError(
            "Policy name can only contain alphanumeric characters, periods (.), hyphens (-), and underscores (_)"
        )

    # Cannot start with a period for MinIO compatibility
    if policy_name[0] == ".":
        raise PolicyValidationError("Policy name cannot start with a period")

    # Check for reserved policy names (MinIO built-in policies)
    if policy_name in BUILT_IN_POLICIES:
        raise PolicyValidationError(f"'{policy_name}' is a reserved policy name")

    # Avoid names that could be confused with system policies
    if policy_name.startswith("arn:"):
        raise PolicyValidationError("Policy name cannot start with 'arn:'")

    # naming patterns for data governance
    if not any(
        policy_name.startswith(prefix) for prefix in DATA_GOVERNANCE_POLICY_PREFIXES
    ):
        raise PolicyValidationError(
            f"Policy name should start with '{USER_HOME_POLICY_PREFIX}', '{USER_SYSTEM_POLICY_PREFIX}', or '{GROUP_POLICY_PREFIX}'"
        )

    return policy_name
