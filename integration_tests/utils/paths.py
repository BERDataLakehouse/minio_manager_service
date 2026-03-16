"""
S3 path utilities for integration tests.

Provides helpers for constructing valid S3 paths following
the MinIO Manager service conventions.
"""

from .unique import unique_table_name, unique_file_name


# Default bucket used by the service
DEFAULT_BUCKET = "cdm-lake"

# Warehouse prefixes
USERS_GENERAL_WAREHOUSE = "users-general-warehouse"
USERS_SQL_WAREHOUSE = "users-sql-warehouse"
TENANT_GENERAL_WAREHOUSE = "tenant-general-warehouse"
TENANT_SQL_WAREHOUSE = "tenant-sql-warehouse"


def user_home_path(username: str, warehouse: str = "general") -> str:
    """
    Get the home path for a user.

    Args:
        username: The username
        warehouse: 'general' or 'sql' (default: 'general')

    Returns:
        str: S3 path like 's3a://cdm-lake/users-general-warehouse/username/'
    """
    prefix = USERS_SQL_WAREHOUSE if warehouse == "sql" else USERS_GENERAL_WAREHOUSE
    return f"s3a://{DEFAULT_BUCKET}/{prefix}/{username}/"


def user_table_path(username: str, table_name: str | None = None) -> str:
    """
    Get the path for a user's table in SQL warehouse.

    Args:
        username: The username
        table_name: Table name (auto-generated if None)

    Returns:
        str: S3 path like 's3a://cdm-lake/users-sql-warehouse/username/table.db/'
    """
    if table_name is None:
        table_name = unique_table_name(username)
    return f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{username}/{table_name}.db/"


def user_file_path(
    username: str, filename: str | None = None, table_name: str | None = None
) -> str:
    """
    Get the path for a file in a user's table.

    Args:
        username: The username
        filename: File name (auto-generated if None)
        table_name: Table name (auto-generated if None)

    Returns:
        str: S3 path like 's3a://cdm-lake/users-sql-warehouse/username/table.db/file.txt'
    """
    if filename is None:
        filename = unique_file_name()
    if table_name is None:
        table_name = unique_table_name(username)
    return f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{username}/{table_name}.db/{filename}"


def tenant_home_path(tenant_name: str, warehouse: str = "general") -> str:
    """
    Get the home path for a tenant/group.

    Args:
        tenant_name: The tenant/group name
        warehouse: 'general' or 'sql' (default: 'general')

    Returns:
        str: S3 path like 's3a://cdm-lake/tenant-general-warehouse/tenant/'
    """
    prefix = TENANT_SQL_WAREHOUSE if warehouse == "sql" else TENANT_GENERAL_WAREHOUSE
    return f"s3a://{DEFAULT_BUCKET}/{prefix}/{tenant_name}/"


def parse_s3_path(path: str) -> dict:
    """
    Parse an S3 path into components.

    Args:
        path: S3 path like 's3a://bucket/prefix/key'

    Returns:
        dict: {'bucket': str, 'key': str, 'prefix': str}
    """
    # Remove s3:// or s3a:// prefix
    if path.startswith("s3a://"):
        path = path[6:]
    elif path.startswith("s3://"):
        path = path[5:]

    parts = path.split("/", 1)
    bucket = parts[0]
    key = parts[1] if len(parts) > 1 else ""

    return {
        "bucket": bucket,
        "key": key,
        "full_path": f"s3a://{bucket}/{key}",
    }
