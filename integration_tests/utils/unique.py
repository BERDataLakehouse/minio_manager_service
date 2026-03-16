"""
Unique identifier generators for parallel-safe integration tests.

All resources created during tests use these generators to ensure
no collisions between parallel test workers.
"""

import uuid
from datetime import datetime


def unique_id() -> str:
    """
    Generate a short unique identifier for test resources.

    Returns:
        str: 8-character hex string (e.g., 'a1b2c3d4')
    """
    return uuid.uuid4().hex[:8]


def unique_username(prefix: str = "testuser") -> str:
    """
    Generate a unique username.

    Args:
        prefix: Prefix for the username (default: 'testuser')

    Returns:
        str: Username like 'testuser_a1b2c3d4'
    """
    return f"{prefix}_{unique_id()}"


def unique_group_name(prefix: str = "testgroup") -> str:
    """
    Generate a unique group/tenant name.

    Note: Group names can only contain lowercase letters and numbers.
    Underscores are NOT allowed (Hive compatibility).

    Args:
        prefix: Prefix for the group name (default: 'testgroup')

    Returns:
        str: Group name like 'testgroupa1b2c3d4' (no underscores)
    """
    return f"{prefix}{unique_id()}"


def unique_table_name(username: str) -> str:
    """
    Generate a unique table name following governance conventions.

    Format: u_{username}__test_{uuid}

    Args:
        username: Owner username

    Returns:
        str: Table name like 'u_testuser_a1b2c3d4__test_e5f6g7h8'
    """
    return f"u_{username}__test_{unique_id()}"


def unique_file_name(extension: str = "txt") -> str:
    """
    Generate a unique file name.

    Args:
        extension: File extension without dot (default: 'txt')

    Returns:
        str: Filename like 'test_a1b2c3d4.txt'
    """
    return f"test_{unique_id()}.{extension}"


def unique_timestamp() -> str:
    """
    Generate a timestamp string for unique identification.

    Returns:
        str: Timestamp like '20231208_153045_123456'
    """
    now = datetime.now()
    return now.strftime("%Y%m%d_%H%M%S_%f")
