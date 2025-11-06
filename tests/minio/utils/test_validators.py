"""Tests for the minio.utils.validators module."""

import pytest

from src.minio.utils import validators
from src.service.exceptions import GroupOperationError, UserOperationError


# =============================================================================
# GROUP NAME VALIDATION TESTS
# =============================================================================


def test_validate_group_name_valid():
    """Test that valid group names pass validation (lowercase only)."""
    assert validators.validate_group_name("kbase") == "kbase"
    assert validators.validate_group_name("tenant123") == "tenant123"
    assert validators.validate_group_name("myorg") == "myorg"
    assert validators.validate_group_name("ab") == "ab"  # Minimum length


def test_validate_group_name_strips_whitespace():
    """Test that group name whitespace is stripped."""
    assert validators.validate_group_name("  kbase  ") == "kbase"
    assert validators.validate_group_name("\tkbase\n") == "kbase"


def test_validate_group_name_no_underscores():
    """Test that group names with underscores are rejected.

    Underscores are not allowed in tenant names to prevent ambiguity
    with the namespace separator: {tenant}_{namespace}
    """
    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("my_tenant")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("tenant_name_123")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("kbase_org")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("_tenant")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("tenant_")


def test_validate_group_name_no_uppercase():
    """Test that group names with uppercase letters are rejected.

    Uppercase letters would cause Hive namespace collisions because Hive
    stores all database names in lowercase. 'KBase' and 'kbase' would both
    become 'kbase_' in Hive.
    """
    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("KBase")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("MyOrg")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("Tenant123")

    with pytest.raises(GroupOperationError, match="Hive stores all names in lowercase"):
        validators.validate_group_name("MixedCase")


def test_validate_group_name_invalid_length():
    """Test that group names with invalid length are rejected."""
    with pytest.raises(GroupOperationError, match="between 2 and 64 characters"):
        validators.validate_group_name("a")  # Too short

    with pytest.raises(GroupOperationError, match="between 2 and 64 characters"):
        validators.validate_group_name("a" * 65)  # Too long


def test_validate_group_name_invalid_characters():
    """Test that group names with invalid characters are rejected."""
    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("tenant-name")  # Hyphen not allowed

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("tenant.name")  # Period not allowed

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        validators.validate_group_name("tenant@name")  # Special char not allowed


def test_validate_group_name_must_start_with_letter():
    """Test that group names must start with a letter."""
    with pytest.raises(GroupOperationError, match="must start with a letter"):
        validators.validate_group_name("1tenant")

    with pytest.raises(GroupOperationError, match="must start with a letter"):
        validators.validate_group_name("123abc")


def test_validate_group_name_reserved():
    """Test that reserved group names are rejected."""
    reserved = ["admin", "root", "system", "all", "everyone", "public", "default", "minio"]
    for name in reserved:
        with pytest.raises(GroupOperationError, match="reserved for system use"):
            validators.validate_group_name(name)

        # Uppercase versions are rejected due to lowercase-only requirement
        with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
            validators.validate_group_name(name.upper())


# =============================================================================
# USERNAME VALIDATION TESTS
# =============================================================================


def test_validate_username_valid():
    """Test that valid usernames pass validation."""
    assert validators.validate_username("alice") == "alice"
    assert validators.validate_username("bob123") == "bob123"
    assert validators.validate_username("user.name-123") == "user.name-123"
    assert validators.validate_username("user_name") == "user_name"  # Underscores OK for users


def test_validate_username_allows_underscores():
    """Test that usernames can contain underscores (unlike group names)."""
    assert validators.validate_username("my_user") == "my_user"
    assert validators.validate_username("user_name_123") == "user_name_123"


def test_validate_username_invalid():
    """Test that invalid usernames are rejected."""
    with pytest.raises(UserOperationError):
        validators.validate_username("a")  # Too short

    with pytest.raises(UserOperationError):
        validators.validate_username("admin")  # Reserved

    with pytest.raises(UserOperationError):
        validators.validate_username("user@name")  # Invalid char 