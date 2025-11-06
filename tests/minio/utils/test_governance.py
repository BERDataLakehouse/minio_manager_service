"""Tests for the minio.utils.governance module."""

import pytest

from src.minio.utils import governance
from src.service.exceptions import GroupOperationError, UserOperationError


# =============================================================================
# USER GOVERNANCE PREFIX TESTS
# =============================================================================


def test_generate_user_governance_prefix_valid():
    """Test that valid usernames generate correct governance prefixes."""
    assert governance.generate_user_governance_prefix("alice") == "u_alice__"
    assert governance.generate_user_governance_prefix("bob123") == "u_bob123__"
    assert governance.generate_user_governance_prefix("user.name-123") == "u_user.name-123__"


def test_generate_user_governance_prefix_strips_whitespace():
    """Test that username whitespace is stripped."""
    assert governance.generate_user_governance_prefix("  alice  ") == "u_alice__"


def test_generate_user_governance_prefix_invalid():
    """Test that invalid usernames raise UserOperationError."""
    with pytest.raises(UserOperationError):
        governance.generate_user_governance_prefix("a")  # Too short

    with pytest.raises(UserOperationError):
        governance.generate_user_governance_prefix("admin")  # Reserved

    with pytest.raises(UserOperationError):
        governance.generate_user_governance_prefix("user@name")  # Invalid char


# =============================================================================
# TENANT/GROUP GOVERNANCE PREFIX TESTS
# =============================================================================


def test_generate_group_governance_prefix_valid():
    """Test that valid group names generate correct governance prefixes."""
    # New pattern: {tenant}_ (no "t_" prefix, single underscore, lowercase only)
    assert governance.generate_group_governance_prefix("kbase") == "kbase_"
    assert governance.generate_group_governance_prefix("tenant123") == "tenant123_"
    assert governance.generate_group_governance_prefix("myorg") == "myorg_"


def test_generate_group_governance_prefix_strips_whitespace():
    """Test that group name whitespace is stripped."""
    assert governance.generate_group_governance_prefix("  kbase  ") == "kbase_"


def test_generate_group_governance_prefix_no_underscores_allowed():
    """Test that group names with underscores are rejected."""
    # Underscores are NOT allowed in tenant names to avoid ambiguity
    # with the namespace separator: {tenant}_{namespace}
    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        governance.generate_group_governance_prefix("my_tenant")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        governance.generate_group_governance_prefix("tenant_name_123")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        governance.generate_group_governance_prefix("kbase_org")


def test_generate_group_governance_prefix_no_uppercase_allowed():
    """Test that group names with uppercase letters are rejected.

    Uppercase letters cause Hive namespace collisions because Hive stores
    all database names in lowercase. For example, 'KBase' and 'kbase' would
    both become 'kbase_' in Hive, causing a collision.
    """
    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        governance.generate_group_governance_prefix("KBase")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        governance.generate_group_governance_prefix("MyOrg")

    with pytest.raises(GroupOperationError, match="lowercase letters and numbers"):
        governance.generate_group_governance_prefix("Tenant123")

    with pytest.raises(GroupOperationError, match="Hive stores all names in lowercase"):
        governance.generate_group_governance_prefix("MixedCase")


def test_generate_group_governance_prefix_invalid():
    """Test that invalid group names raise GroupOperationError."""
    with pytest.raises(GroupOperationError):
        governance.generate_group_governance_prefix("a")  # Too short

    with pytest.raises(GroupOperationError):
        governance.generate_group_governance_prefix("admin")  # Reserved

    with pytest.raises(GroupOperationError):
        governance.generate_group_governance_prefix("1tenant")  # Starts with number

    with pytest.raises(GroupOperationError):
        governance.generate_group_governance_prefix("tenant-name")  # Hyphen not allowed


# =============================================================================
# NAMESPACE PATTERN TESTS
# =============================================================================


def test_user_namespace_pattern():
    """Test that user namespace follows u_{username}__ pattern."""
    prefix = governance.generate_user_governance_prefix("alice")
    namespace = "my_database"
    full_name = f"{prefix}{namespace}"

    assert full_name == "u_alice__my_database"
    # Double underscore allows usernames to contain underscores
    assert full_name.startswith("u_")
    assert "__" in full_name


def test_tenant_namespace_pattern():
    """Test that tenant namespace follows {tenant}_{namespace} pattern."""
    prefix = governance.generate_group_governance_prefix("kbase")
    namespace = "my_database"
    full_name = f"{prefix}{namespace}"

    assert full_name == "kbase_my_database"
    # Single underscore in prefix - tenant cannot contain underscores
    assert not full_name.startswith("t_")
    # The prefix itself has exactly one underscore
    assert prefix == "kbase_"
    assert prefix.count("_") == 1
    # The namespace can contain underscores (that's allowed)
    assert full_name.startswith("kbase_")


def test_namespace_patterns_are_distinct():
    """Test that user and tenant namespace patterns are distinguishable."""
    user_prefix = governance.generate_user_governance_prefix("alice")
    tenant_prefix = governance.generate_group_governance_prefix("kbase")

    # User prefix always starts with "u_"
    assert user_prefix.startswith("u_")

    # Tenant prefix never starts with "t_" or "u_"
    assert not tenant_prefix.startswith("t_")
    assert not tenant_prefix.startswith("u_")

    # User prefix ends with double underscore
    assert user_prefix.endswith("__")

    # Tenant prefix ends with single underscore
    assert tenant_prefix.endswith("_")
    assert not tenant_prefix.endswith("__")


# =============================================================================
# SEPARATOR CONSTANT TESTS
# =============================================================================


def test_separator_constants():
    """Test that separator constants are correctly defined."""
    assert governance.USER_PREFIX_MARKER == "u_"
    assert governance.USER_GOVERNANCE_SUFFIX_SEPARATOR == "__"
    assert governance.TENANT_GOVERNANCE_SUFFIX_SEPARATOR == "_" 