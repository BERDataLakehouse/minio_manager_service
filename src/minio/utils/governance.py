"""
Governance naming utilities for SQL warehouse resources.

This module centralizes generation of governance prefixes used to enforce
table/database naming rules for users and groups (tenants).
"""

from .validators import validate_group_name, validate_username

# Markers and separator used in governance prefixes
USER_PREFIX_MARKER = "u_"
GROUP_PREFIX_MARKER = "t_"
GOVERNANCE_SUFFIX_SEPARATOR = "__"


def _format_governance_prefix(marker: str, validated_name: str) -> str:
    return f"{marker}{validated_name}{GOVERNANCE_SUFFIX_SEPARATOR}"


def generate_user_governance_prefix(username: str) -> str:
    """Return the governance prefix for a user's SQL warehouse names.

    Example: username "alice" -> "u_alice__"
    """
    validated_username = validate_username(username)
    return _format_governance_prefix(USER_PREFIX_MARKER, validated_username)


def generate_group_governance_prefix(group_name: str) -> str:
    """Return the governance prefix for a group's SQL warehouse names.

    Example: group_name "kbase" -> "t_kbase__"
    """
    validated_group_name = validate_group_name(group_name)
    return _format_governance_prefix(GROUP_PREFIX_MARKER, validated_group_name)


