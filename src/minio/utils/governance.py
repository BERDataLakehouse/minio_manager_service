"""
Governance naming utilities for SQL warehouse resources.

This module centralizes generation of governance prefixes used to enforce
table/database naming rules for users and groups (tenants).
"""

from .validators import validate_group_name, validate_username

# Markers and separator used in governance prefixes
USER_PREFIX_MARKER = "u_"
USER_GOVERNANCE_SUFFIX_SEPARATOR = "__"
TENANT_GOVERNANCE_SUFFIX_SEPARATOR = "_"


def _format_user_governance_prefix(validated_username: str) -> str:
    return f"{USER_PREFIX_MARKER}{validated_username}{USER_GOVERNANCE_SUFFIX_SEPARATOR}"


def _format_tenant_governance_prefix(validated_tenant_name: str) -> str:
    return f"{validated_tenant_name}{TENANT_GOVERNANCE_SUFFIX_SEPARATOR}"


def generate_user_governance_prefix(username: str) -> str:
    """Return the governance prefix for a user's SQL warehouse names.

    Example: username "alice" -> "u_alice__"
    """
    validated_username = validate_username(username)
    return _format_user_governance_prefix(validated_username)


def generate_group_governance_prefix(group_name: str) -> str:
    """Return the governance prefix for a group's (tenant's) SQL warehouse names.

    Example: group_name "kbase" -> "kbase_"

    Note: Group/tenant names cannot contain underscores to prevent
    ambiguity with the namespace separator.
    """
    validated_group_name = validate_group_name(group_name)
    return _format_tenant_governance_prefix(validated_group_name)


