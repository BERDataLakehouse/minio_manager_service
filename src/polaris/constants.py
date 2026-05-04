"""Shared constants and helpers for Polaris integration.

Centralises the naming conventions used by Polaris catalogs, catalog roles,
and principal roles so the routes layer and the :class:`PolarisService`
agree on the same strings. Changing a convention here propagates through
``ensure_tenant_catalog`` / ``drop_tenant_catalog`` and the provisioning /
effective-access routes without further edits.
"""

from collections.abc import Iterable
from typing import Tuple

# ----- Storage layout -----

# Subdirectory appended to SQL warehouse paths for Iceberg catalog storage.
# Each user/tenant catalog stores data under <warehouse_path>/<name>/iceberg/.
# This path has its own IAM statement separate from the u_{username}__* governed path.
ICEBERG_STORAGE_SUBDIRECTORY = "iceberg"


# ----- Personal-catalog naming -----

# Catalog role granted CATALOG_MANAGE_CONTENT on a user's personal catalog.
PERSONAL_CATALOG_ADMIN_ROLE = "catalog_admin"


def personal_catalog_name(username: str) -> str:
    """Catalog name for a user's personal Iceberg catalog (``user_{username}``)."""
    return f"user_{username}"


def personal_principal_role(username: str) -> str:
    """Principal role bound to a user's personal catalog (``{username}_role``)."""
    return f"{username}_role"


# ----- Tenant-catalog naming -----


def tenant_catalog_name(group: str) -> str:
    """Catalog name for a tenant's shared Iceberg catalog (``tenant_{group}``)."""
    return f"tenant_{group}"


def tenant_writer_catalog_role(group: str) -> str:
    """Tenant catalog role with CATALOG_MANAGE_CONTENT (``{group}_writer``)."""
    return f"{group}_writer"


def tenant_reader_catalog_role(group: str) -> str:
    """Tenant catalog role with read-only privileges (``{group}_reader``)."""
    return f"{group}_reader"


def tenant_writer_principal_role(group: str) -> str:
    """Principal role bound to the tenant writer catalog role (``{group}_member``)."""
    return f"{group}_member"


def tenant_reader_principal_role(group: str) -> str:
    """Principal role bound to the tenant reader catalog role (``{group}ro_member``)."""
    return f"{group}ro_member"


# ----- Group-name conventions -----


def normalize_group_name_for_polaris(group_name: str) -> Tuple[str, bool]:
    """Derive the base group name and read-only flag for Polaris operations.

    Read-only groups use the suffix "ro" (e.g., "kbasero" → base "kbase", is_ro=True).

    Returns:
        (base_group_name, is_read_only_group)
    """
    if group_name.endswith("ro"):
        return group_name[:-2], True
    return group_name, False


def dedup_groups_preferring_write(
    user_groups: Iterable[str],
) -> dict[str, bool]:
    """Collapse a user's MinIO group memberships to one Polaris binding per tenant.

    A user can belong to both the read-write (``teamA``) and read-only
    (``teamAro``) variants of the same tenant. In Polaris we only need the
    higher-privilege binding — granting both is wasteful and the writer role
    is a strict superset of the reader role anyway.

    Empty base names (e.g., a group literally called ``"ro"``) are dropped
    defensively so we never call Polaris with an empty catalog name.

    Used by both the live provisioning path
    (:func:`polaris.orchestration.ensure_user_polaris_state`) and the bulk
    backfill (``ensure-polaris-resources`` migration endpoint) so they apply
    identical role-binding semantics.

    Returns:
        Mapping from base group name to ``is_read_only`` flag.
    """
    deduped: dict[str, bool] = {}
    for group_name in user_groups:
        base, is_ro = normalize_group_name_for_polaris(group_name)
        if not base:
            continue
        # Prefer write (is_ro=False) over read (is_ro=True) when both variants present.
        if not is_ro or base not in deduped:
            deduped[base] = is_ro
    return deduped
