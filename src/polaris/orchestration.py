"""Cross-manager Polaris orchestration helpers.

The higher-level workflow that spans both :class:`PolarisUserManager` and
:class:`PolarisGroupManager` plus the MinIO group manager. Lives above the
manager layer so multiple callers (route handlers, the unified credential
flow) share one definition and stay in sync. Idempotent: repeated calls
produce the same end state.

Takes the three managers explicitly (rather than via :class:`AppState`) to
avoid an import cycle through ``service.app_state`` and to keep the helper
usable from service-layer callers that don't hold an ``AppState``.
"""

import logging

from minio.managers.group_manager import GroupManager
from polaris.constants import (
    dedup_groups_preferring_write,
    personal_catalog_name,
    tenant_catalog_name,
)
from polaris.managers.group_manager import PolarisGroupManager
from polaris.managers.user_manager import PolarisUserManager

logger = logging.getLogger(__name__)


async def ensure_user_polaris_state(
    username: str,
    polaris_user_manager: PolarisUserManager,
    polaris_group_manager: PolarisGroupManager,
    group_manager: GroupManager,
    exclude_groups: set[str] | None = None,
) -> tuple[str, list[str]]:
    """Idempotently align the user's Polaris state with their MinIO state.

    Performed work:
      1. Ensure personal Polaris assets exist (catalog ``user_{username}``,
         principal, ``catalog_admin`` catalog role, ``{username}_role``
         principal role, role bindings) via
         :meth:`PolarisUserManager.create_user`.
      2. Read the user's current MinIO group memberships via
         :meth:`MinioGroupManager.get_user_groups`.
      3. Deduplicate using :func:`dedup_groups_preferring_write` so a user
         in both ``teamA`` and ``teamAro`` gets one writer binding (not
         both writer and reader).
      4. For each unique base group, mirror the membership into Polaris via
         :meth:`PolarisGroupManager.add_user_to_group`. Bases listed in
         ``exclude_groups`` are skipped so their tenant catalogs and role
         bindings are not touched (used by the bulk-backfill migration
         endpoint that supports operator-supplied exclusion lists).

    Takes managers individually (rather than an ``AppState``) so service-
    layer callers like :class:`CredentialService` can use it without
    pulling in ``AppState``.

    Returns:
        ``(personal_catalog_name, tenant_catalog_names)`` — the tenant list
        preserves the dedup helper's first-seen order of base groups, with
        any excluded bases omitted.
    """
    excluded = exclude_groups or set()
    catalog = personal_catalog_name(username)

    # 1. Personal Polaris assets.
    await polaris_user_manager.create_user(username)

    # 2-4. Mirror MinIO group memberships into Polaris role bindings.
    user_groups = await group_manager.get_user_groups(username)
    deduped = dedup_groups_preferring_write(user_groups)

    tenant_catalogs: list[str] = []
    for base_group, is_ro in deduped.items():
        if base_group in excluded:
            continue
        tenant_catalogs.append(tenant_catalog_name(base_group))
        # Pass the canonical *name* (with or without "ro" suffix) so
        # PolarisGroupManager picks the right writer/reader role.
        group_name = f"{base_group}ro" if is_ro else base_group
        await polaris_group_manager.add_user_to_group(username, group_name)

    return catalog, tenant_catalogs
