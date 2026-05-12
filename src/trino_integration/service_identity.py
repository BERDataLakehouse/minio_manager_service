"""Trino tenant catalog naming + global service-identity access management.

For every BERDL tenant, the Trino coordinator needs a stable, platform-owned
identity it can authenticate as when reading the tenant's Iceberg metadata
(via Polaris) and data files (via MinIO/S3 IAM). BERDL uses a **single
global identity** for this — one Polaris service principal + one IAM service
user — pre-provisioned by an admin once per environment.

The credentials live in `mms-env.yaml` (and the matching docker-compose env
block for local dev) under `TRINO_GLOBAL_*`. MMS grants this identity access
to each new tenant catalog at tenant-create time and revokes on
tenant-delete, but never mints or stores per-tenant credentials.

This module owns:
- Tenant naming helpers used by the reconciler (`tenant_alias`,
  `tenant_warehouse_name`); tenant-name validation lives in
  ``s3.utils.validators.validate_tenant_group_name``.
- The grant/revoke helpers (`grant_global_trino_access`,
  `revoke_global_trino_access`) called from the create/delete-group routes.

The reconciler's `CREATE CATALOG` work lives in
`trino_integration.reconciler`.
"""

import logging
import re

from polaris.constants import tenant_reader_principal_role
from s3.utils.validators import validate_tenant_group_name

logger = logging.getLogger(__name__)


def tenant_alias(group_name: str) -> str:
    """Trino catalog alias for a tenant group.

    Mirrors the sanitization used by ``setup_trino_session._sanitize_identifier``
    so the reconciler-created Trino catalog name matches the Spark-side alias
    that notebooks already use.
    """
    return re.sub(r"[^a-z0-9_]", "_", group_name.lower()).strip("_")


def tenant_warehouse_name(group_name: str) -> str:
    """Polaris warehouse identifier for a tenant group (``tenant_{group}``)."""
    return f"tenant_{group_name}"


async def grant_global_trino_access(group_name: str, *, app_state) -> None:
    """Grant the configured global Trino service identity access to a tenant.

    Two side effects, both idempotent against the underlying APIs:

    1. ``TRINO_GLOBAL_IAM_USERNAME`` is added to ``{group}ro``, inheriting
       the existing ``GROUP_HOME_RO`` policy (which scopes S3 reads to the
       tenant's warehouse prefix).
    2. ``TRINO_GLOBAL_POLARIS_PRINCIPAL`` is granted the existing
       ``{group}ro_member`` principal role on the new tenant catalog,
       carrying ``TABLE_READ_DATA, TABLE_LIST, NAMESPACE_LIST``.

    When either env var is unset (test/local-dev convenience) the matching
    step is skipped silently. Production environments must set both.
    """
    group_name = validate_tenant_group_name(group_name)
    ro_group = f"{group_name}ro"

    if app_state.trino_global_iam_username:
        await app_state.group_manager.add_user_to_group(
            app_state.trino_global_iam_username, ro_group
        )
    else:
        logger.debug(
            "TRINO_GLOBAL_IAM_USERNAME is unset; skipping IAM-side grant for %s",
            group_name,
        )

    if app_state.trino_global_polaris_principal:
        await app_state.polaris_service.grant_principal_role_to_principal(
            principal=app_state.trino_global_polaris_principal,
            principal_role=tenant_reader_principal_role(group_name),
        )
    else:
        logger.debug(
            "TRINO_GLOBAL_POLARIS_PRINCIPAL is unset; skipping Polaris-side grant for %s",
            group_name,
        )

    logger.info(
        "Granted global Trino access for tenant %s (iam_user=%s, polaris_principal=%s)",
        group_name,
        app_state.trino_global_iam_username or "(unset)",
        app_state.trino_global_polaris_principal or "(unset)",
    )


async def revoke_global_trino_access(group_name: str, *, app_state) -> None:
    """Revoke the global Trino service identity's access to a tenant.

    Best-effort teardown — each step logs and continues on failure so a
    partial state can be cleaned up by re-running. Mirrors the
    grant order in reverse: Polaris-side revoke first (so the principal
    can no longer list the tenant via Polaris), then IAM-side removal
    from ``{group}ro``.
    """
    group_name = validate_tenant_group_name(group_name)
    ro_group = f"{group_name}ro"

    if app_state.trino_global_polaris_principal:
        try:
            await app_state.polaris_service.revoke_principal_role_from_principal(
                principal=app_state.trino_global_polaris_principal,
                principal_role=tenant_reader_principal_role(group_name),
            )
        except Exception as e:  # noqa: BLE001 — best-effort teardown
            logger.warning(
                "Failed to revoke Polaris role binding for global principal %s on tenant %s: %s; continuing teardown.",
                app_state.trino_global_polaris_principal,
                group_name,
                e,
            )

    if app_state.trino_global_iam_username:
        try:
            await app_state.group_manager.remove_user_from_group(
                app_state.trino_global_iam_username, ro_group
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "Failed to remove global IAM user %s from %s: %s; continuing teardown.",
                app_state.trino_global_iam_username,
                ro_group,
                e,
            )

    logger.info(
        "Revoked global Trino access for tenant %s",
        group_name,
    )
