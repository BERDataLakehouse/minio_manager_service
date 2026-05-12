"""Trino tenant catalog naming helpers.

For every BERDL tenant, the Trino coordinator needs a stable, platform-owned
identity it can authenticate as when reading the tenant's Iceberg metadata
(via Polaris) and data files (via MinIO/S3 IAM). BERDL uses a **single
global identity** for this — one Polaris service principal + one IAM service
user — pre-provisioned by an admin once per environment.

The global identity is granted broad access at bootstrap time (Polaris
`service_admin` role + `s3:*` on the `cdm-lake` bucket), so MMS does not
need to add per-tenant Polaris roles or IAM group memberships. The
credentials live in `mms-env.yaml` under `TRINO_GLOBAL_S3_*` and
`TRINO_GLOBAL_POLARIS_CLIENT_*`.

This module owns the tenant naming helpers used by the reconciler
(`tenant_alias`, `tenant_warehouse_name`); tenant-name validation lives in
``s3.utils.validators.validate_tenant_group_name``. The reconciler's
`CREATE CATALOG` work lives in `trino_integration.reconciler`.
"""

import re


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
