"""MMS-side Trino catalog reconciler for tenant Polaris catalogs.

For every BERDL tenant, the corresponding tenant Polaris catalog must be
exposed as a coordinator-global Trino catalog so users can issue
``SELECT * FROM {tenant}.{namespace}.{table}`` queries through Trino. This
module owns that lifecycle.

Architecture (see docs/trino-tenant-catalog-tech-spec.md):

* Per-tenant service identity is provisioned by
  :mod:`trino_integration.service_identity` (Phase 1) — IAM user + Polaris principal,
  both named ``trino-{group}-svc``, both members of ``{group}ro``. Their
  credentials are persisted in the s3 + polaris credential stores.
* The reconciler reads those credentials and issues ``CREATE CATALOG`` to
  the Trino coordinator as the configured admin identity (default
  ``platform_admin``), authenticated via the ``trino_admin_token`` extra
  credential. The plugin's admin path (Phase 2) authorizes the call.
* Drops use the same admin path, called from the tenant-deletion flow.

The Trino dbapi is synchronous; we wrap calls in ``asyncio.to_thread`` to
avoid blocking the FastAPI event loop. The dbapi connection is short-lived
per call rather than held open — admin operations are infrequent and a
fresh connection avoids stale-token edge cases.
"""

import asyncio
import logging
import os
import re
from typing import Iterable

import trino

from credentials.polaris_store import PolarisCredentialStore
from credentials.s3_store import S3CredentialStore
from service.exceptions import PolarisOperationError
from trino_integration.service_identity import (
    service_user_name,
    tenant_alias,
    tenant_warehouse_name,
    validate_trino_tenant_name,
)

logger = logging.getLogger(__name__)

ADMIN_TOKEN_KEY = "trino_admin_token"

# Allowed names follow the access-control plugin's TENANT_ALIAS_PATTERN
# verbatim; if these diverge, the plugin will reject otherwise-valid
# reconcile calls. Mirrors trino_access_control:BerdlSystemAccessControl.
_TENANT_ALIAS_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,62}")

# SQL allow-list. The values we splice into CREATE CATALOG come from MMS env
# vars and credential stores; we still validate every key + escape every
# value to defend against accidental injection from a corrupted store.
_ALLOWED_PROPERTY_KEYS = frozenset(
    {
        "iceberg.catalog.type",
        "iceberg.rest-catalog.uri",
        "iceberg.rest-catalog.warehouse",
        "iceberg.rest-catalog.security",
        "iceberg.rest-catalog.oauth2.credential",
        "iceberg.rest-catalog.oauth2.scope",
        "iceberg.rest-catalog.oauth2.server-uri",
        "iceberg.rest-catalog.oauth2.token-refresh-enabled",
        "iceberg.rest-catalog.oauth2.token-exchange-enabled",
        "iceberg.rest-catalog.vended-credentials-enabled",
        "iceberg.security",
        "fs.native-s3.enabled",
        "s3.endpoint",
        "s3.aws-access-key",
        "s3.aws-secret-key",
        "s3.path-style-access",
        "s3.region",
    }
)


def _escape_sql_string(value: str) -> str:
    """Escape single quotes by doubling them. Same convention as
    ``setup_trino_session._escape_sql_string``."""
    return value.replace("'", "''")


def _validate_catalog_name(name: str) -> None:
    if not _TENANT_ALIAS_PATTERN.fullmatch(name):
        raise ValueError(
            f"Invalid tenant catalog alias '{name}': must match "
            f"{_TENANT_ALIAS_PATTERN.pattern}"
        )


def _validate_property_keys(props: dict[str, str]) -> None:
    bad = [k for k in props if k not in _ALLOWED_PROPERTY_KEYS]
    if bad:
        raise ValueError(f"Disallowed Iceberg catalog property keys: {bad}")


def _polaris_oauth2_server_uri(polaris_uri: str) -> str:
    base = polaris_uri.rstrip("/")
    if base.endswith("/v1"):
        return f"{base}/oauth/tokens"
    return f"{base}/v1/oauth/tokens"


def build_iceberg_catalog_properties(
    *,
    polaris_catalog_uri: str,
    polaris_warehouse: str,
    polaris_credential: str,
    s3_endpoint: str,
    s3_access_key: str,
    s3_secret_key: str,
    s3_region: str = "us-east-1",
    s3_secure: bool = False,
) -> dict[str, str]:
    """Build the ``WITH (...)`` property map for a tenant Trino Iceberg catalog.

    Mirrors the per-user personal-catalog property set produced by
    ``spark_notebook.notebook_utils.berdl_notebook_utils.setup_trino_session
    ._build_iceberg_catalog_properties`` so both code paths end up with the
    same Trino-side configuration. The reconciler always sets
    ``iceberg.security=read_only`` and ``vended-credentials-enabled=false``
    (Trino #27416 still open at the time of writing).
    """
    if not polaris_catalog_uri:
        raise ValueError("polaris_catalog_uri is required")
    if not polaris_credential:
        raise ValueError("polaris_credential is required")

    endpoint = polaris_catalog_uri.rstrip("/")
    oauth2_server_uri = _polaris_oauth2_server_uri(endpoint)

    if not s3_endpoint.startswith("http"):
        protocol = "https" if s3_secure else "http"
        s3_endpoint_url = f"{protocol}://{s3_endpoint}"
    else:
        s3_endpoint_url = s3_endpoint

    return {
        "iceberg.catalog.type": "rest",
        "iceberg.rest-catalog.uri": endpoint,
        "iceberg.rest-catalog.warehouse": polaris_warehouse,
        "iceberg.rest-catalog.security": "OAUTH2",
        "iceberg.rest-catalog.oauth2.credential": polaris_credential,
        "iceberg.rest-catalog.oauth2.scope": "PRINCIPAL_ROLE:ALL",
        "iceberg.rest-catalog.oauth2.server-uri": oauth2_server_uri,
        "iceberg.rest-catalog.oauth2.token-refresh-enabled": "true",
        "iceberg.rest-catalog.oauth2.token-exchange-enabled": "false",
        "iceberg.rest-catalog.vended-credentials-enabled": "false",
        "iceberg.security": "read_only",
        "fs.native-s3.enabled": "true",
        "s3.endpoint": s3_endpoint_url,
        "s3.aws-access-key": s3_access_key,
        "s3.aws-secret-key": s3_secret_key,
        "s3.path-style-access": "true",
        "s3.region": s3_region,
    }


def _render_create_catalog_sql(catalog_name: str, properties: dict[str, str]) -> str:
    _validate_catalog_name(catalog_name)
    _validate_property_keys(properties)
    props_sql = ",\n        ".join(
        f"\"{k}\" = '{_escape_sql_string(v)}'" for k, v in properties.items()
    )
    return (
        f'CREATE CATALOG IF NOT EXISTS "{catalog_name}" USING iceberg\n'
        f"    WITH (\n        {props_sql}\n    )"
    )


class TrinoCatalogReconciler:
    """Issues CREATE/DROP CATALOG against Trino as the platform admin.

    Construction reads connection details from the ambient environment
    (``TRINO_HOST``, ``TRINO_PORT``, ``TRINO_ADMIN_USERNAME``,
    ``TRINO_ADMIN_TOKEN``). When ``TRINO_ADMIN_TOKEN`` is empty, every call
    raises so that misconfigured environments fail loudly rather than
    silently dropping reconcile work.

    The class holds no long-lived state; methods open and close one
    connection per invocation. Trino dbapi is synchronous, so each call
    runs on a worker thread via :func:`asyncio.to_thread`.
    """

    def __init__(
        self,
        *,
        s3_credential_store: S3CredentialStore,
        polaris_credential_store: PolarisCredentialStore,
        trino_host: str | None = None,
        trino_port: int | None = None,
        trino_admin_username: str | None = None,
        trino_admin_token: str | None = None,
        polaris_catalog_uri: str | None = None,
        s3_endpoint: str | None = None,
    ) -> None:
        self._s3_credential_store = s3_credential_store
        self._polaris_credential_store = polaris_credential_store

        self._trino_host = trino_host or os.getenv("TRINO_HOST", "trino")
        self._trino_port = int(
            trino_port if trino_port is not None else os.getenv("TRINO_PORT", "8080")
        )
        self._admin_username = trino_admin_username or os.getenv(
            "TRINO_ADMIN_USERNAME", "platform_admin"
        )
        self._admin_token = trino_admin_token or os.getenv("TRINO_ADMIN_TOKEN", "")

        self._polaris_catalog_uri = polaris_catalog_uri or os.getenv(
            "POLARIS_CATALOG_URI", ""
        )
        self._s3_endpoint = s3_endpoint or os.getenv("MINIO_ENDPOINT", "")

    def _require_admin_token(self) -> None:
        if not self._admin_token:
            raise PolarisOperationError(
                "TRINO_ADMIN_TOKEN is not configured; the Trino reconciler "
                "cannot issue CREATE/DROP CATALOG. Set the same value in "
                "the MMS env and in trino-config.yaml admin.shared-secret."
            )

    def _connect(self) -> trino.dbapi.Connection:
        return trino.dbapi.connect(
            host=self._trino_host,
            port=self._trino_port,
            user=self._admin_username,
            extra_credential=[(ADMIN_TOKEN_KEY, self._admin_token)],
        )

    async def _execute_admin_sql(self, statements: Iterable[str]) -> None:
        """Run a sequence of admin SQL statements on a fresh connection."""

        def _run():
            with self._connect() as conn:
                cursor = conn.cursor()
                for sql in statements:
                    cursor.execute(sql)
                    cursor.fetchall()

        await asyncio.to_thread(_run)

    async def tenant_catalog_exists(self, group_name: str) -> bool:
        """Return whether Trino currently has the tenant catalog alias.

        Dynamic catalogs are coordinator-local, so this is used by bootstrap
        paths to repair a freshly created or restarted environment without
        drop/recreate work when the catalog is already visible.
        """
        self._require_admin_token()
        group_name = validate_trino_tenant_name(group_name)
        alias = tenant_alias(group_name)
        _validate_catalog_name(alias)

        def _run() -> bool:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute("SHOW CATALOGS")
                return alias in {row[0] for row in cursor.fetchall()}

        return await asyncio.to_thread(_run)

    async def reconcile_tenant(self, group_name: str) -> str:
        """Recreate the Trino catalog for ``group_name`` from persisted creds.

        Idempotent. Drop-then-create semantics so a rotated service
        principal credential always replaces a stale one in the
        coordinator. Mirrors the ``force=True`` behavior of
        ``setup_trino_session._create_dynamic_catalog`` for personal
        catalogs.

        Args:
            group_name: Tenant group name (no ``ro`` suffix).

        Returns:
            The tenant catalog alias as registered in Trino.

        Raises:
            PolarisOperationError: If the admin token is unset, persisted
                credentials are missing, or Trino rejects the call.
        """
        self._require_admin_token()
        if not self._polaris_catalog_uri:
            raise PolarisOperationError(
                "POLARIS_CATALOG_URI is not configured; cannot build "
                "tenant catalog properties."
            )
        if not self._s3_endpoint:
            raise PolarisOperationError(
                "MINIO_ENDPOINT is not configured; cannot build tenant "
                "catalog properties."
            )

        group_name = validate_trino_tenant_name(group_name)
        svc_user = service_user_name(group_name)
        alias = tenant_alias(group_name)
        warehouse = tenant_warehouse_name(group_name)

        s3_creds = await self._s3_credential_store.get_credentials(svc_user)
        if s3_creds is None:
            raise PolarisOperationError(
                f"S3 credentials for service identity '{svc_user}' are not "
                f"in the credential store. Provision the service identity "
                f"first via PolarisService + service_identity orchestration."
            )
        s3_access_key, s3_secret_key = s3_creds

        polaris_record = await self._polaris_credential_store.get_credentials(svc_user)
        if polaris_record is None:
            raise PolarisOperationError(
                f"Polaris credentials for service identity '{svc_user}' are "
                f"not in the credential store."
            )
        polaris_credential = (
            f"{polaris_record.client_id}:{polaris_record.client_secret}"
        )

        properties = build_iceberg_catalog_properties(
            polaris_catalog_uri=self._polaris_catalog_uri,
            polaris_warehouse=warehouse,
            polaris_credential=polaris_credential,
            s3_endpoint=self._s3_endpoint,
            s3_access_key=s3_access_key,
            s3_secret_key=s3_secret_key,
        )

        create_sql = _render_create_catalog_sql(alias, properties)
        drop_sql = f'DROP CATALOG IF EXISTS "{alias}"'

        logger.info(
            "Reconciling Trino tenant catalog for group=%s alias=%s warehouse=%s",
            group_name,
            alias,
            warehouse,
        )
        await self._execute_admin_sql([drop_sql, create_sql])
        logger.info(
            "Trino tenant catalog '%s' reconciled (warehouse=%s)",
            alias,
            warehouse,
        )
        return alias

    async def deprovision_tenant(self, group_name: str) -> str:
        """Drop the Trino catalog for ``group_name``. Idempotent.

        Called from the tenant-deletion flow before
        :meth:`PolarisService.drop_tenant_catalog` runs, so Trino can no
        longer route to a Polaris catalog that's about to disappear.
        Tolerates the catalog already being absent.
        """
        self._require_admin_token()
        group_name = validate_trino_tenant_name(group_name)
        alias = tenant_alias(group_name)
        drop_sql = f'DROP CATALOG IF EXISTS "{alias}"'
        logger.info(
            "Dropping Trino tenant catalog for group=%s alias=%s",
            group_name,
            alias,
        )
        await self._execute_admin_sql([drop_sql])
        return alias
