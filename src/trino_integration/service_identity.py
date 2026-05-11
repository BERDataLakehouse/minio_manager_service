"""Per-tenant Trino service identity orchestration.

For every BERDL tenant, the Trino coordinator needs a stable, platform-owned
identity it can authenticate as when reading the tenant's Iceberg metadata
(via Polaris) and data files (via MinIO/S3 IAM). That identity is used in the
Trino dynamic catalog created by the reconciler. We model it as a regular
IAM user + Polaris principal pair, both named ``trino-{group}-svc``, both
added to the existing ``{group}ro`` IAM and Polaris reader infrastructure.

Why reuse ``{group}ro``: the existing read-only tenant group already has the
right MinIO ``GROUP_HOME_RO`` policy attached and the matching Polaris
``{group}ro_member`` principal role. Adding the service identity to that
group inherits those privileges automatically; no parallel IAM policy and no
extension to ``ensure_tenant_catalog`` are needed.

This module deliberately does NOT contain the Trino-side ``CREATE CATALOG``
work — that is the reconciler's job (Phase 3) and lives elsewhere. This
module is responsible only for the IAM and Polaris artifacts the reconciler
later consumes via the credential stores.
"""

import logging
import re
from dataclasses import dataclass

from credentials.polaris_store import PolarisCredentialStore
from credentials.s3_store import S3CredentialStore
from polaris.managers.group_manager import PolarisGroupManager
from polaris.managers.user_manager import PolarisUserManager
from polaris.polaris_service import PolarisService
from s3.utils.validators import validate_group_name
from service.exceptions import GroupOperationError, PolarisOperationError

logger = logging.getLogger(__name__)

TRINO_SERVICE_USER_PREFIX = "trino-"
TRINO_SERVICE_USER_SUFFIX = "-svc"
MAX_TRINO_TENANT_NAME_LENGTH = (
    64 - len(TRINO_SERVICE_USER_PREFIX) - len(TRINO_SERVICE_USER_SUFFIX)
)


def validate_trino_tenant_name(group_name: str) -> str:
    """Validate a tenant name before deriving Trino service resources.

    Tenant names accepted by MMS group creation can be up to 64 chars, but the
    derived IAM/Polaris service username is ``trino-{tenant}-svc`` and
    usernames are capped at 64 chars. Since creating a tenant now provisions
    that service identity synchronously, reject names that cannot complete the
    Trino setup before any route performs side effects.
    """
    group_name = validate_group_name(group_name)
    if group_name.endswith("ro"):
        raise GroupOperationError(
            "Tenant group name cannot end with 'ro' because that suffix is "
            "reserved for read-only tenant groups"
        )
    if len(group_name) > MAX_TRINO_TENANT_NAME_LENGTH:
        raise GroupOperationError(
            "Tenant group name must be at most "
            f"{MAX_TRINO_TENANT_NAME_LENGTH} characters for Trino integration "
            f"because service usernames use the "
            f"'{TRINO_SERVICE_USER_PREFIX}{{tenant}}{TRINO_SERVICE_USER_SUFFIX}' "
            "format"
        )
    return group_name


def service_user_name(group_name: str) -> str:
    """Stable IAM/Polaris identity name for the per-tenant Trino reader.

    Used as both the IAM username and the Polaris principal name so the two
    sides stay in sync. Length and character constraints are inherited from
    :func:`s3.utils.validators.validate_username` (allows alphanumeric, dot,
    hyphen, underscore; must start/end alphanumeric; no consecutive specials;
    2-64 chars) — for plausible group names this name is well within bounds.
    """
    return f"{TRINO_SERVICE_USER_PREFIX}{group_name}{TRINO_SERVICE_USER_SUFFIX}"


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


@dataclass(frozen=True)
class TrinoServiceIdentity:
    """Materialized per-tenant Trino service identity.

    Returned by :func:`provision_tenant_trino_service` so callers (the
    reconciler, integration tests) have everything needed to issue
    ``CREATE CATALOG`` without re-querying credential stores.
    """

    tenant_alias: str
    iam_username: str
    s3_access_key: str
    s3_secret_key: str
    polaris_principal: str
    polaris_client_id: str
    polaris_client_secret: str
    polaris_warehouse: str


async def provision_tenant_trino_service(
    group_name: str,
    *,
    user_manager,
    group_manager,
    polaris_group_manager: PolarisGroupManager,
    polaris_user_manager: PolarisUserManager,
    s3_credential_store: S3CredentialStore,
    polaris_credential_store: PolarisCredentialStore,
) -> TrinoServiceIdentity:
    """Provision the per-tenant Trino service identity end-to-end.

    Resource-idempotent and safe to re-run for recovery, but not credential
    stable: ``create_service_user`` and ``reset_credentials`` mint fresh
    secrets and overwrite the credential stores on every call. Use
    :func:`ensure_tenant_trino_service` for cache-first reconciliation that
    avoids needless rotation.

    The orchestration mirrors the existing route-layer pattern for human
    users (see ``routes/tenants.py::add_member`` and
    ``routes/management.py::create_group``): IAM-side first, then Polaris
    mirrors the IAM membership, then both credential stores get refreshed.

    Args:
        group_name: The base tenant group name (no ``ro`` suffix), e.g.
            ``"globalusers"``.
        user_manager: ``UserManager`` from either ``minio.managers`` or
            ``s3.managers`` — must implement
            ``create_service_user(username) -> UserModel``.
        group_manager: ``GroupManager`` from either backend — must implement
            ``add_user_to_group(username, group)``.
        polaris_group_manager: Existing :class:`PolarisGroupManager`. Reused
            verbatim from the human-user flow.
        polaris_user_manager: Existing :class:`PolarisUserManager`. Used only
            to call :meth:`reset_credentials` after the principal is created.
        s3_credential_store: Where the IAM access keys are persisted for the
            reconciler to read later.
        polaris_credential_store: Where the Polaris ``client_id``/
            ``client_secret`` are persisted.

    Returns:
        :class:`TrinoServiceIdentity` with everything the reconciler needs to
        issue ``CREATE CATALOG`` for this tenant.

    Raises:
        PolarisOperationError: If Polaris does not return client credentials
            after the reset (matches existing
            ``credentials.polaris_service`` behavior).
    """
    group_name = validate_trino_tenant_name(group_name)
    svc_user = service_user_name(group_name)
    ro_group = f"{group_name}ro"
    warehouse = tenant_warehouse_name(group_name)

    # IAM side — minimal user, then mirror the human-user "add to RO group"
    # pattern. The {group}ro group's GROUP_HOME_RO policy is the read-only
    # tenant scope; the service user inherits it via group membership.
    user_model = await user_manager.create_service_user(svc_user)
    await group_manager.add_user_to_group(svc_user, ro_group)
    await s3_credential_store.store_credentials(
        username=svc_user,
        access_key=user_model.s3_access_key,
        secret_key=user_model.s3_secret_key,
    )

    # Polaris side — same call the human-user route makes. Auto-creates the
    # Polaris principal trino-{group}-svc and grants {group}ro_member
    # (TABLE_READ_DATA, TABLE_LIST, NAMESPACE_LIST). No write privileges.
    await polaris_group_manager.add_user_to_group(svc_user, ro_group)

    # Capture the Polaris credential. Polaris only returns the client_secret
    # at creation/reset time, so we must reset+persist atomically (with the
    # same self-healing behavior as credentials.polaris_service: if the DB
    # write fails, the next provision call rotates again).
    creds = await polaris_user_manager.reset_credentials(svc_user)
    credential_data = creds.get("credentials", {})
    client_id = credential_data.get("clientId")
    client_secret = credential_data.get("clientSecret")
    if not client_id or not client_secret:
        raise PolarisOperationError(
            f"Polaris did not return client credentials for service identity "
            f"'{svc_user}'"
        )

    # The PolarisCredentialStore was designed for human users where
    # personal_catalog is the user's own catalog; for service identities
    # this field holds the tenant catalog the principal serves
    # (read-scoped). The store doesn't interpret the value — only the
    # human-user notebook UX does, and it never queries by service username.
    await polaris_credential_store.store_credentials(
        username=svc_user,
        client_id=client_id,
        client_secret=client_secret,
        personal_catalog=warehouse,
    )

    logger.info(
        "Provisioned Trino service identity for tenant %s (svc_user=%s, warehouse=%s)",
        group_name,
        svc_user,
        warehouse,
    )

    return TrinoServiceIdentity(
        tenant_alias=tenant_alias(group_name),
        iam_username=svc_user,
        s3_access_key=user_model.s3_access_key,
        s3_secret_key=user_model.s3_secret_key,
        polaris_principal=svc_user,
        polaris_client_id=client_id,
        polaris_client_secret=client_secret,
        polaris_warehouse=warehouse,
    )


async def ensure_tenant_trino_service(
    group_name: str,
    *,
    user_manager,
    group_manager,
    polaris_group_manager: PolarisGroupManager,
    polaris_user_manager: PolarisUserManager,
    s3_credential_store: S3CredentialStore,
    polaris_credential_store: PolarisCredentialStore,
) -> TrinoServiceIdentity:
    """Ensure the per-tenant Trino service identity exists without needless rotation.

    This is the backfill/recovery counterpart to
    :func:`provision_tenant_trino_service`. It repairs the IAM and Polaris
    reader bindings every time, but only rotates and persists credentials when
    the cached credentials are missing or the IAM service user itself is absent.
    That keeps routine Trino cold-start reconciliation from rotating every
    tenant credential.
    """
    group_name = validate_trino_tenant_name(group_name)
    svc_user = service_user_name(group_name)
    ro_group = f"{group_name}ro"
    warehouse = tenant_warehouse_name(group_name)

    cached_s3 = await s3_credential_store.get_credentials(svc_user)
    iam_user_exists = await user_manager.resource_exists(svc_user)
    if cached_s3 is None or not iam_user_exists:
        user_model = await user_manager.create_service_user(svc_user)
        s3_access_key = user_model.s3_access_key
        s3_secret_key = user_model.s3_secret_key
        await s3_credential_store.store_credentials(
            username=svc_user,
            access_key=s3_access_key,
            secret_key=s3_secret_key,
        )
    else:
        s3_access_key, s3_secret_key = cached_s3

    await group_manager.add_user_to_group(svc_user, ro_group)
    await polaris_group_manager.add_user_to_group(svc_user, ro_group)

    polaris_record = await polaris_credential_store.get_credentials(svc_user)
    if polaris_record is None or polaris_record.personal_catalog != warehouse:
        creds = await polaris_user_manager.reset_credentials(svc_user)
        credential_data = creds.get("credentials", {})
        client_id = credential_data.get("clientId")
        client_secret = credential_data.get("clientSecret")
        if not client_id or not client_secret:
            raise PolarisOperationError(
                f"Polaris did not return client credentials for service identity "
                f"'{svc_user}'"
            )
        await polaris_credential_store.store_credentials(
            username=svc_user,
            client_id=client_id,
            client_secret=client_secret,
            personal_catalog=warehouse,
        )
    else:
        client_id = polaris_record.client_id
        client_secret = polaris_record.client_secret

    logger.info(
        "Ensured Trino service identity for tenant %s (svc_user=%s, warehouse=%s)",
        group_name,
        svc_user,
        warehouse,
    )

    return TrinoServiceIdentity(
        tenant_alias=tenant_alias(group_name),
        iam_username=svc_user,
        s3_access_key=s3_access_key,
        s3_secret_key=s3_secret_key,
        polaris_principal=svc_user,
        polaris_client_id=client_id,
        polaris_client_secret=client_secret,
        polaris_warehouse=warehouse,
    )


async def deprovision_tenant_trino_service(
    group_name: str,
    *,
    user_manager,
    group_manager,
    polaris_group_manager: PolarisGroupManager,
    polaris_service: PolarisService,
    s3_credential_store: S3CredentialStore,
    polaris_credential_store: PolarisCredentialStore,
) -> None:
    """Tear down the per-tenant Trino service identity.

    Best-effort: each step logs and continues on failure so partial state can
    be cleaned up by re-running. Order is the inverse of provisioning, with
    Polaris artifacts removed before IAM artifacts so a leftover Polaris
    principal can never look up a now-deleted IAM user.

    User principals in Polaris are intentionally NOT deleted by
    ``drop_tenant_catalog`` (humans own their identity across tenant
    lifecycles). The service principal's lifecycle *is* the tenant's, so we
    delete it explicitly here rather than relying on
    ``drop_tenant_catalog`` to do it.

    Args:
        group_name: The base tenant group name (no ``ro`` suffix).
        polaris_service: Used directly for ``delete_principal`` because
            :class:`PolarisUserManager.delete_user` also tears down the
            personal catalog, which a service identity does not have.
    """
    group_name = validate_trino_tenant_name(group_name)
    svc_user = service_user_name(group_name)
    ro_group = f"{group_name}ro"

    # Polaris side: revoke the role binding, delete the principal, purge cred
    try:
        await polaris_group_manager.remove_user_from_group(svc_user, ro_group)
    except Exception as e:  # noqa: BLE001 — best-effort teardown
        logger.warning(
            "Failed to revoke Polaris role binding for service identity %s: %s; "
            "continuing teardown.",
            svc_user,
            e,
        )
    try:
        await polaris_service.delete_principal(svc_user)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "Failed to delete Polaris principal %s: %s; continuing teardown.",
            svc_user,
            e,
        )
    try:
        await polaris_credential_store.delete_credentials(svc_user)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "Failed to purge Polaris credential entry for %s: %s; continuing teardown.",
            svc_user,
            e,
        )

    # IAM side: remove from group, delete the user, purge cred. delete_user
    # via IAM also revokes outstanding access keys.
    try:
        await group_manager.remove_user_from_group(svc_user, ro_group)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "Failed to remove IAM service user %s from %s: %s; continuing teardown.",
            svc_user,
            ro_group,
            e,
        )
    try:
        await user_manager.delete_service_user(svc_user)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "Failed to delete IAM service user %s: %s; continuing teardown.",
            svc_user,
            e,
        )
    try:
        await s3_credential_store.delete_credentials(svc_user)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "Failed to purge S3 credential entry for %s: %s; continuing teardown.",
            svc_user,
            e,
        )

    logger.info(
        "Deprovisioned Trino service identity for tenant %s (svc_user=%s)",
        group_name,
        svc_user,
    )
