import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from polaris.constants import (
    ICEBERG_STORAGE_SUBDIRECTORY,
    normalize_group_name_for_polaris,
)
from polaris.namespace_acl_models import (
    EffectiveAccessGroupTenant,
    EffectiveAccessNamespaceGrant,
    EffectiveAccessNamespaceTenant,
    PolarisEffectiveAccessResponse,
)
from service import app_state
from service.dependencies import auth, require_admin
from service.kb_auth import AdminPermission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/polaris")


async def _ensure_polaris_user_resources(
    username: str,
    app_state_obj: app_state.AppState,
) -> tuple[str, list[str]]:
    """Ensure Polaris catalog/principal/roles exist and return tenant catalogs."""
    polaris = app_state_obj.polaris_service

    # Use SQL warehouse path with /iceberg/ subdirectory.
    # Iceberg uses Polaris for catalog-level isolation instead of governance prefixes.
    # The /iceberg/ path has its own IAM statement separate from the u_{username}__*
    # governed path, added by policy_creator._create_default_user_home_policy().
    user_config = app_state_obj.user_manager.config
    storage_location = f"s3a://{user_config.default_bucket}/{user_config.users_sql_warehouse_prefix}/{username}/{ICEBERG_STORAGE_SUBDIRECTORY}/"

    # All steps are idempotent — create_* methods return existing entities on 409,
    # and grant_* calls are wrapped in try/except to handle "already granted" (500).
    catalog_name = f"user_{username}"

    # 1. Create personal catalog
    await polaris.create_catalog(name=catalog_name, storage_location=storage_location)

    # 2. Create principal
    await polaris.create_principal(name=username)

    # 3. Create catalog_admin role in the personal catalog
    catalog_role = "catalog_admin"
    await polaris.create_catalog_role(catalog=catalog_name, role_name=catalog_role)

    # 4. Grant CATALOG_MANAGE_CONTENT on the catalog to the catalog role
    await polaris.grant_catalog_privilege(
        catalog=catalog_name,
        role_name=catalog_role,
        privilege="CATALOG_MANAGE_CONTENT",
    )

    # 5. Create a principal role for the user
    principal_role = f"{username}_role"
    await polaris.create_principal_role(role_name=principal_role)

    # 6. Assign the catalog role to the principal role
    await polaris.grant_catalog_role_to_principal_role(
        catalog=catalog_name,
        catalog_role=catalog_role,
        principal_role=principal_role,
    )

    # 7. Assign the principal role to the principal
    await polaris.grant_principal_role_to_principal(
        principal=username, principal_role=principal_role
    )

    # Check for group memberships to determine tenant catalogs and grant access.
    # This must happen AFTER the principal is created above, because
    # grant_principal_role_to_principal requires the principal to exist.
    user_groups = await app_state_obj.group_manager.get_user_groups(username)
    group_config = app_state_obj.user_manager.config
    tenant_catalogs = []
    for g in user_groups:
        base_group, is_ro = normalize_group_name_for_polaris(g)
        tenant_catalogs.append(f"tenant_{base_group}")

        # Ensure the tenant catalog and roles exist (idempotent).
        # This handles groups that were created before Polaris was integrated.
        storage = f"s3a://{group_config.default_bucket}/{group_config.tenant_sql_warehouse_prefix}/{base_group}/{ICEBERG_STORAGE_SUBDIRECTORY}/"
        await polaris.ensure_tenant_catalog(base_group, storage)

        # Grant the appropriate principal role for this group
        principal_role = f"{base_group}ro_member" if is_ro else f"{base_group}_member"
        await polaris.grant_principal_role_to_principal(username, principal_role)

    namespace_sync = await app_state_obj.namespace_acl_manager.reconcile_user(username)
    if not namespace_sync.success:
        logger.warning(
            "Namespace ACL reconciliation for %s had %s failures during provisioning",
            username,
            len(namespace_sync.failed_grants),
        )
    namespace_grants = await app_state_obj.namespace_acl_manager.list_grants_for_user(
        username
    )
    tenant_catalogs.extend(
        f"tenant_{grant.tenant_name}"
        for grant in namespace_grants
        if grant.status == "active"
    )

    # Remove duplicates but preserve order
    return catalog_name, list(dict.fromkeys(tenant_catalogs))


def _authorize_polaris_provision(username: str, authenticated_user: Any) -> None:
    """Authorize self-provisioning or full admin provisioning."""
    if (
        authenticated_user.user != username
        and authenticated_user.admin_perm != AdminPermission.FULL
    ):
        raise HTTPException(
            status_code=403,
            detail="You can only provision your own Polaris catalog",
        )


@router.post("/user_provision/{username}", response_model=Dict[str, Any])
async def provision_polaris_user(
    username: str,
    app_state_obj: app_state.AppState = Depends(app_state.get_app_state),
    authenticated_user=Depends(auth),  # Any authenticated user
):
    """
    Provision a user's Polaris environment and return fresh credentials.

    This is the single entry point for Polaris user setup. It is fully idempotent:
    all create operations silently succeed if the resource already exists, and
    credentials are cached in PostgreSQL so repeated calls return the same
    principal credential until explicit rotation.

    Steps performed:
    1. Create personal Iceberg catalog (``user_{username}``)
    2. Create Polaris principal for the user
    3. Create ``catalog_admin`` catalog role with ``CATALOG_MANAGE_CONTENT`` privilege
    4. Create ``{username}_role`` principal role and wire it to the catalog role
    5. Return cached credentials, creating them once on cache miss
    6. Discover tenant catalog access from group memberships

    Authorization:
    - Authenticated users can provision themselves.
    - Admins (``AdminPermission.FULL``) can provision any user.

    Returns:
        ``client_id``, ``client_secret``, ``personal_catalog``, ``tenant_catalogs``
    """
    # Self-provisioning: users can only provision their own catalog
    _authorize_polaris_provision(username, authenticated_user)

    try:
        catalog_name, tenant_catalogs = await _ensure_polaris_user_resources(
            username, app_state_obj
        )
        creds = await app_state_obj.polaris_credential_service.get_or_create(
            username=username,
            personal_catalog=catalog_name,
        )

    except Exception:
        logger.exception(f"Failed to provision Polaris environment for {username}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to provision Polaris environment for {username}",
        )

    return {
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "personal_catalog": catalog_name,
        "tenant_catalogs": tenant_catalogs,
    }


@router.post("/credentials/rotate/{username}", response_model=Dict[str, Any])
async def rotate_polaris_credentials(
    username: str,
    app_state_obj: app_state.AppState = Depends(app_state.get_app_state),
    authenticated_user=Depends(auth),
):
    """
    Explicitly rotate a user's Polaris credentials.

    Normal provisioning is stable and cache-first. This endpoint intentionally
    invalidates existing long-lived Spark Connect and Trino catalog configs, so
    those engines must be restarted or recreated after rotation.
    """
    _authorize_polaris_provision(username, authenticated_user)

    try:
        catalog_name, tenant_catalogs = await _ensure_polaris_user_resources(
            username, app_state_obj
        )
        creds = await app_state_obj.polaris_credential_service.rotate(
            username=username,
            personal_catalog=catalog_name,
        )
    except Exception:
        logger.exception("Failed to rotate Polaris credentials for %s", username)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to rotate Polaris credentials for {username}",
        )

    return {
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "personal_catalog": catalog_name,
        "tenant_catalogs": tenant_catalogs,
    }


@router.get(
    "/effective-access/me",
    response_model=PolarisEffectiveAccessResponse,
)
async def get_my_effective_access(
    app_state_obj: app_state.AppState = Depends(app_state.get_app_state),
    authenticated_user=Depends(auth),
):
    """Return the authenticated user's effective Polaris access."""
    return await _effective_access_response(authenticated_user.user, app_state_obj)


@router.get(
    "/effective-access/{username}",
    response_model=PolarisEffectiveAccessResponse,
)
async def get_effective_access_for_user(
    username: str,
    app_state_obj: app_state.AppState = Depends(app_state.get_app_state),
    _authenticated_user=Depends(require_admin),
):
    """Return a user's effective Polaris access. Requires admin."""
    return await _effective_access_response(username, app_state_obj)


async def _effective_access_response(
    username: str,
    app_state_obj: app_state.AppState,
) -> PolarisEffectiveAccessResponse:
    tenant_access: dict[str, str] = {}
    for group_name in await app_state_obj.group_manager.get_user_groups(username):
        tenant_name, is_ro = normalize_group_name_for_polaris(group_name)
        if not tenant_name:
            continue
        access_level = "read_only" if is_ro else "read_write"
        if tenant_access.get(tenant_name) == "read_write":
            continue
        tenant_access[tenant_name] = access_level

    group_tenants = [
        EffectiveAccessGroupTenant(
            tenant_name=tenant_name,
            catalog_name=f"tenant_{tenant_name}",
            access_level=access_level,
        )
        for tenant_name, access_level in sorted(tenant_access.items())
    ]

    namespace_grants_by_tenant: dict[str, list[EffectiveAccessNamespaceGrant]] = {}
    catalog_by_tenant: dict[str, str] = {}
    grants = await app_state_obj.namespace_acl_manager.list_grants_for_user(username)
    for grant in grants:
        if grant.status != "active":
            continue
        catalog_by_tenant[grant.tenant_name] = grant.catalog_name
        namespace_grants_by_tenant.setdefault(grant.tenant_name, []).append(
            EffectiveAccessNamespaceGrant(
                grant_id=grant.id,
                namespace=list(grant.namespace_parts),
                namespace_name=grant.namespace_name,
                access_level=grant.access_level,
            )
        )

    namespace_acl_tenants = [
        EffectiveAccessNamespaceTenant(
            tenant_name=tenant_name,
            catalog_name=catalog_by_tenant[tenant_name],
            namespaces=sorted(
                namespace_grants,
                key=lambda grant: (grant.namespace_name, grant.access_level),
            ),
        )
        for tenant_name, namespace_grants in sorted(namespace_grants_by_tenant.items())
    ]

    return PolarisEffectiveAccessResponse(
        username=username,
        personal_catalog=f"user_{username}",
        group_tenants=group_tenants,
        namespace_acl_tenants=namespace_acl_tenants,
    )
