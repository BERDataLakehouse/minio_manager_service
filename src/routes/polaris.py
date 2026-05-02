"""Polaris provisioning and effective-access HTTP routes.

These routes are not yet mounted in :mod:`main`. ``AppState`` will gain
``polaris_service`` / ``polaris_credential_service`` fields in a follow-up
PR, at which point this router can be wired into the FastAPI app.
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from polaris.constants import (
    ICEBERG_STORAGE_SUBDIRECTORY,
    PERSONAL_CATALOG_ADMIN_ROLE,
    normalize_group_name_for_polaris,
    personal_catalog_name,
    personal_principal_role,
    tenant_catalog_name,
    tenant_reader_principal_role,
    tenant_writer_principal_role,
)
from service import app_state
from service.dependencies import auth, require_admin
from service.kb_auth import AdminPermission, KBaseUser

router = APIRouter(prefix="/polaris")


# ===== RESPONSE MODELS =====


class PolarisCredentialsResponse(BaseModel):
    """Polaris OAuth client credentials and the user's catalog access list."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    client_id: Annotated[
        str, Field(description="Polaris OAuth client ID", min_length=1)
    ]
    client_secret: Annotated[
        str, Field(description="Polaris OAuth client secret", min_length=1)
    ]
    personal_catalog: Annotated[
        str, Field(description="The user's personal Iceberg catalog name")
    ]
    tenant_catalogs: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Tenant catalogs the user has access to via group membership. "
                "Each tenant appears at most once."
            ),
        ),
    ]


class EffectiveAccessGroupTenant(BaseModel):
    """Tenant catalog access inherited from MinIO tenant membership."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    tenant_name: str
    catalog_name: str
    access_level: Literal["read_only", "read_write"]


class PolarisEffectiveAccessResponse(BaseModel):
    """Effective Polaris access for one user."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: str
    personal_catalog: str
    group_tenants: list[EffectiveAccessGroupTenant]


# ===== HELPERS =====


def _authorize_polaris_provision(username: str, authenticated_user: KBaseUser) -> None:
    """Authorize self-provisioning or full-admin provisioning."""
    if (
        authenticated_user.user != username
        and authenticated_user.admin_perm != AdminPermission.FULL
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only provision your own Polaris catalog",
        )


def _dedup_groups_preferring_write(
    user_groups: list[str],
) -> dict[str, bool]:
    """Collapse a user's group membership to one entry per base tenant.

    When a user is in both the read-write (``teamA``) and read-only
    (``teamAro``) variants of the same tenant we only need to bind the
    higher-privilege role once. Empty base names (groups normalising to
    ``""``) are dropped defensively.

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


async def _ensure_polaris_user_resources(
    username: str,
    app_state_obj: app_state.AppState,
) -> tuple[str, list[str]]:
    """Ensure Polaris catalog/principal/roles exist and return tenant catalogs.

    All operations are idempotent: ``create_*`` methods on
    :class:`PolarisService` swallow 409 (already exists), and
    ``grant_*`` calls perform a check-first to avoid duplicate-binding errors.

    Returns:
        ``(personal_catalog_name, tenant_catalog_names)`` — the tenant list is
        deduplicated and order-preserving.
    """
    polaris = app_state_obj.polaris_service

    # Personal catalog uses SQL warehouse path with /iceberg/ subdirectory.
    # Iceberg uses Polaris for catalog-level isolation instead of governance prefixes.
    # The /iceberg/ path has its own IAM statement separate from the u_{username}__*
    # governed path, added by policy_creator._create_default_user_home_policy().
    catalog_name = personal_catalog_name(username)
    storage_location = (
        f"{app_state_obj.users_sql_warehouse_base}/{username}/"
        f"{ICEBERG_STORAGE_SUBDIRECTORY}/"
    )

    # 1. Create personal catalog
    await polaris.create_catalog(name=catalog_name, storage_location=storage_location)

    # 2. Create principal
    await polaris.create_principal(name=username)

    # 3. Create catalog_admin role in the personal catalog
    await polaris.create_catalog_role(
        catalog=catalog_name, role_name=PERSONAL_CATALOG_ADMIN_ROLE
    )

    # 4. Grant CATALOG_MANAGE_CONTENT on the catalog to the catalog role
    await polaris.grant_catalog_privilege(
        catalog=catalog_name,
        role_name=PERSONAL_CATALOG_ADMIN_ROLE,
        privilege="CATALOG_MANAGE_CONTENT",
    )

    # 5. Create a principal role for the user
    user_principal_role = personal_principal_role(username)
    await polaris.create_principal_role(role_name=user_principal_role)

    # 6. Assign the catalog role to the principal role
    await polaris.grant_catalog_role_to_principal_role(
        catalog=catalog_name,
        catalog_role=PERSONAL_CATALOG_ADMIN_ROLE,
        principal_role=user_principal_role,
    )

    # 7. Assign the principal role to the principal
    await polaris.grant_principal_role_to_principal(
        principal=username, principal_role=user_principal_role
    )

    # 8. Discover group memberships and grant tenant access. Must run AFTER the
    # principal is created above because grant_principal_role_to_principal
    # requires the principal to exist.
    user_groups = await app_state_obj.group_manager.get_user_groups(username)
    deduped = _dedup_groups_preferring_write(user_groups)

    tenant_catalogs: list[str] = []
    for base_group, is_ro in deduped.items():
        tenant_catalog = tenant_catalog_name(base_group)
        tenant_catalogs.append(tenant_catalog)

        # Ensure the tenant catalog and roles exist (idempotent). This handles
        # groups that were created before Polaris was integrated.
        tenant_storage_location = (
            f"{app_state_obj.tenant_sql_warehouse_base}/{base_group}/"
            f"{ICEBERG_STORAGE_SUBDIRECTORY}/"
        )
        await polaris.ensure_tenant_catalog(base_group, tenant_storage_location)

        # Grant the appropriate principal role for this group
        tenant_principal_role = (
            tenant_reader_principal_role(base_group)
            if is_ro
            else tenant_writer_principal_role(base_group)
        )
        await polaris.grant_principal_role_to_principal(username, tenant_principal_role)

    return catalog_name, tenant_catalogs


# ===== PROVISIONING ROUTES =====


@router.post("/user_provision/{username}", response_model=PolarisCredentialsResponse)
async def provision_polaris_user(
    username: str,
    app_state_obj: Annotated[app_state.AppState, Depends(app_state.get_app_state)],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
) -> PolarisCredentialsResponse:
    """
    Provision a user's Polaris environment and return cached credentials.

    Single entry point for Polaris user setup. Fully idempotent: all create
    operations silently succeed if the resource already exists, and
    credentials are cached in PostgreSQL so repeated calls return the same
    principal credential until explicit rotation.

    Steps performed (in order):
      1. Create personal Iceberg catalog (``user_{username}``)
      2. Create Polaris principal for the user
      3. Create ``catalog_admin`` catalog role with ``CATALOG_MANAGE_CONTENT``
      4. Create ``{username}_role`` principal role and wire it to the catalog role
      5. Discover tenant catalog access from group memberships and bind
         the appropriate writer/reader principal roles
      6. Return cached credentials, creating them once on cache miss

    Authorization:
      - Authenticated users can provision themselves.
      - Admins (``AdminPermission.FULL``) can provision any user.
    """
    _authorize_polaris_provision(username, authenticated_user)

    catalog_name, tenant_catalogs = await _ensure_polaris_user_resources(
        username, app_state_obj
    )
    creds = await app_state_obj.polaris_credential_service.get_or_create(
        username=username,
        personal_catalog=catalog_name,
    )

    return PolarisCredentialsResponse(
        client_id=creds.client_id,
        client_secret=creds.client_secret,
        personal_catalog=catalog_name,
        tenant_catalogs=tenant_catalogs,
    )


@router.post(
    "/credentials/rotate/{username}", response_model=PolarisCredentialsResponse
)
async def rotate_polaris_credentials(
    username: str,
    app_state_obj: Annotated[app_state.AppState, Depends(app_state.get_app_state)],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
) -> PolarisCredentialsResponse:
    """
    Explicitly rotate a user's Polaris credentials.

    Normal provisioning is stable and cache-first. This endpoint intentionally
    invalidates existing long-lived Spark Connect and Trino catalog configs, so
    those engines must be restarted or recreated after rotation.
    """
    _authorize_polaris_provision(username, authenticated_user)

    catalog_name, tenant_catalogs = await _ensure_polaris_user_resources(
        username, app_state_obj
    )
    creds = await app_state_obj.polaris_credential_service.rotate(
        username=username,
        personal_catalog=catalog_name,
    )

    return PolarisCredentialsResponse(
        client_id=creds.client_id,
        client_secret=creds.client_secret,
        personal_catalog=catalog_name,
        tenant_catalogs=tenant_catalogs,
    )


# ===== EFFECTIVE-ACCESS ROUTES =====


@router.get("/effective-access/me", response_model=PolarisEffectiveAccessResponse)
async def get_my_effective_access(
    app_state_obj: Annotated[app_state.AppState, Depends(app_state.get_app_state)],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
) -> PolarisEffectiveAccessResponse:
    """Return the authenticated user's effective Polaris access."""
    return await _effective_access_response(authenticated_user.user, app_state_obj)


@router.get(
    "/effective-access/{username}", response_model=PolarisEffectiveAccessResponse
)
async def get_effective_access_for_user(
    username: str,
    app_state_obj: Annotated[app_state.AppState, Depends(app_state.get_app_state)],
    _authenticated_user: Annotated[KBaseUser, Depends(require_admin)],
) -> PolarisEffectiveAccessResponse:
    """Return a user's effective Polaris access. Requires admin."""
    return await _effective_access_response(username, app_state_obj)


async def _effective_access_response(
    username: str,
    app_state_obj: app_state.AppState,
) -> PolarisEffectiveAccessResponse:
    user_groups = await app_state_obj.group_manager.get_user_groups(username)
    deduped = _dedup_groups_preferring_write(user_groups)

    group_tenants = [
        EffectiveAccessGroupTenant(
            tenant_name=base_group,
            catalog_name=tenant_catalog_name(base_group),
            access_level="read_only" if is_ro else "read_write",
        )
        for base_group, is_ro in sorted(deduped.items())
    ]

    return PolarisEffectiveAccessResponse(
        username=username,
        personal_catalog=personal_catalog_name(username),
        group_tenants=group_tenants,
    )
