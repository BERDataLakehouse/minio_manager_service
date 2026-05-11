"""Polaris provisioning and effective-access HTTP routes.

Mounted at ``/polaris`` from :mod:`main`. Provides explicit self-service
provisioning (``POST /polaris/user_provision/{username}``) and credential
rotation (``POST /polaris/credentials/rotate/{username}``), plus
effective-access discovery (``GET /polaris/effective-access/{me,username}``).

Day-to-day callers should prefer the unified ``/credentials/`` and
``/credentials/rotate`` endpoints, which also return the S3 IAM half.
These Polaris-only endpoints are mostly used by tooling that needs the
``tenant_catalogs`` list in the response (which the unified endpoints
omit) and by admins explicitly rotating Polaris credentials for another
user.
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import BaseModel, ConfigDict, Field

from polaris.constants import (
    dedup_groups_preferring_write,
    personal_catalog_name,
    tenant_catalog_name,
)
from polaris.orchestration import ensure_user_polaris_state
from s3.models.tenant import TenantSummaryResponse
from service import app_state
from service.dependencies import auth, require_admin
from service.kb_auth import AdminPermission, KBaseUser
from trino_integration.service_identity import ensure_tenant_trino_service

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


def _extract_token(request: Request) -> str:
    """Extract the bearer token from the Authorization header."""
    header = request.headers.get("Authorization", "")
    _, credentials = get_authorization_scheme_param(header)
    return credentials


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

    catalog_name, tenant_catalogs = await ensure_user_polaris_state(
        username,
        polaris_user_manager=app_state_obj.polaris_user_manager,
        polaris_group_manager=app_state_obj.polaris_group_manager,
        group_manager=app_state_obj.group_manager,
    )
    # PolarisCredentialService self-bootstraps the principal so
    # ensure_user_polaris_state's create_user call is redundant on this
    # path — kept above because we also need the tenant_catalogs list for
    # the response, which the credential service doesn't compute.
    creds = await app_state_obj.polaris_credential_service.get_or_create(username)

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

    catalog_name, tenant_catalogs = await ensure_user_polaris_state(
        username,
        polaris_user_manager=app_state_obj.polaris_user_manager,
        polaris_group_manager=app_state_obj.polaris_group_manager,
        group_manager=app_state_obj.group_manager,
    )
    creds = await app_state_obj.polaris_credential_service.rotate(username)

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


class ReconcileTrinoCatalogResponse(BaseModel):
    """Result of force-reconciling a single tenant's Trino catalog."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    tenant_name: str
    tenant_alias: str


@router.get(
    "/management/tenants",
    response_model=list[TenantSummaryResponse],
    summary="List tenants for Polaris management",
    description=(
        "Admin tenant listing used by one-shot Polaris/Trino maintenance tooling. "
        "Returns the same tenant summary shape as ``GET /tenants``."
    ),
)
async def list_management_tenants(
    request: Request,
    app_state_obj: Annotated[app_state.AppState, Depends(app_state.get_app_state)],
    authenticated_user: Annotated[KBaseUser, Depends(require_admin)],
) -> list[TenantSummaryResponse]:
    """List tenants with metadata for admin maintenance scripts."""
    return await app_state_obj.tenant_manager.list_tenants(
        authenticated_user.user, _extract_token(request)
    )


@router.post(
    "/management/tenants/{tenant_name}/reconcile-trino",
    response_model=ReconcileTrinoCatalogResponse,
    status_code=status.HTTP_200_OK,
    summary="Force-reconcile a single tenant Trino catalog",
    description=(
        "Ensure the service identity for ``tenant_name``, then drop and recreate "
        "the Trino catalog from the credentials persisted in MMS. Idempotent. "
        "Use cases:\n"
        "- after rotating the per-tenant service principal credential\n"
        "- recovery after a partial-failure during regular tenant create\n"
        "- ad-hoc admin force-recreate.\n"
        "For bulk reconcile across all tenants use "
        "``POST /management/migrate/reconcile-trino-catalogs``."
    ),
)
async def reconcile_tenant_trino_catalog(
    tenant_name: str,
    app_state_obj: Annotated[app_state.AppState, Depends(app_state.get_app_state)],
    _authenticated_user: Annotated[KBaseUser, Depends(require_admin)],
) -> ReconcileTrinoCatalogResponse:
    """Force-reconcile one tenant's Trino catalog. Admin only."""
    await ensure_tenant_trino_service(
        group_name=tenant_name,
        user_manager=app_state_obj.user_manager,
        group_manager=app_state_obj.group_manager,
        polaris_group_manager=app_state_obj.polaris_group_manager,
        polaris_user_manager=app_state_obj.polaris_user_manager,
        s3_credential_store=app_state_obj.s3_credential_store,
        polaris_credential_store=app_state_obj.polaris_credential_store,
    )
    alias = await app_state_obj.trino_catalog_reconciler.reconcile_tenant(tenant_name)
    return ReconcileTrinoCatalogResponse(
        tenant_name=tenant_name,
        tenant_alias=alias,
    )


async def _effective_access_response(
    username: str,
    app_state_obj: app_state.AppState,
) -> PolarisEffectiveAccessResponse:
    user_groups = await app_state_obj.group_manager.get_user_groups(username)
    deduped = dedup_groups_preferring_write(user_groups)

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
