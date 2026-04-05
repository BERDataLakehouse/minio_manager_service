"""Tenant metadata, steward management, and member operations.

All endpoints are under the ``/tenants`` prefix.
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Path, Query, Request, status
from fastapi.security.utils import get_authorization_scheme_param

from s3.models.tenant import (
    TenantDetailResponse,
    TenantMemberResponse,
    TenantMetadataResponse,
    TenantMetadataUpdate,
    TenantStewardResponse,
    TenantSummaryResponse,
)
from service.app_state import get_app_state
from service.dependencies import auth, require_admin, require_steward_or_admin
from service.kb_auth import KBaseUser

router = APIRouter(prefix="/tenants", tags=["tenants"])


def _extract_token(request: Request) -> str:
    """Extract the bearer token from the Authorization header (case-insensitive)."""
    header = request.headers.get("Authorization", "")
    _, credentials = get_authorization_scheme_param(header)
    return credentials


# ── Tenant listing ───────────────────────────────────────────────────────


@router.get(
    "",
    response_model=list[TenantSummaryResponse],
    summary="List tenants",
    description="List all tenants with summary info. Any authenticated user can call this.",
)
async def list_tenants(
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    app_state = get_app_state(request)
    token = _extract_token(request)
    return await app_state.tenant_manager.list_tenants(authenticated_user.user, token)


# ── Tenant detail ────────────────────────────────────────────────────────


@router.get(
    "/{tenant_name}",
    response_model=TenantDetailResponse,
    summary="Get tenant detail",
    description=(
        "Get full tenant detail including metadata, member list with profiles "
        "(display name, email, access level), steward list, and storage paths. "
        "Visible to any authenticated user."
    ),
)
async def get_tenant_detail(
    tenant_name: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    app_state = get_app_state(request)
    token = _extract_token(request)
    return await app_state.tenant_manager.get_tenant_detail(tenant_name, token)


# ── Update tenant metadata ──────────────────────────────────────────────


@router.patch(
    "/{tenant_name}",
    response_model=TenantMetadataResponse,
    summary="Update tenant metadata",
    description="Update display name, description, or organization. Requires steward or admin.",
)
async def update_tenant_metadata(
    tenant_name: Annotated[str, Path(min_length=1)],
    body: TenantMetadataUpdate,
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    await require_steward_or_admin(tenant_name, request, authenticated_user)
    app_state = get_app_state(request)
    return await app_state.tenant_manager.update_metadata(
        tenant_name, body, authenticated_user.user
    )


# ── Tenant members ──────────────────────────────────────────────────────


@router.get(
    "/{tenant_name}/members",
    response_model=list[TenantMemberResponse],
    summary="List tenant members",
    description="List members with profiles. Requires member, steward, or admin.",
)
async def get_tenant_members(
    tenant_name: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    app_state = get_app_state(request)
    token = _extract_token(request)
    return await app_state.tenant_manager.get_tenant_members(
        tenant_name, authenticated_user, token
    )


@router.post(
    "/{tenant_name}/members/{username}",
    response_model=TenantMemberResponse,
    status_code=status.HTTP_200_OK,
    summary="Add tenant member",
    description="Add a user to the tenant. Requires steward or admin.",
)
async def add_tenant_member(
    tenant_name: Annotated[str, Path(min_length=1)],
    username: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    permission: Annotated[
        Literal["read_write", "read_only"],
        Query(description="Permission level for the new member"),
    ] = "read_write",
):
    await require_steward_or_admin(tenant_name, request, authenticated_user)
    app_state = get_app_state(request)
    token = _extract_token(request)
    return await app_state.tenant_manager.add_member(
        tenant_name, username, permission, token
    )


@router.delete(
    "/{tenant_name}/members/{username}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove tenant member",
    description="Remove a user from the tenant. Requires steward or admin.",
)
async def remove_tenant_member(
    tenant_name: Annotated[str, Path(min_length=1)],
    username: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    await require_steward_or_admin(tenant_name, request, authenticated_user)
    app_state = get_app_state(request)
    await app_state.tenant_manager.remove_member(
        tenant_name, username, authenticated_user
    )


# ── Steward management ──────────────────────────────────────────────────


@router.get(
    "/{tenant_name}/stewards",
    response_model=list[TenantStewardResponse],
    summary="List stewards",
    description="List stewards for a tenant. Requires member, steward, or admin.",
)
async def get_tenant_stewards(
    tenant_name: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    app_state = get_app_state(request)
    token = _extract_token(request)
    return await app_state.tenant_manager.get_stewards(
        tenant_name, authenticated_user, token
    )


@router.post(
    "/{tenant_name}/stewards/{username}",
    response_model=TenantStewardResponse,
    status_code=status.HTTP_200_OK,
    summary="Assign steward",
    description="Assign a user as steward. Admin only. Automatically adds the user to the RW group if not already a member.",
)
async def assign_steward(
    tenant_name: Annotated[str, Path(min_length=1)],
    username: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(require_admin)],
):
    app_state = get_app_state(request)
    token = _extract_token(request)
    return await app_state.tenant_manager.add_steward(
        tenant_name, username, authenticated_user.user, token
    )


@router.delete(
    "/{tenant_name}/stewards/{username}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove steward",
    description="Remove steward assignment. Admin only. Does not remove from tenant.",
)
async def remove_steward(
    tenant_name: Annotated[str, Path(min_length=1)],
    username: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(require_admin)],
):
    app_state = get_app_state(request)
    await app_state.tenant_manager.remove_steward(tenant_name, username)


# ── Tenant lifecycle (admin only) ────────────────────────────────────────


@router.post(
    "/{tenant_name}",
    response_model=TenantMetadataResponse,
    status_code=status.HTTP_200_OK,
    summary="Create tenant metadata",
    description="Create metadata for a tenant (idempotent). Admin only. Returns existing if already created.",
)
async def create_tenant(
    tenant_name: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(require_admin)],
    body: TenantMetadataUpdate | None = None,
):
    app_state = get_app_state(request)
    return await app_state.tenant_manager.create_metadata(
        tenant_name, authenticated_user.user, body
    )


@router.delete(
    "/{tenant_name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete tenant metadata",
    description="Delete metadata and steward assignments. Admin only. Does not delete MinIO group.",
)
async def delete_tenant(
    tenant_name: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(require_admin)],
):
    app_state = get_app_state(request)
    await app_state.tenant_manager.delete_metadata(tenant_name)
