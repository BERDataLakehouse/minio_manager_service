"""Routes for Polaris namespace ACL grant management."""

import logging
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)

from polaris.namespace_acl_manager import (
    NamespaceAclNamespaceNotFoundError,
    NamespaceAclValidationError,
)
from polaris.namespace_acl_models import (
    NamespaceAclGrantRequest,
    NamespaceAclGrantResponse,
    NamespaceAclRevokeRequest,
    NamespaceAclSyncResponse,
)
from service.app_state import get_app_state
from service.dependencies import auth, require_admin, require_steward_or_admin
from service.kb_auth import KBaseUser
from s3.utils.validators import validate_group_name

logger = logging.getLogger(__name__)

router = APIRouter(tags=["namespace-acls"])


@router.post(
    "/tenants/{tenant_name}/namespace-acls",
    response_model=NamespaceAclGrantResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_200_OK: {
            "model": NamespaceAclGrantResponse,
            "description": "Existing active grant returned for an idempotent request.",
        },
    },
    summary="Grant namespace access",
    description="Grant read or write access to an existing namespace in a tenant catalog.",
)
async def grant_namespace_acl(
    tenant_name: Annotated[str, Path(min_length=1)],
    body: NamespaceAclGrantRequest,
    request: Request,
    response: Response,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    """Grant namespace access to a user."""
    await require_steward_or_admin(tenant_name, request, authenticated_user)
    app_state = get_app_state(request)
    tenant_name = await _require_tenant_exists(app_state, tenant_name)
    await _ensure_minio_user(app_state, body.username)

    shadowed = await _is_shadowed_by_tenant_membership(
        app_state,
        tenant_name,
        body.username,
        body.access_level,
    )
    try:
        result = await app_state.namespace_acl_manager.grant_namespace_access(
            tenant_name=tenant_name,
            namespace_parts=body.namespace,
            username=body.username,
            access_level=body.access_level,
            actor=authenticated_user.user,
            shadowed=shadowed,
        )
    except NamespaceAclNamespaceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except NamespaceAclValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        ) from e
    if result.grant is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Grant was recorded but could not be loaded",
        )
    if not result.sync_result.success:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "grant_id": result.grant.id,
                "status": result.grant.status,
                "failures": [
                    {"grant_id": failure.grant_id, "message": failure.message}
                    for failure in result.sync_result.failed_grants
                ],
            },
        )
    if not result.created:
        response.status_code = status.HTTP_200_OK
    return NamespaceAclGrantResponse.from_record(result.grant)


@router.get(
    "/tenants/{tenant_name}/namespace-acls",
    response_model=list[NamespaceAclGrantResponse],
    summary="List namespace grants for a tenant",
    description="List namespace ACL grants. Requires tenant steward or admin.",
)
async def list_namespace_acls(
    tenant_name: Annotated[str, Path(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    namespace: Annotated[
        str | None,
        Query(description="Optional dotted namespace filter"),
    ] = None,
):
    """List namespace ACL grants for a tenant."""
    await require_steward_or_admin(tenant_name, request, authenticated_user)
    app_state = get_app_state(request)
    tenant_name = await _require_tenant_exists(app_state, tenant_name)
    namespace_parts = namespace.split(".") if namespace else None
    grants = await app_state.namespace_acl_manager.list_grants_for_tenant(
        tenant_name,
        namespace_parts,
    )
    return [NamespaceAclGrantResponse.from_record(grant) for grant in grants]


@router.delete(
    "/tenants/{tenant_name}/namespace-acls",
    response_model=NamespaceAclGrantResponse,
    summary="Revoke namespace access",
    description="Revoke the current grant for a user and namespace.",
)
async def revoke_namespace_acl(
    tenant_name: Annotated[str, Path(min_length=1)],
    body: NamespaceAclRevokeRequest,
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    """Revoke namespace access from a user."""
    await require_steward_or_admin(tenant_name, request, authenticated_user)
    app_state = get_app_state(request)
    tenant_name = await _require_tenant_exists(app_state, tenant_name)
    result = await app_state.namespace_acl_manager.revoke_namespace_access(
        tenant_name=tenant_name,
        namespace_parts=body.namespace,
        username=body.username,
        actor=authenticated_user.user,
    )
    if result is None or result.grant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active namespace ACL grant found",
        )
    if not result.sync_result.success:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "grant_id": result.grant.id,
                "status": result.grant.status,
                "failures": [
                    {"grant_id": failure.grant_id, "message": failure.message}
                    for failure in result.sync_result.failed_grants
                ],
            },
        )
    return NamespaceAclGrantResponse.from_record(result.grant)


@router.get(
    "/me/namespace-acls",
    response_model=list[NamespaceAclGrantResponse],
    summary="List my namespace grants",
    description="List namespace ACL grants for the authenticated user.",
)
async def list_my_namespace_acls(
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    """List namespace ACL grants for the authenticated user."""
    app_state = get_app_state(request)
    grants = await app_state.namespace_acl_manager.list_grants_for_user(
        authenticated_user.user
    )
    return [NamespaceAclGrantResponse.from_record(grant) for grant in grants]


@router.post(
    "/management/migrate/sync-namespace-acls",
    response_model=NamespaceAclSyncResponse,
    summary="Reconcile namespace ACLs for a user",
    description="Admin drift-repair endpoint for Polaris and MinIO namespace ACL state.",
)
async def sync_namespace_acls(
    username: Annotated[str, Query(min_length=1)],
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(require_admin)],
):
    """Admin-callable namespace ACL drift repair for one user."""
    app_state = get_app_state(request)
    result = await app_state.namespace_acl_manager.reconcile_user(username)
    return NamespaceAclSyncResponse(
        username=result.username,
        policy_name=result.policy_name,
        synced_grants=list(result.synced_grants),
        failed_grants=[
            {"grant_id": failure.grant_id, "message": failure.message}
            for failure in result.failed_grants
        ],
        revoked_stale_roles=list(result.revoked_stale_roles),
        policy_size_bytes=result.policy_size_bytes,
    )


async def _require_tenant_exists(app_state, tenant_name: str) -> str:
    tenant_name = validate_group_name(tenant_name)
    if tenant_name.endswith("ro"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use the base tenant name, not the read-only group name",
        )
    if not await app_state.group_manager.resource_exists(tenant_name):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_name}' not found",
        )
    return tenant_name


async def _ensure_minio_user(app_state, username: str) -> None:
    if await app_state.user_manager.resource_exists(username):
        return
    await app_state.user_manager.create_user(username)


async def _is_shadowed_by_tenant_membership(
    app_state,
    tenant_name: str,
    username: str,
    access_level: str,
) -> bool:
    rw_members = set(await app_state.group_manager.get_group_members(tenant_name))
    if username in rw_members:
        return True
    if access_level == "write":
        return False
    ro_members = set(
        await app_state.group_manager.get_group_members(f"{tenant_name}ro")
    )
    return username in ro_members
