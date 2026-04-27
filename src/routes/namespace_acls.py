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
from fastapi.security.utils import get_authorization_scheme_param

from polaris.namespace_acl_manager import (
    NamespaceAclNamespaceNotFoundError,
    NamespaceAclValidationError,
)
from polaris.namespace_acl_models import (
    NamespaceAclBulkSyncResponse,
    NamespaceAclGrantRequest,
    NamespaceAclGrantResponse,
    NamespaceAclRevokeRequest,
    NamespaceAclSyncResponse,
)
from polaris.namespace_acl_store import normalize_namespace_parts
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
        status.HTTP_207_MULTI_STATUS: {
            "model": NamespaceAclGrantResponse,
            "description": (
                "Grant intent is recorded in the source of truth, but external "
                "side effects (Polaris role / MinIO policy) are not yet in sync. "
                "Inspect the response 'status' and 'last_sync_error' fields, then "
                "call POST /management/migrate/sync-namespace-acls to retry."
            ),
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

    # 1. Validate the namespace BEFORE provisioning the user. This avoids
    #    creating a stray MinIO/Polaris user when the steward typos the
    #    namespace name.
    try:
        await app_state.namespace_acl_manager.validate_namespace_for_grant(
            tenant_name,
            body.namespace,
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

    # 2. Verify the target is a real KBase user before MMS provisioning. The
    #    grant flow eventually creates MinIO and Polaris principals for the
    #    target, and we don't want to fan out those side effects for typo'd
    #    usernames.
    token = _extract_token(request)
    await _require_kbase_user(app_state, body.username, token)

    # 3. Idempotently provision the MinIO user; create_user is a no-op when the
    #    user already exists.
    await _ensure_minio_user(app_state, body.username)

    shadowed = await app_state.namespace_acl_manager.is_shadowed_by_tenant_membership(
        tenant_name=tenant_name,
        username=body.username,
        access_level=body.access_level,
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

    # The grant intent is durable in PostgreSQL even when external sync fails.
    # Surface partial-sync failures via 207 Multi-Status with the grant payload
    # so clients can distinguish "request rejected" (4xx) from "intent recorded
    # but Polaris/MinIO side effects partially failed" (207). The grant 'status'
    # field is sync_error and a follow-up reconcile will heal it.
    if not result.sync_result.success:
        response.status_code = status.HTTP_207_MULTI_STATUS
    elif not result.created:
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
    try:
        namespace_parts = (
            list(normalize_namespace_parts(namespace.split("."))) if namespace else None
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        ) from e
    grants = await app_state.namespace_acl_manager.list_grants_for_tenant(
        tenant_name,
        namespace_parts,
    )
    return [NamespaceAclGrantResponse.from_record(grant) for grant in grants]


@router.delete(
    "/tenants/{tenant_name}/namespace-acls",
    response_model=NamespaceAclGrantResponse,
    responses={
        status.HTTP_207_MULTI_STATUS: {
            "model": NamespaceAclGrantResponse,
            "description": (
                "Revocation is recorded in the source of truth, but cleanup of "
                "Polaris role assignments or the MinIO policy is partially "
                "failed. Call POST /management/migrate/sync-namespace-acls to "
                "retry."
            ),
        },
    },
    summary="Revoke namespace access",
    description="Revoke the current grant for a user and namespace.",
)
async def revoke_namespace_acl(
    tenant_name: Annotated[str, Path(min_length=1)],
    body: NamespaceAclRevokeRequest,
    request: Request,
    response: Response,
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
        response.status_code = status.HTTP_207_MULTI_STATUS
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
    response_model=NamespaceAclSyncResponse | NamespaceAclBulkSyncResponse,
    summary="Reconcile namespace ACLs for a user",
    description="Admin drift-repair endpoint for Polaris and MinIO namespace ACL state.",
)
async def sync_namespace_acls(
    request: Request,
    authenticated_user: Annotated[KBaseUser, Depends(require_admin)],
    username: Annotated[str | None, Query(min_length=1)] = None,
    tenant: Annotated[str | None, Query(min_length=1)] = None,
):
    """Admin-callable namespace ACL drift repair."""
    if username and tenant:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Specify either username or tenant, not both",
        )

    app_state = get_app_state(request)
    if username:
        result = await app_state.namespace_acl_manager.reconcile_user(username)
        return _sync_response_from_result(result)

    tenant_name = None
    scope = "all"
    if tenant:
        tenant_name = await _require_tenant_exists(app_state, tenant)
        scope = "tenant"

    usernames = await app_state.namespace_acl_manager.list_usernames_for_sync(
        tenant_name=tenant_name,
    )
    results = [
        _sync_response_from_result(
            await app_state.namespace_acl_manager.reconcile_user(sync_username)
        )
        for sync_username in usernames
    ]
    return NamespaceAclBulkSyncResponse(
        scope=scope,
        tenant_name=tenant_name,
        reconciled_users=usernames,
        results=results,
    )


def _sync_response_from_result(result) -> NamespaceAclSyncResponse:
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


def _extract_token(request: Request) -> str:
    """Extract the bearer token from the Authorization header (case-insensitive)."""
    header = request.headers.get("Authorization", "")
    _, credentials = get_authorization_scheme_param(header)
    return credentials


async def _require_kbase_user(app_state, username: str, token: str) -> None:
    """Reject grant requests for usernames that KBase Auth doesn't recognize.

    Calls the same KBase Auth batch profile endpoint already used by tenant
    membership flows. A KBase profile lookup that returns no display name is
    treated as "user does not exist", so we fail closed rather than fan out
    Polaris/MinIO provisioning side effects for typo'd usernames.
    """
    profiles = await app_state.profile_client.get_user_profiles([username], token)
    profile = profiles.get(username)
    if profile is None or profile.display_name is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"KBase user '{username}' not found",
        )


async def _ensure_minio_user(app_state, username: str) -> None:
    if await app_state.user_manager.resource_exists(username):
        return
    await app_state.user_manager.create_user(username)
