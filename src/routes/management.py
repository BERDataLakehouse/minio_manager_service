"""
Resource Management Routes for the MinIO Manager API.

This module provides administrative operations for managing
users, groups, and policies. These are admin-level operations
that require elevated privileges.
"""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from polaris.orchestration import ensure_user_polaris_state
from s3.models.user import UserModel
from s3.utils.validators import validate_group_name
from service.app_state import get_app_state
from service.dependencies import auth, require_admin
from service.exceptions import (
    DataGovernanceError,
    GroupOperationError,
    TenantNotFoundError,
    UserOperationError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/management", tags=["management"])


# ===== RESPONSE MODELS =====


class UserListResponse(BaseModel):
    """Response model for user listing with pagination."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    users: Annotated[list[UserModel], Field(description="List of users")]
    total_count: Annotated[int, Field(description="Total number of users", ge=0)]
    retrieved_count: Annotated[
        int, Field(description="Number of users retrieved", ge=0)
    ]
    page: Annotated[int, Field(description="Current page number", ge=1)]
    page_size: Annotated[int, Field(description="Number of items per page", ge=1)]
    total_pages: Annotated[int, Field(description="Total number of pages", ge=1)]
    has_next: Annotated[bool, Field(description="Whether there are more pages")]
    has_prev: Annotated[bool, Field(description="Whether there are previous pages")]


class UserManagementResponse(BaseModel):
    """Response model for user management operations.

    Carries the full credential bundle (S3 IAM + Polaris OAuth) returned
    on create / rotate so admin tooling has both halves in one round-trip,
    matching the user-facing ``GET /credentials/`` shape.
    """

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    # S3 IAM half
    s3_access_key: Annotated[str, Field(description="S3 IAM access key")]
    s3_secret_key: Annotated[
        str, Field(description="S3 IAM secret key (only on creation/rotation)")
    ]
    # Polaris OAuth half
    polaris_client_id: Annotated[str, Field(description="Polaris OAuth client ID")]
    polaris_client_secret: Annotated[
        str,
        Field(description="Polaris OAuth client secret (only on creation/rotation)"),
    ]
    home_paths: Annotated[list[str], Field(description="User home directory paths")]
    groups: Annotated[list[str], Field(description="Group memberships")]
    total_policies: Annotated[int, Field(description="Number of active policies", ge=0)]
    operation: Annotated[
        str, Field(description="Operation performed (create/update/rotate)")
    ]
    performed_by: Annotated[
        str, Field(description="Admin who performed the operation", min_length=1)
    ]
    timestamp: Annotated[datetime, Field(description="When operation was performed")]


class GroupManagementResponse(BaseModel):
    """Response model for group management operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    group_name: Annotated[str, Field(description="Group name", min_length=1)]
    ro_group_name: Annotated[
        str | None,
        Field(
            default=None,
            description="Read-only group name (created alongside main group)",
        ),
    ]
    members: Annotated[list[str], Field(description="Group members")]
    member_count: Annotated[int, Field(description="Number of members", ge=0)]
    operation: Annotated[
        str, Field(description="Operation performed (create/update/delete)")
    ]
    performed_by: Annotated[
        str, Field(description="Admin who performed the operation", min_length=1)
    ]
    timestamp: Annotated[datetime, Field(description="When operation was performed")]


class ResourceDeleteResponse(BaseModel):
    """Response model for resource deletion."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    resource_type: Annotated[str, Field(description="Type of resource deleted")]
    resource_name: Annotated[
        str, Field(description="Name of resource deleted", min_length=1)
    ]
    message: Annotated[str, Field(description="Human-readable message")]


class GroupNamesResponse(BaseModel):
    """Response model for listing group names only (for authenticated users)."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    group_names: Annotated[
        list[str], Field(description="List of available group names")
    ]
    total_count: Annotated[int, Field(description="Total number of groups", ge=0)]


class UserNamesResponse(BaseModel):
    """Response model for listing usernames only (lightweight alternative to full user list)."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    usernames: Annotated[list[str], Field(description="List of all usernames")]
    total_count: Annotated[int, Field(description="Total number of users", ge=0)]


class MigrationError(BaseModel):
    """A single error encountered during a bulk operation."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    resource_type: Annotated[str, Field(description="Type of resource (user/group)")]
    resource_name: Annotated[str, Field(description="Name of the resource")]
    error: Annotated[str, Field(description="Error message")]


class RotateAllCredentialsResponse(BaseModel):
    """Response model for bulk credential rotation.

    A user counts as ``rotated`` only when BOTH backends rotate
    successfully — partial-success cases (e.g., S3 ok, Polaris failed)
    are counted under ``users_failed`` and surfaced in ``errors`` with
    ``resource_type`` of ``user_s3`` or ``user_polaris`` so operators
    can tell which backend to retry.
    """

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    users_rotated: Annotated[
        int,
        Field(description="Users whose S3 AND Polaris credentials both rotated", ge=0),
    ]
    users_failed: Annotated[
        int,
        Field(description="Users where at least one backend's rotation failed", ge=0),
    ]
    errors: Annotated[
        list[MigrationError],
        Field(
            description=(
                "Per-backend errors. ``resource_type`` is ``user_s3`` or "
                "``user_polaris`` so each backend's failures are separable."
            )
        ),
    ]
    performed_by: Annotated[str, Field(description="Admin who performed the operation")]
    timestamp: Annotated[datetime, Field(description="When operation was performed")]


# ===== USER MANAGEMENT ENDPOINTS =====


@router.get(
    "/users/names",
    response_model=UserNamesResponse,
    summary="List all usernames",
    description="Get a list of all usernames in the system without fetching full user details. Much faster than the full user list endpoint.",
)
async def list_user_names(
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """List all usernames in the system (lightweight)."""
    app_state = get_app_state(request)

    all_usernames = await app_state.user_manager.list_resources()

    logger.info(
        f"Admin {authenticated_user.user} listed {len(all_usernames)} usernames"
    )
    return UserNamesResponse(
        usernames=all_usernames,
        total_count=len(all_usernames),
    )


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all users",
    description="Get a paginated list of all users in the system with basic information.",
)
async def list_users(
    request: Request,
    authenticated_user=Depends(require_admin),
    page: Annotated[
        int,
        Query(ge=1, description="Page number (1-based)"),
    ] = 1,
    page_size: Annotated[
        int,
        Query(ge=1, le=500, description="Number of users per page"),
    ] = 50,
):
    """List all users in the system with pagination."""
    app_state = get_app_state(request)

    # Get all usernames
    all_usernames = await app_state.user_manager.list_resources()
    total_count = len(all_usernames)

    # Calculate pagination
    total_pages = (total_count + page_size - 1) // page_size  # Ceiling division
    offset = (page - 1) * page_size
    paginated_usernames = all_usernames[offset : offset + page_size]

    # Get user info for paginated results
    users = []
    for username in paginated_usernames:
        try:
            user_info = await app_state.user_manager.get_user(username)
            users.append(user_info)
        except Exception as e:
            logger.warning(f"Failed to get info for user {username}: {e}")

    logger.info(
        f"Admin {authenticated_user.user} listed {len(users)} users (page {page}/{total_pages})"
    )
    return UserListResponse(
        users=users,
        total_count=total_count,
        retrieved_count=len(users),
        page=page,
        page_size=page_size,
        total_pages=max(1, total_pages),  # At least 1 page
        has_next=page < total_pages,
        has_prev=page > 1,
    )


@router.post(
    "/users/{username}",
    response_model=UserManagementResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    description="Create a new user with home directories and initial policy configuration.",
)
async def create_user(
    username: Annotated[str, Path(description="Username to create", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Create a new user account in MinIO and provision matching Polaris assets.

    Orchestration order:
      1. ``minio.user_manager.create_user`` — MinIO IAM user, policies,
         home directories, default group memberships (``globalusers``,
         optionally ``refdataro``).
      2. ``polaris.orchestration.ensure_user_polaris_state`` — provisions
         personal Polaris assets and mirrors the user's actual MinIO group
         memberships into Polaris role bindings (queried directly from
         the group manager so default groups added by step 1, and any
         future additions to that default set, are mirrored without code
         changes here).
    """
    app_state = get_app_state(request)

    # 1. MinIO side.
    user_info = await app_state.user_manager.create_user(username=username)

    # 2. Polaris personal assets + mirror MinIO group memberships.
    await ensure_user_polaris_state(
        username,
        polaris_user_manager=app_state.polaris_user_manager,
        polaris_group_manager=app_state.polaris_group_manager,
        group_manager=app_state.group_manager,
    )

    # 3. Polaris credentials. PolarisCredentialService self-bootstraps the
    # principal on cache miss, so step 2's create_user is redundant on this
    # path — we keep it for the group-membership mirror that the credential
    # service does not perform.
    polaris_record = await app_state.polaris_credential_service.get_or_create(username)

    response = UserManagementResponse(
        username=user_info.username,
        s3_access_key=user_info.access_key,
        s3_secret_key=str(user_info.secret_key),
        polaris_client_id=polaris_record.client_id,
        polaris_client_secret=polaris_record.client_secret,
        home_paths=user_info.home_paths,
        groups=user_info.groups,
        total_policies=user_info.total_policies,
        operation="create",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(f"Admin {authenticated_user.user} created user {username}")
    return response


@router.post(
    "/users/{username}/rotate-credentials",
    response_model=UserManagementResponse,
    summary="Rotate user credentials",
    description="Force rotation of user credentials for security purposes.",
)
async def rotate_user_credentials(
    username: Annotated[str, Path(description="Username", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Rotate both S3 IAM and Polaris OAuth credentials for a user.

    Mirrors the user-facing ``POST /credentials/rotate`` so admin-driven
    rotation has the same blast radius as user-driven rotation. This is
    typically used to respond to suspected credential compromise — leaving
    Polaris OAuth secrets intact would let long-lived Spark Connect /
    Trino sessions keep authenticating with the old material.

    Both backends self-bootstrap the underlying identity, so this works
    on users provisioned before either backend was integrated.
    """
    app_state = get_app_state(request)

    access_key, secret_key = await app_state.s3_credential_service.rotate(username)
    polaris_record = await app_state.polaris_credential_service.rotate(username)

    user_info = await app_state.user_manager.get_user(username)

    response = UserManagementResponse(
        username=username,
        s3_access_key=access_key,
        s3_secret_key=secret_key,
        polaris_client_id=polaris_record.client_id,
        polaris_client_secret=polaris_record.client_secret,
        home_paths=user_info.home_paths,
        groups=user_info.groups,
        total_policies=user_info.total_policies,
        operation="rotate",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(
        f"Admin {authenticated_user.user} rotated credentials for user {username}"
    )
    return response


@router.delete(
    "/users/{username}",
    response_model=ResourceDeleteResponse,
    summary="Delete user",
    description="Delete user account and cleanup all associated resources.",
)
async def delete_user(
    username: Annotated[str, Path(description="Username to delete", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Delete a user account.

    Tear-down order:
      1. Cached credentials for both backends (so a later retry after a
         partial failure doesn't trip on the missing identity).
      2. Polaris user — drops principal role, principal, and personal catalog.
         Done before MinIO so the Polaris bindings can't reference a
         deleted MinIO IAM identity.
      3. MinIO user — IAM, policies, directories, group memberships.
    """
    app_state = get_app_state(request)

    # 1. Credentials cache cleanup (each backend has its own cache).
    await app_state.s3_credential_service.delete_credentials(username)
    await app_state.polaris_credential_service.delete_credentials(username)

    # 2. Polaris assets (idempotent / 404-tolerant).
    await app_state.polaris_user_manager.delete_user(username)

    # 3. MinIO assets.
    success = await app_state.user_manager.delete_resource(username)
    if not success:
        raise UserOperationError(f"Failed to delete user {username}")

    response = ResourceDeleteResponse(
        resource_type="user",
        resource_name=username,
        message=f"User {username} deleted successfully",
    )

    logger.info(f"Admin {authenticated_user.user} deleted user {username}")
    return response


# ===== GROUP MANAGEMENT ENDPOINTS =====


@router.get(
    "/groups",
    summary="List all groups",
    description="Get a list of all groups in the system with membership information.",
)
async def list_groups(
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """List all groups in the system."""
    app_state = get_app_state(request)

    group_names = await app_state.group_manager.list_resources()

    groups = []
    for group_name in group_names:
        try:
            group_info = await app_state.group_manager.get_group_info(group_name)
            groups.append(
                {
                    "group_name": group_info.group_name,
                    "members": group_info.members,
                    "member_count": len(group_info.members),
                }
            )
        except Exception as e:
            logger.warning(f"Failed to get info for group {group_name}: {e}")

    logger.info(f"Admin {authenticated_user.user} listed {len(groups)} groups")
    return {"groups": groups, "total_count": len(group_names)}


@router.get(
    "/groups/names",
    response_model=GroupNamesResponse,
    summary="List available group names",
    description="Get a list of all available group names in the system. Requires authentication but not admin privileges.",
)
async def list_group_names(
    request: Request,
    authenticated_user=Depends(auth),
):
    """List all group names in the system.

    This endpoint is available to any authenticated user and returns only
    group names without detailed membership or policy information.
    """
    app_state = get_app_state(request)

    group_names = await app_state.group_manager.list_resources()

    logger.info(f"User {authenticated_user.user} listed {len(group_names)} group names")
    return GroupNamesResponse(
        group_names=group_names,
        total_count=len(group_names),
    )


@router.post(
    "/groups/{group_name}",
    response_model=GroupManagementResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create group",
    description="Create a new group with shared workspace and policy configuration.",
)
async def create_group(
    group_name: Annotated[str, Path(description="Group name to create", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Create a new group.

    Creates the main group and the matching ``{group_name}ro`` read-only group
    in MinIO IAM, then provisions the matching tenant catalog and writer/
    reader principal-role bindings in Polaris.
    """
    # Prevent creating groups ending with 'ro' - this suffix is reserved for read-only variants
    if group_name.endswith("ro"):
        raise DataGovernanceError(
            "Group name cannot end with 'ro' - this suffix is reserved for read-only group variants"
        )

    # Validate group name early to return 400 for invalid names
    validate_group_name(group_name)

    app_state = get_app_state(request)

    # 1. MinIO side. create_group returns a tuple: (main_group, ro_group)
    group_info, ro_group_info = await app_state.group_manager.create_group(
        group_name=group_name,
        creator=authenticated_user.user,
    )

    # 2. Polaris side. Provisions tenant catalog + writer/reader roles and
    # binds the creator to both (mirrors MinIO's add-creator-to-both behavior).
    await app_state.polaris_group_manager.create_group(
        group_name=group_name, creator=authenticated_user.user
    )

    # Ensure tenant metadata row exists for this group
    await app_state.tenant_manager.ensure_metadata(
        group_name, created_by=authenticated_user.user
    )

    # Return response for the main group (read/write), including RO group info
    response = GroupManagementResponse(
        group_name=group_info.group_name,
        ro_group_name=ro_group_info.group_name,
        members=group_info.members,
        member_count=len(group_info.members),
        operation="create",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(
        f"Admin {authenticated_user.user} created group {group_name} and read-only group {ro_group_info.group_name}"
    )
    return response


@router.post(
    "/groups/{group_name}/members/{username}",
    response_model=GroupManagementResponse,
    summary="Add group member",
    description="Add a user to the specified group.",
)
async def add_group_member(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    username: Annotated[str, Path(description="Username to add", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Add a member to a group (MinIO IAM + matching Polaris role binding)."""
    app_state = get_app_state(request)

    await app_state.group_manager.add_user_to_group(username, group_name)
    await app_state.polaris_group_manager.add_user_to_group(username, group_name)

    # Get updated group info
    group_info = await app_state.group_manager.get_group_info(group_name)

    response = GroupManagementResponse(
        group_name=group_info.group_name,
        ro_group_name=None,  # RO group name is only returned on group creation
        members=group_info.members,
        member_count=len(group_info.members),
        operation="add_member",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(
        f"Admin {authenticated_user.user} added {username} to group {group_name}"
    )
    return response


@router.delete(
    "/groups/{group_name}/members/{username}",
    response_model=GroupManagementResponse,
    summary="Remove group member",
    description="Remove a user from the specified group.",
)
async def remove_group_member(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    username: Annotated[str, Path(description="Username to remove", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Remove a member from a group (MinIO IAM + matching Polaris role revoke)."""
    app_state = get_app_state(request)

    await app_state.group_manager.remove_user_from_group(username, group_name)
    await app_state.polaris_group_manager.remove_user_from_group(username, group_name)

    # Get updated group info
    group_info = await app_state.group_manager.get_group_info(group_name)

    response = GroupManagementResponse(
        group_name=group_info.group_name,
        ro_group_name=None,  # RO group name is only returned on group creation
        members=group_info.members,
        member_count=len(group_info.members),
        operation="remove_member",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(
        f"Admin {authenticated_user.user} removed {username} from group {group_name}"
    )
    return response


@router.delete(
    "/groups/{group_name}",
    response_model=ResourceDeleteResponse,
    summary="Delete group",
    description="Delete group and cleanup all associated resources.",
)
async def delete_group(
    group_name: Annotated[str, Path(description="Group name to delete", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Delete a group and any associated Polaris tenant catalog + metadata.

    Tear-down order: Polaris first (so the catalog and role bindings are gone
    before MinIO IAM disappears), then MinIO IAM, then tenant metadata.
    """
    app_state = get_app_state(request)

    # Polaris first — drop catalog + roles. No-op for *ro inputs.
    await app_state.polaris_group_manager.delete_group(group_name)

    success = await app_state.group_manager.delete_resource(group_name)
    if not success:
        raise GroupOperationError(f"Failed to delete group {group_name}")

    try:
        await app_state.tenant_manager.delete_metadata(group_name)
    except TenantNotFoundError:
        pass  # no tenant metadata for this group

    response = ResourceDeleteResponse(
        resource_type="group",
        resource_name=group_name,
        message=f"Group {group_name} deleted successfully",
    )

    logger.info(f"Admin {authenticated_user.user} deleted group {group_name}")
    return response


# ===== MIGRATION ENDPOINTS =====


@router.post(
    "/credentials/rotate-all-credentials",
    response_model=RotateAllCredentialsResponse,
    summary="Rotate all users' credentials",
    description=(
        "Force-rotate BOTH S3 IAM and Polaris OAuth credentials for every "
        "user in the system. Each per-user, per-backend rotation is "
        "independent — errors do not block others. A user is counted as "
        "fully rotated only when both backends succeed; partial failures "
        "are surfaced in ``errors`` with ``resource_type`` of ``user_s3`` "
        "or ``user_polaris``."
    ),
)
async def rotate_all_credentials(
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Rotate S3 + Polaris credentials for all users.

    Used as a security primitive (e.g., after suspected compromise or an
    encryption-key rollover). Polaris must be rotated alongside S3 —
    leaving Polaris OAuth secrets intact would defeat the purpose by
    letting long-lived Spark Connect / Trino sessions keep authenticating
    with the old material.
    """
    app_state = get_app_state(request)
    errors: list[MigrationError] = []
    users_rotated = 0

    all_usernames = await app_state.user_manager.list_resources()
    logger.info(f"Rotating credentials for {len(all_usernames)} users")

    for username in all_usernames:
        # Track each backend independently so a Polaris failure doesn't
        # mask a successful S3 rotation (or vice versa). Both backends
        # are attempted for every user even if the first fails.
        s3_ok = False
        polaris_ok = False

        try:
            await app_state.s3_credential_service.rotate(username)
            s3_ok = True
        except Exception as e:
            logger.warning(f"Failed to rotate S3 credentials for user {username}: {e}")
            errors.append(
                MigrationError(
                    resource_type="user_s3", resource_name=username, error=str(e)
                )
            )

        try:
            await app_state.polaris_credential_service.rotate(username)
            polaris_ok = True
        except Exception as e:
            logger.warning(
                f"Failed to rotate Polaris credentials for user {username}: {e}"
            )
            errors.append(
                MigrationError(
                    resource_type="user_polaris", resource_name=username, error=str(e)
                )
            )

        if s3_ok and polaris_ok:
            users_rotated += 1

    users_failed = len(all_usernames) - users_rotated

    logger.info(
        f"Admin {authenticated_user.user} rotated credentials: "
        f"{users_rotated} fully succeeded, {users_failed} had at least one "
        f"backend failure ({len(errors)} per-backend errors total)"
    )

    return RotateAllCredentialsResponse(
        users_rotated=users_rotated,
        users_failed=users_failed,
        errors=errors,
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )


class RegeneratePoliciesResponse(BaseModel):
    """Response model for bulk policy regeneration."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    users_updated: Annotated[
        int, Field(description="Number of user policies regenerated", ge=0)
    ]
    groups_updated: Annotated[
        int, Field(description="Number of group policies regenerated", ge=0)
    ]
    users_skipped: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="Usernames excluded by the caller that exist in the system",
        ),
    ]
    groups_skipped: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="Base group names excluded by the caller that exist in the system",
        ),
    ]
    errors: Annotated[list[MigrationError], Field(description="Errors encountered")]
    performed_by: Annotated[str, Field(description="Admin who performed the operation")]
    timestamp: Annotated[datetime, Field(description="When operation was performed")]


class RegeneratePoliciesRequest(BaseModel):
    """Request model for bulk policy regeneration."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    exclude_users: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Usernames to skip, such as system or service accounts. "
                "Names that do not exist are silently ignored — verify the "
                "`users_skipped` field in the response to confirm which "
                "exclusions actually matched a present user."
            ),
        ),
    ]
    exclude_groups: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Base group names to skip. The corresponding read-only group "
                "is also skipped automatically. Names that do not exist are "
                "silently ignored — verify the `groups_skipped` field in the "
                "response to confirm which exclusions actually matched a present group."
            ),
        ),
    ]


class EnsurePolarisRequest(BaseModel):
    """Request model for bulk Polaris resource provisioning.

    Mirrors :class:`RegeneratePoliciesRequest` so an operator can pass the
    same exclusion list to both migration endpoints (e.g., to skip the same
    set of system / service accounts when running a backfill).
    """

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    exclude_users: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Usernames to skip, such as system or service accounts. "
                "Names that do not exist are silently ignored — verify the "
                "`users_skipped` field in the response to confirm which "
                "exclusions actually matched a present user."
            ),
        ),
    ]
    exclude_groups: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Base group names to skip. The corresponding read-only group "
                "is also skipped automatically (no tenant catalog ensured, no "
                "role bindings granted for excluded groups even on users that "
                "are members). Names that do not exist are silently ignored — "
                "verify the `groups_skipped` field in the response to confirm "
                "which exclusions actually matched a present group."
            ),
        ),
    ]


class EnsurePolarisResponse(BaseModel):
    """Response model for bulk Polaris resource provisioning."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    users_provisioned: Annotated[
        int, Field(description="Number of users provisioned in Polaris", ge=0)
    ]
    groups_provisioned: Annotated[
        int, Field(description="Number of tenant catalogs ensured", ge=0)
    ]
    provisioned_users: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Sorted list of usernames that were successfully processed. "
                "Operators can grep this against `errors` to verify "
                "exactly which users completed."
            ),
        ),
    ]
    provisioned_groups: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Sorted list of base group names whose tenant catalog was "
                "successfully ensured. Useful for confirming which tenants "
                "are now Polaris-backed after a backfill."
            ),
        ),
    ]
    users_skipped: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="Usernames excluded by the caller that exist in the system",
        ),
    ]
    groups_skipped: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="Base group names excluded by the caller that exist in the system",
        ),
    ]
    errors: Annotated[list[MigrationError], Field(description="Errors encountered")]
    performed_by: Annotated[str, Field(description="Admin who performed the operation")]
    timestamp: Annotated[datetime, Field(description="When operation was performed")]


@router.post(
    "/migrate/regenerate-policies",
    response_model=RegeneratePoliciesResponse,
    summary="Regenerate all IAM policies",
    description=(
        "**Write operation.** Force-regenerates HOME policies for every user "
        "and every base group (RW + RO) in the system from the current "
        "template, replacing the previously stored policy in MinIO IAM. "
        "Use this to roll out a template change — e.g., adding the Iceberg "
        "sub-path statement so existing policies grant access to the new "
        "Polaris-managed prefix. Re-running the endpoint is idempotent: it "
        "always overwrites with the current template. Each regeneration is "
        "independent — per-resource errors do not block the others. "
        "Callers may pass `exclude_users` / `exclude_groups` to skip system "
        "or service accounts; verify `users_skipped` / `groups_skipped` in "
        "the response to confirm which exclusions actually matched a "
        "present resource."
    ),
)
async def regenerate_all_policies(
    request: Request,
    payload: RegeneratePoliciesRequest = RegeneratePoliciesRequest(),
    authenticated_user=Depends(require_admin),
):
    """Regenerate user and group HOME policies, skipping caller-supplied exclusions."""
    app_state = get_app_state(request)
    errors: list[MigrationError] = []
    users_updated = 0
    groups_updated = 0

    exclude_users = set(payload.exclude_users)
    exclude_groups = set(payload.exclude_groups)

    # Regenerate user HOME policies
    all_usernames = await app_state.user_manager.list_resources()
    target_usernames = [u for u in all_usernames if u not in exclude_users]
    skipped_users = sorted(set(all_usernames) & exclude_users)
    logger.info(
        f"Regenerating HOME policies for {len(target_usernames)} users "
        f"(skipped {len(skipped_users)} excluded users)"
    )

    for username in target_usernames:
        try:
            await app_state.policy_manager.regenerate_user_home_policy(username)
            users_updated += 1
        except Exception as e:
            logger.warning(f"Failed to regenerate policy for user {username}: {e}")
            errors.append(
                MigrationError(
                    resource_type="user", resource_name=username, error=str(e)
                )
            )

    # Regenerate group HOME policies (both RW and RO)
    all_group_names = await app_state.group_manager.list_resources()

    # Filter to base groups only (exclude *ro groups)
    base_groups = [g for g in all_group_names if not g.endswith("ro")]
    target_base_groups = [g for g in base_groups if g not in exclude_groups]
    skipped_groups = sorted(set(base_groups) & exclude_groups)
    logger.info(
        f"Regenerating HOME policies for {len(target_base_groups)} base groups "
        f"(RW + RO; skipped {len(skipped_groups)} excluded base groups)"
    )

    for base_group in target_base_groups:
        # Regenerate RW policy
        try:
            await app_state.policy_manager.regenerate_group_home_policy(
                group_name=base_group, read_only=False
            )
            groups_updated += 1
        except Exception as e:
            logger.warning(
                f"Failed to regenerate RW policy for group {base_group}: {e}"
            )
            errors.append(
                MigrationError(
                    resource_type="group", resource_name=base_group, error=str(e)
                )
            )

        # Regenerate RO policy
        ro_group_name = f"{base_group}ro"
        try:
            await app_state.policy_manager.regenerate_group_home_policy(
                group_name=ro_group_name, read_only=True, path_target=base_group
            )
            groups_updated += 1
        except Exception as e:
            logger.warning(
                f"Failed to regenerate RO policy for group {ro_group_name}: {e}"
            )
            errors.append(
                MigrationError(
                    resource_type="group", resource_name=ro_group_name, error=str(e)
                )
            )

    logger.info(
        f"Admin {authenticated_user.user} regenerated policies: "
        f"{users_updated} users, {groups_updated} groups, "
        f"{len(skipped_users)} users skipped, {len(skipped_groups)} groups skipped, "
        f"{len(errors)} errors"
    )

    return RegeneratePoliciesResponse(
        users_updated=users_updated,
        groups_updated=groups_updated,
        users_skipped=skipped_users,
        groups_skipped=skipped_groups,
        errors=errors,
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )


@router.post(
    "/migrate/ensure-polaris-resources",
    response_model=EnsurePolarisResponse,
    summary="Ensure Polaris resources for all users and groups",
    description=(
        "Ensure all users have Polaris principals, personal catalogs, and roles. "
        "Ensure all groups have tenant catalogs. Grant correct principal roles "
        "based on group memberships. All operations are idempotent. "
        "Callers may pass `exclude_users` / `exclude_groups` to skip system or "
        "service accounts and groups that should not be backfilled."
    ),
)
async def ensure_all_polaris_resources(
    request: Request,
    payload: EnsurePolarisRequest = EnsurePolarisRequest(),
    authenticated_user=Depends(require_admin),
):
    """Backfill Polaris resources for every existing MinIO user and group.

    Mirrors the per-request orchestration that the create-user / create-group
    / add-member endpoints do, but applied to every existing MinIO resource.
    Safe to re-run: every Polaris call here is idempotent. Caller-supplied
    exclusion lists honour the same convention as ``regenerate-policies``.
    """
    app_state = get_app_state(request)
    polaris_group_manager = app_state.polaris_group_manager
    errors: list[MigrationError] = []
    provisioned_users: list[str] = []
    provisioned_groups: list[str] = []

    exclude_users = set(payload.exclude_users)
    exclude_groups = set(payload.exclude_groups)

    # 1. Ensure each base tenant catalog exists. Excluded base groups are
    # skipped entirely — no catalog is provisioned and no user role bindings
    # for that base get mirrored either (see step 2).
    all_group_names = await app_state.group_manager.list_resources()
    base_groups = [g for g in all_group_names if not g.endswith("ro")]
    target_base_groups = [g for g in base_groups if g not in exclude_groups]
    skipped_groups = sorted(set(base_groups) & exclude_groups)
    logger.info(
        f"Ensuring Polaris tenant catalogs for {len(target_base_groups)} groups "
        f"(skipped {len(skipped_groups)} excluded base groups)"
    )

    for base_group in target_base_groups:
        try:
            # Backfill: ensure the catalog without a "creator" binding.
            await polaris_group_manager.ensure_catalog(base_group)
            provisioned_groups.append(base_group)
        except Exception as e:
            logger.warning(
                f"Failed to ensure tenant catalog for group {base_group}: {e}"
            )
            errors.append(
                MigrationError(
                    resource_type="group", resource_name=base_group, error=str(e)
                )
            )

    # 2. For each user: provision personal Polaris assets and mirror their
    # current MinIO group memberships into Polaris role bindings. Excluded
    # users are skipped entirely; excluded base groups are skipped per-user
    # too so we don't grant a role on a catalog we deliberately didn't
    # provision in step 1.
    all_usernames = await app_state.user_manager.list_resources()
    target_usernames = [u for u in all_usernames if u not in exclude_users]
    skipped_users = sorted(set(all_usernames) & exclude_users)
    logger.info(
        f"Ensuring Polaris resources for {len(target_usernames)} users "
        f"(skipped {len(skipped_users)} excluded users)"
    )

    for username in target_usernames:
        try:
            # Same orchestration the live POST /management/users and
            # /credentials/* paths run, so backfill produces the same
            # end-state as live provisioning. exclude_groups is honored
            # inside the helper for endpoint consistency.
            await ensure_user_polaris_state(
                username,
                polaris_user_manager=app_state.polaris_user_manager,
                polaris_group_manager=app_state.polaris_group_manager,
                group_manager=app_state.group_manager,
                exclude_groups=exclude_groups,
            )
            provisioned_users.append(username)
        except Exception as e:
            logger.warning(f"Failed to provision Polaris for user {username}: {e}")
            errors.append(
                MigrationError(
                    resource_type="user", resource_name=username, error=str(e)
                )
            )

    logger.info(
        f"Admin {authenticated_user.user} ensured Polaris resources: "
        f"{len(provisioned_users)} users, {len(provisioned_groups)} groups, "
        f"{len(skipped_users)} users skipped, {len(skipped_groups)} groups skipped, "
        f"{len(errors)} errors"
    )

    return EnsurePolarisResponse(
        users_provisioned=len(provisioned_users),
        groups_provisioned=len(provisioned_groups),
        provisioned_users=sorted(provisioned_users),
        provisioned_groups=sorted(provisioned_groups),
        users_skipped=skipped_users,
        groups_skipped=skipped_groups,
        errors=errors,
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )
