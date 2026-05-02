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

from minio.managers.user_manager import GLOBAL_USER_GROUP, REFDATA_TENANT_RO_GROUP
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
    """Response model for user management operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    access_key: Annotated[str, Field(description="MinIO access key")]
    secret_key: Annotated[
        str, Field(description="MinIO secret key (only on creation/rotation)")
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
    """Response model for bulk credential rotation."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    users_rotated: Annotated[
        int, Field(description="Number of users whose credentials were rotated", ge=0)
    ]
    users_failed: Annotated[
        int, Field(description="Number of users whose rotation failed", ge=0)
    ]
    errors: Annotated[list[MigrationError], Field(description="Errors encountered")]
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
      2. ``polaris.user_manager.create_user`` — personal Iceberg catalog +
         principal + ``catalog_admin`` role + ``{username}_role``.
      3. ``polaris.group_manager.add_user_to_group`` for each MinIO default
         group the user joined — keeps the Polaris principal-role bindings in
         sync with the MinIO membership.
    """
    app_state = get_app_state(request)

    # 1. MinIO side.
    user_info = await app_state.user_manager.create_user(username=username)

    # 2. Polaris personal assets.
    await app_state.polaris_user_manager.create_user(username=username)

    # 3. Mirror default-group memberships into Polaris. UserManager.create_user
    # always adds to GLOBAL_USER_GROUP and best-effort adds to
    # REFDATA_TENANT_RO_GROUP (skipped silently if absent), so we mirror
    # whichever the user actually joined per `user_info.groups`.
    user_groups = set(user_info.groups or ())
    for group_name in (GLOBAL_USER_GROUP, REFDATA_TENANT_RO_GROUP):
        if group_name in user_groups:
            await app_state.polaris_group_manager.add_user_to_group(
                username, group_name
            )

    response = UserManagementResponse(
        username=user_info.username,
        access_key=user_info.access_key,
        secret_key=str(user_info.secret_key),
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
    """Rotate credentials for a user."""
    app_state = get_app_state(request)

    access_key, secret_key = await app_state.credential_service.rotate(username)

    user_info = await app_state.user_manager.get_user(username)

    response = UserManagementResponse(
        username=username,
        access_key=access_key,
        secret_key=secret_key,
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
      1. Cached MinIO and Polaris credentials (so a later retry after a
         partial failure doesn't trip on the missing user/principal).
      2. Polaris user — drops principal role, principal, and personal catalog.
         Done before MinIO so the Polaris bindings can't reference a
         deleted MinIO IAM identity.
      3. MinIO user — IAM, policies, directories, group memberships.
    """
    app_state = get_app_state(request)

    # 1. Credentials cache cleanup.
    await app_state.credential_service.delete_credentials(username)
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
        "Force-rotate credentials for every user in the system. "
        "Each rotation is independent — errors do not block others. "
        "Returns counts of successes and failures with error details."
    ),
)
async def rotate_all_credentials(
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Rotate credentials for all users in the system."""
    app_state = get_app_state(request)
    errors: list[MigrationError] = []
    users_rotated = 0

    all_usernames = await app_state.user_manager.list_resources()
    logger.info(f"Rotating credentials for {len(all_usernames)} users")

    for username in all_usernames:
        try:
            await app_state.credential_service.rotate(username)
            users_rotated += 1
        except Exception as e:
            logger.warning(f"Failed to rotate credentials for user {username}: {e}")
            errors.append(
                MigrationError(
                    resource_type="user", resource_name=username, error=str(e)
                )
            )

    logger.info(
        f"Admin {authenticated_user.user} rotated credentials: "
        f"{users_rotated} succeeded, {len(errors)} failed"
    )

    return RotateAllCredentialsResponse(
        users_rotated=users_rotated,
        users_failed=len(errors),
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


class EnsurePolarisResponse(BaseModel):
    """Response model for bulk Polaris resource provisioning."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    users_provisioned: Annotated[
        int, Field(description="Number of users provisioned in Polaris", ge=0)
    ]
    groups_provisioned: Annotated[
        int, Field(description="Number of tenant catalogs ensured", ge=0)
    ]
    errors: Annotated[list[MigrationError], Field(description="Errors encountered")]
    performed_by: Annotated[str, Field(description="Admin who performed the operation")]
    timestamp: Annotated[datetime, Field(description="When operation was performed")]


@router.post(
    "/migrate/regenerate-policies",
    response_model=RegeneratePoliciesResponse,
    summary="Regenerate all IAM policies",
    description=(
        "Force-regenerate HOME policies for all users and groups from the current template. "
        "This updates pre-existing policies to include new path statements (e.g., Iceberg paths). "
        "Each regeneration is independent — errors do not block others. "
        "Callers may pass `exclude_users` / `exclude_groups` to skip system or service accounts."
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
        "based on group memberships. All operations are idempotent."
    ),
)
async def ensure_all_polaris_resources(
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Backfill Polaris resources for every existing MinIO user and group.

    Mirrors the per-request orchestration that the create-user / create-group
    / add-member endpoints do, but applied to every existing MinIO resource.
    Safe to re-run: every Polaris call here is idempotent.
    """
    app_state = get_app_state(request)
    polaris_user_manager = app_state.polaris_user_manager
    polaris_group_manager = app_state.polaris_group_manager
    errors: list[MigrationError] = []
    users_provisioned = 0
    groups_provisioned = 0

    # 1. Ensure each base tenant catalog exists.
    all_group_names = await app_state.group_manager.list_resources()
    base_groups = [g for g in all_group_names if not g.endswith("ro")]
    logger.info(f"Ensuring Polaris tenant catalogs for {len(base_groups)} groups")

    for base_group in base_groups:
        try:
            # Backfill: ensure the catalog without a "creator" binding.
            await polaris_group_manager.ensure_catalog(base_group)
            groups_provisioned += 1
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
    # current MinIO group memberships into Polaris role bindings.
    all_usernames = await app_state.user_manager.list_resources()
    logger.info(f"Ensuring Polaris resources for {len(all_usernames)} users")

    for username in all_usernames:
        try:
            await polaris_user_manager.create_user(username)

            user_groups = await app_state.group_manager.get_user_groups(username)
            for group_name in user_groups:
                await polaris_group_manager.add_user_to_group(username, group_name)

            users_provisioned += 1
        except Exception as e:
            logger.warning(f"Failed to provision Polaris for user {username}: {e}")
            errors.append(
                MigrationError(
                    resource_type="user", resource_name=username, error=str(e)
                )
            )

    logger.info(
        f"Admin {authenticated_user.user} ensured Polaris resources: "
        f"{users_provisioned} users, {groups_provisioned} groups, {len(errors)} errors"
    )

    return EnsurePolarisResponse(
        users_provisioned=users_provisioned,
        groups_provisioned=groups_provisioned,
        errors=errors,
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )
