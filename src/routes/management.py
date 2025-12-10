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

from ..minio.models.policy import PolicyModel, PolicyTarget
from ..minio.models.user import UserModel
from ..minio.utils.validators import validate_group_name
from ..service.app_state import get_app_state
from ..service.dependencies import require_admin
from ..service.exceptions import (
    GroupOperationError,
    PolicyOperationError,
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
    policy_name: Annotated[str, Field(description="Associated policy name")]
    operation: Annotated[
        str, Field(description="Operation performed (create/update/delete)")
    ]
    performed_by: Annotated[
        str, Field(description="Admin who performed the operation", min_length=1)
    ]
    timestamp: Annotated[datetime, Field(description="When operation was performed")]


class PolicyListResponse(BaseModel):
    """Response model for policy listing with pagination."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    policies: Annotated[list[PolicyModel], Field(description="List of policies")]
    total_count: Annotated[int, Field(description="Total number of policies", ge=0)]
    retrieved_count: Annotated[
        int, Field(description="Number of policies retrieved", ge=0)
    ]
    page: Annotated[int, Field(description="Current page number", ge=1)]
    page_size: Annotated[int, Field(description="Number of items per page", ge=1)]
    total_pages: Annotated[int, Field(description="Total number of pages", ge=1)]
    has_next: Annotated[bool, Field(description="Whether there are more pages")]
    has_prev: Annotated[bool, Field(description="Whether there are previous pages")]


class ResourceDeleteResponse(BaseModel):
    """Response model for resource deletion."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    resource_type: Annotated[str, Field(description="Type of resource deleted")]
    resource_name: Annotated[
        str, Field(description="Name of resource deleted", min_length=1)
    ]
    message: Annotated[str, Field(description="Human-readable message")]


# ===== USER MANAGEMENT ENDPOINTS =====


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
    """Create a new user account."""
    app_state = get_app_state(request)

    user_info = await app_state.user_manager.create_user(username=username)

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

    (
        access_key,
        secret_key,
    ) = await app_state.user_manager.get_or_rotate_user_credentials(username)
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
    """Delete a user account."""
    app_state = get_app_state(request)

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
                    "policy_name": group_info.policy_name,
                }
            )
        except Exception as e:
            logger.warning(f"Failed to get info for group {group_name}: {e}")

    logger.info(f"Admin {authenticated_user.user} listed {len(groups)} groups")
    return {"groups": groups, "total_count": len(group_names)}


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

    This creates both the main group with read/write access and a read-only group
    ({group_name}ro) with read-only access to the same shared workspace.
    """
    # Validate group name early to return 400 for invalid names
    validate_group_name(group_name)

    app_state = get_app_state(request)

    # create_group returns a tuple: (main_group, ro_group)
    group_info, ro_group_info = await app_state.group_manager.create_group(
        group_name=group_name,
        creator=authenticated_user.user,
    )

    # Return response for the main group (read/write), including RO group info
    response = GroupManagementResponse(
        group_name=group_info.group_name,
        ro_group_name=ro_group_info.group_name,
        members=group_info.members,
        member_count=len(group_info.members),
        policy_name=str(group_info.policy_name),
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
    """Add a member to a group."""
    app_state = get_app_state(request)

    await app_state.group_manager.add_user_to_group(username, group_name)

    # Get updated group info
    group_info = await app_state.group_manager.get_group_info(group_name)

    response = GroupManagementResponse(
        group_name=group_info.group_name,
        members=group_info.members,
        member_count=len(group_info.members),
        policy_name=str(group_info.policy_name),
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
    """Remove a member from a group."""
    app_state = get_app_state(request)

    await app_state.group_manager.remove_user_from_group(username, group_name)

    # Get updated group info
    group_info = await app_state.group_manager.get_group_info(group_name)

    response = GroupManagementResponse(
        group_name=group_info.group_name,
        members=group_info.members,
        member_count=len(group_info.members),
        policy_name=str(group_info.policy_name),
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
    """Delete a group."""
    app_state = get_app_state(request)

    success = await app_state.group_manager.delete_resource(group_name)
    if not success:
        raise GroupOperationError(f"Failed to delete group {group_name}")

    response = ResourceDeleteResponse(
        resource_type="group",
        resource_name=group_name,
        message=f"Group {group_name} deleted successfully",
    )

    logger.info(f"Admin {authenticated_user.user} deleted group {group_name}")
    return response


# ===== POLICY MANAGEMENT ENDPOINTS =====


@router.get(
    "/policies",
    response_model=PolicyListResponse,
    summary="List all policies",
    description="Get a paginated list of all policies in the system.",
)
async def list_policies(
    request: Request,
    authenticated_user=Depends(require_admin),
    page: Annotated[
        int,
        Query(ge=1, description="Page number (1-based)"),
    ] = 1,
    page_size: Annotated[
        int,
        Query(ge=1, le=500, description="Number of policies per page"),
    ] = 50,
):
    """List all policies in the system with pagination."""
    app_state = get_app_state(request)

    # Get all policies
    all_policies = await app_state.policy_manager.list_all_policies()
    total_count = len(all_policies)

    # Calculate pagination
    total_pages = (total_count + page_size - 1) // page_size  # Ceiling division
    offset = (page - 1) * page_size
    paginated_policies = all_policies[offset : offset + page_size]

    response = PolicyListResponse(
        policies=paginated_policies,
        total_count=total_count,
        retrieved_count=len(paginated_policies),
        page=page,
        page_size=page_size,
        total_pages=max(1, total_pages),  # At least 1 page
        has_next=page < total_pages,
        has_prev=page > 1,
    )

    logger.info(
        f"Admin {authenticated_user.user} listed {len(paginated_policies)} policies (page {page}/{total_pages})"
    )
    return response


@router.delete(
    "/policies/{policy_name}",
    response_model=ResourceDeleteResponse,
    summary="Delete policy",
    description="Delete a policy from the system.",
)
async def delete_policy(
    policy_name: Annotated[
        str, Path(description="Policy name to delete", min_length=1)
    ],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Delete a policy."""
    app_state = get_app_state(request)

    try:
        # Check if policy exists first
        policy_exists = await app_state.policy_manager.resource_exists(policy_name)
        if not policy_exists:
            # Policy doesn't exist - return idempotent success response
            response = ResourceDeleteResponse(
                resource_type="policy",
                resource_name=policy_name,
                message=f"Policy {policy_name} was already deleted or does not exist",
            )
            logger.info(
                f"Admin {authenticated_user.user} attempted to delete non-existent policy {policy_name} - returning idempotent success"
            )
            return response

        # Get all entities (users and groups) that have this policy attached
        try:
            attached_entities = (
                await app_state.policy_manager._get_policy_attached_entities(
                    policy_name
                )
            )
        except Exception as e:
            logger.warning(
                f"Could not get attached entities for policy {policy_name}: {e}"
            )
            attached_entities = {PolicyTarget.USER: [], PolicyTarget.GROUP: []}

        # Detach policy from all users
        for username in attached_entities.get(PolicyTarget.USER, []):
            try:
                await app_state.policy_manager.detach_policy_from_user(
                    policy_name, username
                )
                logger.info(f"Detached policy {policy_name} from user {username}")
            except Exception as e:
                logger.warning(
                    f"Failed to detach policy {policy_name} from user {username}: {e}"
                )

        # Detach policy from all groups
        for group_name in attached_entities.get(PolicyTarget.GROUP, []):
            try:
                await app_state.policy_manager.detach_policy_from_group(
                    policy_name, group_name
                )
                logger.info(f"Detached policy {policy_name} from group {group_name}")
            except Exception as e:
                logger.warning(
                    f"Failed to detach policy {policy_name} from group {group_name}: {e}"
                )

        # Now delete the policy
        success = await app_state.policy_manager.delete_resource(policy_name)
        if not success:
            raise PolicyOperationError(f"Failed to delete policy {policy_name}")

        response = ResourceDeleteResponse(
            resource_type="policy",
            resource_name=policy_name,
            message=f"Policy {policy_name} deleted successfully",
        )

        logger.info(f"Admin {authenticated_user.user} deleted policy {policy_name}")
        return response

    except Exception as e:
        logger.error(f"Unexpected error deleting policy {policy_name}: {e}")
        raise PolicyOperationError(f"Failed to delete policy {policy_name}") from e
