"""
Workspace Management Routes for the MinIO Manager API.

This module provides user workspace management including personal directories,
group spaces, and workspace organization. Focuses on the user experience of
organizing and managing their data storage.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from ..minio.models.policy import PolicyModel
from ..minio.models.user import UserModel
from ..service.app_state import get_app_state
from ..minio.utils.governance import (
    generate_group_governance_prefix,
    generate_user_governance_prefix,
)
from ..service.dependencies import auth
from ..service.exceptions import DataGovernanceError
from ..service.kb_auth import KBaseUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


# ===== RESPONSE MODELS =====


class GroupWorkspaceResponse(BaseModel):
    """Response model for group workspace information."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    group_name: Annotated[str, Field(description="Group name", min_length=1)]
    members: Annotated[list[str], Field(description="Group members")]
    member_count: Annotated[int, Field(description="Number of members", ge=0)]
    accessible_paths: Annotated[
        list[str], Field(description="Group's accessible paths")
    ]


class UserGroupsResponse(BaseModel):
    """Response model for user's group memberships."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    groups: Annotated[list[str], Field(description="Groups user belongs to")]
    group_count: Annotated[int, Field(description="Number of groups", ge=0)]


class UserPoliciesResponse(BaseModel):
    """Response model for user's policy information with full PolicyModel objects."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    user_home_policy: Annotated[PolicyModel, Field(description="User's home policy")]
    user_system_policy: Annotated[
        PolicyModel, Field(description="User's system policy")
    ]
    group_policies: Annotated[
        list[PolicyModel], Field(description="Policies from group memberships")
    ]
    total_policies: Annotated[int, Field(description="Number of active policies", ge=0)]


class UserAccessiblePathsResponse(BaseModel):
    """Response model for user's accessible paths."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    accessible_paths: Annotated[
        list[str], Field(description="All accessible paths from all policies")
    ]
    total_paths: Annotated[
        int, Field(description="Total number of accessible paths", ge=0)
    ]


class UserSqlWarehousePrefixResponse(BaseModel):
    """Response model for user's SQL warehouse prefix."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    sql_warehouse_prefix: Annotated[
        str, Field(description="User's SQL warehouse prefix")
    ]


class GroupSqlWarehousePrefixResponse(BaseModel):
    """Response model for group's SQL warehouse prefix."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    group_name: Annotated[str, Field(description="Group name", min_length=1)]
    sql_warehouse_prefix: Annotated[
        str, Field(description="Group's SQL warehouse prefix")
    ]


class NamespacePrefixResponse(BaseModel):
    """Response model for governance namespace prefix for user or tenant."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    user_namespace_prefix: Annotated[
        str, Field(description="User's governance namespace prefix (e.g., u_user__)")
    ]
    tenant: Annotated[
        str | None, Field(description="Tenant (group) name", default=None)
    ]
    tenant_namespace_prefix: Annotated[
        str | None,
        Field(
            description="Tenant's governance namespace prefix (e.g., tenant_)",
            default=None,
        ),
    ]


# ===== USER WORKSPACE ENDPOINTS =====


@router.get(
    "/me",
    response_model=UserModel,
    summary="Get my workspace",
    description="Get user information for the authenticated user.",
)
async def get_my_workspace(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get user information for the authenticated user."""
    app_state = get_app_state(request)

    username = authenticated_user.user
    user_info = await app_state.user_manager.get_user(username)

    logger.info(f"Retrieved workspace information for user {username}")
    return user_info


@router.get(
    "/me/groups",
    response_model=UserGroupsResponse,
    summary="Get my groups",
    description="Get list of groups the authenticated user belongs to.",
)
async def get_my_groups(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get all groups the authenticated user belongs to."""
    app_state = get_app_state(request)

    username = authenticated_user.user
    user_groups = await app_state.group_manager.get_user_groups(username)

    response = UserGroupsResponse(
        username=username,
        groups=user_groups,
        group_count=len(user_groups),
    )

    logger.info(f"Retrieved groups for user {username}")
    return response


@router.get(
    "/me/policies",
    response_model=UserPoliciesResponse,
    summary="Get my policies",
    description="Get complete policy information for the authenticated user including full PolicyModel objects.",
)
async def get_my_policies(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get complete policy information for the authenticated user."""
    app_state = get_app_state(request)

    username = authenticated_user.user

    policies_data = await app_state.user_manager.get_user_policies(username)

    user_home_policy = policies_data["user_home_policy"]
    user_system_policy = policies_data["user_system_policy"]
    group_policies = policies_data["group_policies"]

    response = UserPoliciesResponse(
        username=username,
        user_home_policy=user_home_policy,
        user_system_policy=user_system_policy,
        group_policies=group_policies,
        total_policies=2
        + len(group_policies),  # home policy + system policy + group policies
    )

    logger.info(f"Retrieved {len(group_policies) + 2} policies for user {username}")
    return response


@router.get(
    "/me/accessible-paths",
    response_model=UserAccessiblePathsResponse,
    summary="Get my accessible paths",
    description="Get all S3 paths accessible to the authenticated user through their policies and group memberships.",
)
async def get_my_accessible_paths(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get all accessible paths for the authenticated user."""
    app_state = get_app_state(request)

    username = authenticated_user.user
    accessible_paths = await app_state.user_manager.get_user_accessible_paths(username)

    response = UserAccessiblePathsResponse(
        username=username,
        accessible_paths=accessible_paths,
        total_paths=len(accessible_paths),
    )

    logger.info(
        f"Retrieved {len(accessible_paths)} accessible paths for user {username}"
    )
    return response


@router.get(
    "/me/groups/{group_name}",
    response_model=GroupWorkspaceResponse,
    summary="Get group workspace",
    description="Get workspace information for a specific group including shared areas and member access.",
)
async def get_group_workspace(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get workspace information for a group."""
    app_state = get_app_state(request)

    username = authenticated_user.user

    # Check if user is a member of the group (either read/write or read-only variant)
    is_member = await app_state.group_manager.is_user_in_group(username, group_name)
    ro_group_name = f"{group_name}ro"
    is_ro_member = await app_state.group_manager.is_user_in_group(
        username, ro_group_name
    )

    if not is_member and not is_ro_member:
        raise DataGovernanceError("User is not a member of the group")
    # Get group information
    group_info = await app_state.group_manager.get_group_info(group_name)
    group_policy = await app_state.policy_manager.get_group_policy(group_name)
    group_accessible_paths = app_state.policy_manager.get_accessible_paths_from_policy(
        group_policy
    )

    response = GroupWorkspaceResponse(
        group_name=group_name,
        members=group_info.members,
        member_count=len(group_info.members),
        accessible_paths=group_accessible_paths,
    )

    logger.info(f"Retrieved group workspace for {group_name} by user {username}")
    return response


@router.get(
    "/me/groups/{group_name}/sql-warehouse-prefix",
    response_model=GroupSqlWarehousePrefixResponse,
    summary="Get group SQL warehouse prefix",
    description="Get the SQL warehouse prefix for a specific group (requires group membership).",
)
async def get_group_sql_warehouse_prefix(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get the SQL warehouse prefix for a specific group."""
    app_state = get_app_state(request)

    username = authenticated_user.user

    # Check if user is a member of the group (either read/write or read-only variant)
    is_member = await app_state.group_manager.is_user_in_group(username, group_name)
    ro_group_name = f"{group_name}ro"
    is_ro_member = await app_state.group_manager.is_user_in_group(
        username, ro_group_name
    )

    if not is_member and not is_ro_member:
        raise DataGovernanceError("User is not a member of the group")

    # Get group SQL warehouse prefix (tenant SQL warehouse)
    sql_warehouse_prefix = f"s3a://{app_state.group_manager.config.default_bucket}/{app_state.group_manager.tenant_sql_warehouse_prefix}/{group_name}/"

    response = GroupSqlWarehousePrefixResponse(
        group_name=group_name,
        sql_warehouse_prefix=sql_warehouse_prefix,
    )

    logger.info(
        f"Retrieved SQL warehouse prefix for group {group_name} by user {username}"
    )
    return response


@router.get(
    "/me/sql-warehouse-prefix",
    response_model=UserSqlWarehousePrefixResponse,
    summary="Get my SQL warehouse prefix",
    description="Get the SQL warehouse prefix for the authenticated user.",
)
async def get_my_sql_warehouse_prefix(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get the SQL warehouse prefix for the authenticated user."""
    app_state = get_app_state(request)

    username = authenticated_user.user
    sql_warehouse_prefix = f"s3a://{app_state.user_manager.config.default_bucket}/{app_state.user_manager.users_sql_warehouse_prefix}/{username}/"

    response = UserSqlWarehousePrefixResponse(
        username=username,
        sql_warehouse_prefix=sql_warehouse_prefix,
    )

    logger.info(f"Retrieved SQL warehouse prefix for user {username}")
    return response


@router.get(
    "/me/namespace-prefix",
    response_model=NamespacePrefixResponse,
    summary="Get governance namespace prefix",
    description=(
        "Get the governance namespace prefix for the authenticated user. "
        "Optionally provide a tenant (group) to get the tenant namespace prefix; "
        "membership is required."
    ),
)
async def get_namespace_prefix(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
    tenant: Annotated[
        str | None, Query(description="Optional tenant (group) name", min_length=1)
    ] = None,
):
    """Return governance namespace prefix for user and optionally for specified tenant.

    Always returns the user's namespace prefix. If tenant is provided and user is a member,
    also returns the tenant's namespace prefix.
    """
    app_state = get_app_state(request)
    username = authenticated_user.user

    # Always generate user prefix
    user_ns_prefix = generate_user_governance_prefix(username)

    tenant_ns_prefix = None
    if tenant:
        # Check if group exists
        group_exists = await app_state.group_manager.get_group_info(tenant)
        if not group_exists:
            raise DataGovernanceError(f"Group {tenant} does not exist")
        # Check if user is a member of the group (either read/write or read-only variant)
        is_member = await app_state.group_manager.is_user_in_group(username, tenant)
        ro_group_name = f"{tenant}ro"
        is_ro_member = await app_state.group_manager.is_user_in_group(
            username, ro_group_name
        )

        if not is_member and not is_ro_member:
            raise DataGovernanceError(
                f"User {username} is not a member of the group {tenant}"
            )
        tenant_ns_prefix = generate_group_governance_prefix(tenant)

    return NamespacePrefixResponse(
        username=username,
        user_namespace_prefix=user_ns_prefix,
        tenant=tenant,
        tenant_namespace_prefix=tenant_ns_prefix,
    )
