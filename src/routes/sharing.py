"""
Data Sharing Routes for the MinIO Manager API.

This module provides the core data governance functionality for sharing and
unsharing data between users and groups.
"""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..minio.managers.sharing_manager import PathAccessInfo
from ..minio.models.policy import PolicyPermissionLevel
from ..minio.utils.validators import validate_s3_path
from ..service.app_state import get_app_state
from ..service.dependencies import auth
from ..service.exceptions import DataGovernanceError
from ..service.kb_auth import KBaseUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sharing", tags=["sharing"])


# ===== REQUEST MODELS =====


class PathRequest(BaseModel):
    """Base request model for S3 path operations."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: Annotated[
        str,
        Field(
            description="S3 path for the operation",
            examples=[
                "s3a://cdm-lake/users-general-warehouse/john/datasets/experiment1/"
            ],
            min_length=1,
        ),
    ]

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Validate S3 path format."""
        return validate_s3_path(v)


class ShareRequest(BaseModel):
    """Request model for sharing data with users or groups."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: Annotated[
        str,
        Field(
            description="S3 path to share",
            examples=[
                "s3a://cdm-lake/users-general-warehouse/john/datasets/experiment1/"
            ],
            min_length=1,
        ),
    ]
    with_users: Annotated[
        list[str],
        Field(default_factory=list, description="List of usernames to share with"),
    ]
    with_groups: Annotated[
        list[str],
        Field(default_factory=list, description="List of group names to share with"),
    ]
    permission: Annotated[
        str,
        Field(
            default="write",
            description="Permission level: 'read' for read-only, 'write' for read-write (default)",
            pattern="^(read|write)$",
        ),
    ]

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Validate S3 path format."""
        return validate_s3_path(v)


class UnshareRequest(BaseModel):
    """Request model for removing shared access."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: Annotated[
        str,
        Field(
            description="S3 path to unshare",
            examples=[
                "s3a://cdm-lake/users-general-warehouse/john/datasets/experiment1/"
            ],
            min_length=1,
        ),
    ]
    from_users: Annotated[
        list[str],
        Field(
            default_factory=list, description="List of usernames to remove access from"
        ),
    ]
    from_groups: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="List of group names to remove access from",
        ),
    ]

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Validate S3 path format."""
        return validate_s3_path(v)


# Type aliases for public/private access and access info queries
PublicAccessRequest = PathRequest
PathAccessRequest = PathRequest


# ===== RESPONSE MODELS =====


class ShareResponse(BaseModel):
    """Response model for sharing operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    path: Annotated[str, Field(description="Path that was shared")]
    shared_with_users: Annotated[
        list[str], Field(description="Users successfully shared with")
    ]
    shared_with_groups: Annotated[
        list[str], Field(description="Groups successfully shared with")
    ]
    success_count: Annotated[int, Field(description="Total successful shares", ge=0)]
    errors: Annotated[
        list[str], Field(default_factory=list, description="Any errors encountered")
    ]
    shared_by: Annotated[
        str, Field(description="User who performed the sharing", min_length=1)
    ]
    shared_at: Annotated[datetime, Field(description="When sharing was performed")]


class UnshareResponse(BaseModel):
    """Response model for unsharing operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    path: Annotated[str, Field(description="Path that was unshared")]
    unshared_from_users: Annotated[
        list[str], Field(description="Users successfully unshared from")
    ]
    unshared_from_groups: Annotated[
        list[str], Field(description="Groups successfully unshared from")
    ]
    success_count: Annotated[int, Field(description="Total successful unshares", ge=0)]
    errors: Annotated[
        list[str], Field(default_factory=list, description="Any errors encountered")
    ]
    unshared_by: Annotated[
        str, Field(description="User who performed the unsharing", min_length=1)
    ]
    unshared_at: Annotated[datetime, Field(description="When unsharing was performed")]


class PublicAccessResponse(BaseModel):
    """Response model for public/private access operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    path: Annotated[str, Field(description="Path that was modified")]
    is_public: Annotated[bool, Field(description="Whether the path is now public")]


class PathAccessResponse(PathAccessInfo):
    """Response model for path access policies query."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    path: Annotated[str, Field(description="Path that was queried")]


# ===== SHARING ENDPOINTS =====


@router.post(
    "/share",
    response_model=ShareResponse,
    summary="Share data path",
    description="Share an S3 path with specified users and/or groups. Only path owners can share their data.",
    responses={
        200: {"description": "All sharing operations succeeded"},
        207: {"description": "Partial success - some sharing operations failed"},
    },
)
async def share_data(
    share_request: Annotated[ShareRequest, Body(description="Sharing configuration")],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
    response: Response,
):
    """Share a data path with specified users or groups."""
    app_state = get_app_state(request)

    username = authenticated_user.user

    # Convert permission string to PolicyPermissionLevel
    permission_level = (
        PolicyPermissionLevel.READ
        if share_request.permission == "read"
        else PolicyPermissionLevel.WRITE
    )

    # Perform the sharing operation
    result = await app_state.sharing_manager.share_path(
        path=share_request.path,
        requesting_user=username,
        with_users=share_request.with_users,
        with_groups=share_request.with_groups,
        permission_level=permission_level,
    )

    share_response = ShareResponse(
        path=share_request.path,
        shared_with_users=result.shared_with_users,
        shared_with_groups=result.shared_with_groups,
        success_count=result.success_count,
        errors=result.errors,
        shared_by=username,
        shared_at=datetime.now(),
    )

    # Set appropriate status code based on whether there were any errors
    if result.errors:
        response.status_code = status.HTTP_207_MULTI_STATUS
        logger.warning(
            f"User {username} shared {share_request.path} with partial success: "
            f"{len(result.shared_with_users)} users and {len(result.shared_with_groups)} groups succeeded, "
            f"{len(result.errors)} errors occurred"
        )
    else:
        response.status_code = status.HTTP_200_OK
        logger.info(
            f"User {username} successfully shared {share_request.path} with "
            f"{len(result.shared_with_users)} users and {len(result.shared_with_groups)} groups"
        )

    return share_response


@router.post(
    "/unshare",
    response_model=UnshareResponse,
    summary="Remove data sharing",
    description="Remove sharing permissions for an S3 path from specified users and/or groups.",
    responses={
        200: {"description": "All unsharing operations succeeded"},
        207: {"description": "Partial success - some unsharing operations failed"},
    },
)
async def unshare_data(
    unshare_request: Annotated[
        UnshareRequest, Body(description="Unsharing configuration")
    ],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
    response: Response,
):
    """Remove sharing permissions from specified users or groups."""
    app_state = get_app_state(request)

    username = authenticated_user.user

    # Perform the unsharing operation
    result = await app_state.sharing_manager.unshare_path(
        path=unshare_request.path,
        requesting_user=username,
        from_users=unshare_request.from_users,
        from_groups=unshare_request.from_groups,
    )

    unshare_response = UnshareResponse(
        path=unshare_request.path,
        unshared_from_users=result.unshared_from_users,
        unshared_from_groups=result.unshared_from_groups,
        success_count=result.success_count,
        errors=result.errors,
        unshared_by=username,
        unshared_at=datetime.now(),
    )

    # Set appropriate status code based on whether there were any errors
    if result.errors:
        response.status_code = status.HTTP_207_MULTI_STATUS
        logger.warning(
            f"User {username} unshared {unshare_request.path} with partial success: "
            f"{len(result.unshared_from_users)} users and {len(result.unshared_from_groups)} groups succeeded, "
            f"{len(result.errors)} errors occurred"
        )
    else:
        response.status_code = status.HTTP_200_OK
        logger.info(
            f"User {username} successfully unshared {unshare_request.path} from "
            f"{len(result.unshared_from_users)} users and {len(result.unshared_from_groups)} groups"
        )

    return unshare_response


# ===== PUBLIC/PRIVATE ACCESS ENDPOINTS =====


@router.post(
    "/make-public",
    response_model=PublicAccessResponse,
    summary="Make path publicly accessible",
    description="Make an S3 path publicly accessible by sharing it with all users via the global user group.",
)
async def make_path_public(
    request_data: Annotated[
        PublicAccessRequest, Body(description="Public access request")
    ],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Make a data path publicly accessible to all users."""
    app_state = get_app_state(request)
    username = authenticated_user.user

    result = await app_state.sharing_manager.make_public(
        path=request_data.path,
        requesting_user=username,
    )

    if result.errors:
        error_msg = f"Failed to make path public: {'; '.join(result.errors)}"
        logger.error(
            f"User {username} failed to make {request_data.path} public: {result.errors}"
        )
        raise DataGovernanceError(error_msg)

    logger.info(f"User {username} successfully made {request_data.path} public")

    return PublicAccessResponse(
        path=request_data.path,
        is_public=True,
    )


@router.post(
    "/make-private",
    response_model=PublicAccessResponse,
    summary="Make path completely private",
    description="Remove a path from ALL policies that have access, making it completely private. Only the owner retains access.",
)
async def make_path_private(
    request_data: Annotated[
        PublicAccessRequest, Body(description="Private access request")
    ],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Make a data path completely private by removing it from all shared access."""
    app_state = get_app_state(request)
    username = authenticated_user.user

    result = await app_state.sharing_manager.make_private(
        path=request_data.path,
        requesting_user=username,
    )

    if result.errors:
        error_msg = f"Failed to make path private: {'; '.join(result.errors)}"
        logger.error(
            f"User {username} failed to make {request_data.path} private: {result.errors}"
        )
        raise DataGovernanceError(error_msg)

    logger.info(f"User {username} successfully made {request_data.path} private")

    return PublicAccessResponse(
        path=request_data.path,
        is_public=False,
    )


@router.post(
    "/get_path_access_info",
    response_model=PathAccessResponse,
    summary="Get path access information",
    description="Find all users and groups that have access to a given S3 path, including public access status.",
)
async def get_path_access_info(
    request_data: Annotated[
        PathAccessRequest, Body(description="Path access info query")
    ],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get access information for a specific path."""
    app_state = get_app_state(request)

    result = await app_state.sharing_manager.get_path_access_info(
        path=request_data.path
    )

    response_data = PathAccessResponse(
        path=request_data.path,
        users=result.users,
        groups=result.groups,
        public=result.public,
    )

    logger.info(
        f"User {authenticated_user.user} queried policies for {request_data.path}"
    )
    return response_data
