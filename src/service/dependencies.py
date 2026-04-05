"""
Dependencies for FastAPI dependency injection.
"""

import logging

from fastapi import Depends, HTTPException, Request, status

from service.app_state import get_app_state
from service.http_bearer import KBaseHTTPBearer
from service.kb_auth import AdminPermission, KBaseUser

logger = logging.getLogger(__name__)

# Initialize the KBase auth dependency for use in routes
auth = KBaseHTTPBearer()


def require_admin(user: KBaseUser = Depends(auth)) -> KBaseUser:
    """Dependency to ensure user has admin permissions."""
    if user.admin_perm != AdminPermission.FULL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required for this operation",
        )
    return user


async def require_steward_or_admin(
    tenant_name: str,
    request: Request,
    user: KBaseUser,
) -> None:
    """Raise 403 if user is neither admin nor steward of the given tenant.

    This is a helper called explicitly in route handlers (not via Depends)
    since it requires both a path parameter and app state.
    """
    if user.admin_perm == AdminPermission.FULL:
        return
    app_state = get_app_state(request)
    if await app_state.tenant_manager.metadata_store.is_steward(tenant_name, user.user):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Requires admin or steward role for tenant '{tenant_name}'",
    )
