"""
Credential Management Routes for the BERDL Data Governance API.

Primary JupyterHub integration. Each call returns a unified bundle of S3
IAM credentials AND Polaris OAuth credentials. Both per-backend services
self-bootstrap their underlying identity on cache miss, so the route is a
two-line orchestration: fetch S3 creds, fetch Polaris creds.

Catalog metadata (personal_catalog, tenant_catalogs) is intentionally
NOT in the response — fetch it from ``GET /polaris/effective-access/me``
to keep this endpoint focused on credential material.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from credentials.polaris_store import PolarisCredentialRecord
from service.app_state import get_app_state
from service.dependencies import auth
from service.kb_auth import KBaseUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["credentials"])


# ===== RESPONSE MODEL =====


class CredentialsResponse(BaseModel):
    """Combined S3 IAM + Polaris OAuth credential bundle."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    # S3 IAM
    s3_access_key: Annotated[str, Field(description="S3 access key (same as username)")]
    s3_secret_key: Annotated[str, Field(description="S3 secret key", min_length=8)]
    # Polaris OAuth
    polaris_client_id: Annotated[
        str, Field(description="Polaris OAuth client ID", min_length=1)
    ]
    polaris_client_secret: Annotated[
        str, Field(description="Polaris OAuth client secret", min_length=1)
    ]


# ===== HELPER =====


def _to_response(
    username: str,
    s3_access_key: str,
    s3_secret_key: str,
    polaris_record: PolarisCredentialRecord,
) -> CredentialsResponse:
    return CredentialsResponse(
        username=username,
        s3_access_key=s3_access_key,
        s3_secret_key=s3_secret_key,  # type: ignore
        polaris_client_id=polaris_record.client_id,
        polaris_client_secret=polaris_record.client_secret,
    )


# ===== ROUTES =====


@router.get(
    "/",
    response_model=CredentialsResponse,
    summary="Get S3 + Polaris credentials",
    description=(
        "Returns cached S3 and Polaris credentials for the authenticated "
        "user. Both per-backend services self-bootstrap their identity on "
        "first access (S3: creates the MinIO user + joins default groups + "
        "attaches policies; Polaris: provisions the personal catalog + "
        "principal + admin role). Subsequent calls return the same "
        "credentials until explicitly rotated."
    ),
)
async def get_credentials(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Cache-first on both backends; bootstraps each on miss."""
    app_state = get_app_state(request)
    username = authenticated_user.user

    s3_access_key, s3_secret_key = await app_state.s3_credential_service.get_or_create(
        username
    )
    polaris_record = await app_state.polaris_credential_service.get_or_create(username)

    return _to_response(username, s3_access_key, s3_secret_key, polaris_record)


@router.post(
    "/rotate",
    response_model=CredentialsResponse,
    summary="Rotate S3 + Polaris credentials",
    description=(
        "Force-rotates S3 and Polaris credentials for the authenticated "
        "user. Each backend invalidates its cache, mints a new secret, and "
        "stores the new value. Both services self-bootstrap the underlying "
        "identity if it doesn't exist yet, so an admin can rotate a user "
        "that was created before either backend was integrated."
    ),
)
async def rotate_credentials(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Force-rotate both backends."""
    app_state = get_app_state(request)
    username = authenticated_user.user

    s3_access_key, s3_secret_key = await app_state.s3_credential_service.rotate(
        username
    )
    polaris_record = await app_state.polaris_credential_service.rotate(username)

    return _to_response(username, s3_access_key, s3_secret_key, polaris_record)
