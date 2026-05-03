"""
Credential Management Routes for the BERDL Data Governance API.

The primary JupyterHub integration endpoints. Each call returns a unified
bundle of MinIO IAM credentials AND Polaris OAuth credentials so a notebook
startup script gets everything in one round-trip.

The route layer composes :class:`S3CredentialService` + the
``ensure_user_polaris_state`` workflow + :class:`PolarisCredentialService`
so each backend keeps its own focused service while callers see a single
endpoint.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from polaris.orchestration import ensure_user_polaris_state
from service.app_state import AppState, get_app_state
from service.dependencies import auth
from service.kb_auth import KBaseUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["credentials"])


# ===== RESPONSE MODELS =====


class CredentialsResponse(BaseModel):
    """Combined MinIO + Polaris credential bundle returned by /credentials/*."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    # MinIO IAM
    access_key: Annotated[str, Field(description="MinIO access key (same as username)")]
    secret_key: Annotated[str, Field(description="MinIO secret key", min_length=8)]
    # Polaris OAuth
    polaris_client_id: Annotated[
        str, Field(description="Polaris OAuth client ID", min_length=1)
    ]
    polaris_client_secret: Annotated[
        str, Field(description="Polaris OAuth client secret", min_length=1)
    ]
    personal_catalog: Annotated[
        str, Field(description="The user's personal Iceberg catalog name")
    ]
    tenant_catalogs: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Tenant catalogs the user has access to via group membership. "
                "Each tenant appears at most once."
            ),
        ),
    ]


# ===== HELPERS =====


async def _build_credentials_response(
    username: str, access_key: str, secret_key: str, app_state: AppState
) -> CredentialsResponse:
    """Compose the Polaris portion of the bundle and return the full response.

    Run after the MinIO credentials have already been fetched/rotated. The
    sequence is: ensure Polaris state aligns with current MinIO group
    membership → fetch (or rotate, depending on caller) Polaris creds → wrap.
    """
    catalog, tenant_catalogs = await ensure_user_polaris_state(
        username,
        polaris_user_manager=app_state.polaris_user_manager,
        polaris_group_manager=app_state.polaris_group_manager,
        group_manager=app_state.group_manager,
    )
    polaris_record = await app_state.polaris_credential_service.get_or_create(
        username=username, personal_catalog=catalog
    )
    return CredentialsResponse(
        username=username,
        access_key=access_key,
        secret_key=secret_key,  # type: ignore
        polaris_client_id=polaris_record.client_id,
        polaris_client_secret=polaris_record.client_secret,
        personal_catalog=catalog,
        tenant_catalogs=tenant_catalogs,
    )


async def _build_rotated_credentials_response(
    username: str, access_key: str, secret_key: str, app_state: AppState
) -> CredentialsResponse:
    """Same as :func:`_build_credentials_response` but rotates Polaris creds."""
    catalog, tenant_catalogs = await ensure_user_polaris_state(
        username,
        polaris_user_manager=app_state.polaris_user_manager,
        polaris_group_manager=app_state.polaris_group_manager,
        group_manager=app_state.group_manager,
    )
    polaris_record = await app_state.polaris_credential_service.rotate(
        username=username, personal_catalog=catalog
    )
    return CredentialsResponse(
        username=username,
        access_key=access_key,
        secret_key=secret_key,  # type: ignore
        polaris_client_id=polaris_record.client_id,
        polaris_client_secret=polaris_record.client_secret,
        personal_catalog=catalog,
        tenant_catalogs=tenant_catalogs,
    )


# ===== ROUTES =====


@router.get(
    "/",
    response_model=CredentialsResponse,
    summary="Get MinIO + Polaris credentials",
    description=(
        "Returns cached MinIO and Polaris credentials for the authenticated "
        "user. Provisions both identities on first access (creates the MinIO "
        "user, joins default groups, materialises the personal Polaris "
        "catalog/principal/role bindings, and mirrors the current MinIO "
        "group memberships into Polaris). Subsequent calls return the same "
        "credentials until explicitly rotated."
    ),
)
async def get_credentials(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Idempotent: full MinIO + Polaris bundle, cache-first on both backends."""
    app_state = get_app_state(request)
    username = authenticated_user.user

    access_key, secret_key = await app_state.s3_credential_service.get_or_create(
        username
    )
    return await _build_credentials_response(
        username, access_key, secret_key, app_state
    )


@router.post(
    "/rotate",
    response_model=CredentialsResponse,
    summary="Rotate MinIO + Polaris credentials",
    description=(
        "Force-rotates MinIO and Polaris credentials for the authenticated "
        "user. Both backends invalidate their cache, mint new secrets, and "
        "store the new values. Polaris state (catalog/principal/role "
        "bindings) is re-synced against current MinIO group membership too "
        "— catches drift since the last rotation."
    ),
)
async def rotate_credentials(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Force-rotate both backends and refresh Polaris state."""
    app_state = get_app_state(request)
    username = authenticated_user.user

    access_key, secret_key = await app_state.s3_credential_service.rotate(username)
    return await _build_rotated_credentials_response(
        username, access_key, secret_key, app_state
    )
