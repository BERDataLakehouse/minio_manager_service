"""
Credential Management Routes for the MinIO Manager API.

This module provides the primary JupyterHub integration endpoints for credential
management. These are the core endpoints that JupyterHub calls to obtain temporary
MinIO credentials for users.

GET /credentials returns cached credentials from the database, creating the user
and storing credentials on first access. POST /credentials/rotate explicitly
rotates credentials and updates the cache.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from ..service.app_state import get_app_state
from ..service.dependencies import auth
from ..service.kb_auth import KBaseUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["credentials"])


# ===== RESPONSE MODELS =====


class CredentialsResponse(BaseModel):
    """Primary response model for credential operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    access_key: Annotated[str, Field(description="MinIO access key (same as username)")]
    secret_key: Annotated[str, Field(description="MinIO secret key", min_length=8)]


@router.get(
    "/",
    response_model=CredentialsResponse,
    summary="Get MinIO credentials",
    description=(
        "Returns cached MinIO credentials for the authenticated user. "
        "Creates the user and stores credentials on first access. "
        "Subsequent calls return the same credentials until explicitly rotated."
    ),
)
async def get_credentials(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get idempotent MinIO credentials (cache-first with distributed lock)."""
    app_state = get_app_state(request)
    username = authenticated_user.user
    credential_store = app_state.credential_store

    # Fast path: check cache without lock
    cached = await credential_store.get_credentials(username)
    if cached is not None:
        access_key, secret_key = cached
        logger.info(f"Returning cached credentials for user {username}")
        return CredentialsResponse(
            username=username,
            access_key=access_key,
            secret_key=secret_key,  # type: ignore
        )

    # Cache miss — acquire lock, then double-check cache to prevent duplicate work
    async with app_state.lock_manager.credential_lock(username):
        # Double-check: another request may have populated the cache while we waited
        cached = await credential_store.get_credentials(username)
        if cached is not None:
            access_key, secret_key = cached
            logger.info(f"Returning cached credentials for user {username} (post-lock)")
            return CredentialsResponse(
                username=username,
                access_key=access_key,
                secret_key=secret_key,  # type: ignore
            )

        # Create or rotate in MinIO and store
        user_exists = await app_state.user_manager.resource_exists(username)
        if not user_exists:
            logger.info(f"Auto-creating user {username} for credential request")
            user_model = await app_state.user_manager.create_user(username=username)
            access_key, secret_key = user_model.access_key, user_model.secret_key
        else:
            (
                access_key,
                secret_key,
            ) = await app_state.user_manager.get_or_rotate_user_credentials(username)

        await credential_store.store_credentials(username, access_key, secret_key)
        logger.info(f"Issued and cached new credentials for user {username}")

    return CredentialsResponse(
        username=username,
        access_key=access_key,
        secret_key=secret_key,  # type: ignore
    )


@router.post(
    "/rotate",
    response_model=CredentialsResponse,
    summary="Rotate MinIO credentials",
    description=(
        "Explicitly rotates the MinIO credentials for the authenticated user. "
        "Deletes the cached credentials, generates new ones in MinIO, "
        "and stores the new credentials in the cache."
    ),
)
async def rotate_credentials(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Force-rotate MinIO credentials and update cache."""
    app_state = get_app_state(request)
    username = authenticated_user.user
    credential_store = app_state.credential_store

    # Lock the entire rotate operation to prevent concurrent rotations
    async with app_state.lock_manager.credential_lock(username):
        # Clear any cached credentials
        await credential_store.delete_credentials(username)

        # Ensure user exists, then rotate
        user_exists = await app_state.user_manager.resource_exists(username)
        if not user_exists:
            logger.info(f"Auto-creating user {username} for rotate request")
            user_model = await app_state.user_manager.create_user(username=username)
            access_key, secret_key = user_model.access_key, user_model.secret_key
        else:
            (
                access_key,
                secret_key,
            ) = await app_state.user_manager.get_or_rotate_user_credentials(username)

        await credential_store.store_credentials(username, access_key, secret_key)
        logger.info(f"Rotated and cached new credentials for user {username}")

    return CredentialsResponse(
        username=username,
        access_key=access_key,
        secret_key=secret_key,  # type: ignore
    )
