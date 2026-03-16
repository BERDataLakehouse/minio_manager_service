"""
Application state information and retrieval functions.

All functions assume that the application state has been initialized via
calling the build_app() method.
"""

import asyncio
import logging
import os
from typing import NamedTuple

from fastapi import FastAPI, Request

from src.minio.core.distributed_lock import DistributedLockManager
from src.minio.core.minio_client import MinIOClient
from src.minio.managers.group_manager import GroupManager
from src.minio.managers.policy_manager import PolicyManager
from src.minio.managers.sharing_manager import SharingManager
from src.minio.managers.user_manager import UserManager
from src.minio.models.minio_config import MinIOConfig
from src.polaris.polaris_service import PolarisService
from src.service.arg_checkers import not_falsy
from src.credentials.service import CredentialService
from src.credentials.store import CredentialStore  # used in build_app only
from src.service.kb_auth import KBaseAuth, KBaseUser

logger = logging.getLogger(__name__)


class AppState(NamedTuple):
    """Holds application state."""

    auth: KBaseAuth
    minio_client: MinIOClient
    user_manager: UserManager
    group_manager: GroupManager
    policy_manager: PolicyManager
    sharing_manager: SharingManager
    lock_manager: DistributedLockManager
    polaris_service: PolarisService
    credential_service: CredentialService


class RequestState(NamedTuple):
    """Holds request specific state."""

    user: KBaseUser | None


async def build_app(app: FastAPI) -> None:
    """
    Build the application state.

    Args:
        app: The FastAPI app.
    """
    logger.info("Initializing application state...")

    # Initialize auth with KBase auth URL and admin roles from environment variables
    auth_url = os.environ.get("KBASE_AUTH_URL", "https://ci.kbase.us/services/auth/")
    admin_roles = os.environ.get("KBASE_ADMIN_ROLES", "KBASE_ADMIN").split(",")
    required_roles = os.environ.get("KBASE_REQUIRED_ROLES", "BERDL_USER").split(",")

    logger.info("Connecting to KBase auth service...")
    auth = await KBaseAuth.create(
        auth_url, required_roles=required_roles, full_admin_roles=admin_roles
    )
    logger.info("KBase auth service connected")

    # Initialize MinIO configuration and client
    logger.info("Initializing MinIO client and managers...")
    config = MinIOConfig(
        endpoint=not_falsy(os.getenv("MINIO_ENDPOINT"), "MINIO_ENDPOINT"),
        access_key=not_falsy(os.getenv("MINIO_ROOT_USER"), "MINIO_ROOT_USER"),
        secret_key=not_falsy(os.getenv("MINIO_ROOT_PASSWORD"), "MINIO_ROOT_PASSWORD"),
    )

    minio_client = await MinIOClient.create(config)
    logger.info("MinIO client session initialized")

    # Initialize distributed lock manager
    logger.info("Initializing distributed lock manager...")
    lock_manager = DistributedLockManager()

    # Verify Redis connection
    if not await lock_manager.health_check():
        raise RuntimeError(
            "Failed to connect to Redis. Redis is required for distributed coordination."
        )
    logger.info("Distributed lock manager initialized and Redis connection verified")

    # Initialize Polaris Service
    logger.info("Initializing Polaris Service...")
    polaris_uri = not_falsy(os.getenv("POLARIS_CATALOG_URI"), "POLARIS_CATALOG_URI")
    polaris_cred = not_falsy(os.getenv("POLARIS_CREDENTIAL"), "POLARIS_CREDENTIAL")
    minio_endpoint = str(config.endpoint)
    polaris_service = PolarisService(polaris_uri, polaris_cred, minio_endpoint)
    logger.info("Polaris Service initialized")

    # Initialize credential store
    logger.info("Initializing credential store...")
    credential_store = await CredentialStore.create(
        host=not_falsy(os.getenv("MMS_DB_HOST"), "MMS_DB_HOST"),
        port=int(os.getenv("MMS_DB_PORT", "5432")),
        dbname=not_falsy(os.getenv("MMS_DB_NAME"), "MMS_DB_NAME"),
        user=not_falsy(os.getenv("MMS_DB_USER"), "MMS_DB_USER"),
        password=not_falsy(os.getenv("MMS_DB_PASSWORD"), "MMS_DB_PASSWORD"),
        encryption_key=not_falsy(
            os.getenv("MMS_DB_ENCRYPTION_KEY"), "MMS_DB_ENCRYPTION_KEY"
        ),
    )
    logger.info("Credential store initialized")

    # Initialize all managers with the shared client and polaris hook
    user_manager = UserManager(minio_client, config, polaris_service=polaris_service)
    group_manager = GroupManager(minio_client, config, polaris_service=polaris_service)
    policy_manager = PolicyManager(minio_client, config, lock_manager=lock_manager)
    sharing_manager = SharingManager(
        minio_client,
        config,
        policy_manager=policy_manager,
        user_manager=user_manager,
        group_manager=group_manager,
    )
    logger.info("MinIO managers initialized")

    # Initialize credential service (coordinates lock + MinIO + DB)
    credential_service = CredentialService(
        user_manager=user_manager,
        credential_store=credential_store,
        lock_manager=lock_manager,
    )
    logger.info("Credential service initialized")

    # Store components in app state
    app.state._auth = auth
    app.state._minio_manager_state = AppState(
        auth=auth,
        minio_client=minio_client,
        user_manager=user_manager,
        group_manager=group_manager,
        policy_manager=policy_manager,
        sharing_manager=sharing_manager,
        lock_manager=lock_manager,
        polaris_service=polaris_service,
        credential_service=credential_service,
    )
    logger.info("Application state initialized")


async def destroy_app_state(app: FastAPI) -> None:
    """
    Destroy the application state, shutting down services and releasing resources.

    Args:
        app: The FastAPI app.
    """
    # Close services if they exist
    if hasattr(app.state, "_minio_manager_state") and app.state._minio_manager_state:
        try:
            # Close Redis connection
            await app.state._minio_manager_state.lock_manager.close()
            logger.info("Redis connection closed")
        except Exception as e:
            logger.warning(f"Error closing Redis connection: {e}")

        try:
            # Close MinIO client session
            await app.state._minio_manager_state.minio_client.close_session()
            logger.info("MinIO client session closed")
        except Exception as e:
            logger.warning(f"Error closing MinIO client session: {e}")

        try:
            # Close Polaris HTTP session
            await app.state._minio_manager_state.polaris_service.close()
            logger.info("Polaris HTTP session closed")
        except Exception as e:
            logger.warning(f"Error closing Polaris HTTP session: {e}")

        try:
            # Close credential store connection pool (via credential service)
            await app.state._minio_manager_state.credential_service.close()
            logger.info("Credential store connection pool closed")
        except Exception as e:
            logger.warning(f"Error closing credential store: {e}")

    # https://docs.aiohttp.org/en/stable/client_advanced.html#graceful-shutdown
    await asyncio.sleep(0.250)
    logger.info("Application state destroyed")


def get_app_state(request: Request) -> AppState:
    """
    Get the application state from a request.

    Args:
        request: The FastAPI request.

    Returns:
        The application state.

    Raises:
        ValueError: If app state has not been initialized.
    """
    return _get_app_state_from_app(request.app)


def _get_app_state_from_app(app: FastAPI) -> AppState:
    """
    Get the application state from a FastAPI app.

    Args:
        app: The FastAPI app.

    Returns:
        The application state.

    Raises:
        ValueError: If app state has not been initialized.
    """
    if (
        not hasattr(app.state, "_minio_manager_state")
        or not app.state._minio_manager_state
    ):
        raise ValueError("App state has not been initialized")
    return app.state._minio_manager_state


def set_request_user(request: Request, user: KBaseUser | None) -> None:
    """
    Set the user for the current request.

    Args:
        request: The FastAPI request.
        user: The KBase user.
    """
    request.state._request_state = RequestState(user=user)


def get_request_user(request: Request) -> KBaseUser | None:
    """
    Get the user for a request.

    Args:
        request: The FastAPI request.

    Returns:
        The authenticated KBaseUser if available, otherwise None.
    """
    if not hasattr(request.state, "_request_state") or not request.state._request_state:
        return None
    return request.state._request_state.user
