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

from credentials.s3_service import S3CredentialService
from credentials.s3_store import S3CredentialStore
from s3.core.distributed_lock import DistributedLockManager
from s3.core.s3_client import S3Client
from s3.core.s3_iam_client import S3IAMClient
from s3.managers.group_manager import GroupManager
from s3.managers.policy_manager import PolicyManager
from s3.managers.sharing_manager import SharingManager
from s3.managers.tenant_manager import TenantManager
from s3.managers.user_manager import UserManager
from s3.models.s3_config import S3Config
from service.arg_checkers import not_falsy
from service.database import DatabasePool, run_migrations
from service.kb_auth import KBaseAuth, KBaseUser
from tenant_metadata.kbase_profile_client import KBaseUserProfileClient
from tenant_metadata.tenant_metadata_store import TenantMetadataStore
from tenant_metadata.user_profile_store import UserProfileStore

logger = logging.getLogger(__name__)


class AppState(NamedTuple):
    """Holds application state."""

    auth: KBaseAuth
    user_manager: UserManager
    group_manager: GroupManager
    policy_manager: PolicyManager
    sharing_manager: SharingManager
    s3_credential_service: S3CredentialService
    tenant_manager: TenantManager
    users_sql_warehouse_base: str
    tenant_sql_warehouse_base: str


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

    # Validate DB env vars *before* running migrations so Alembic never
    # silently falls back to its localhost defaults on a misconfigured env.
    db_host = not_falsy(os.getenv("MMS_DB_HOST"), "MMS_DB_HOST")
    db_port = int(os.getenv("MMS_DB_PORT", "5432"))
    db_name = not_falsy(os.getenv("MMS_DB_NAME"), "MMS_DB_NAME")
    db_user = not_falsy(os.getenv("MMS_DB_USER"), "MMS_DB_USER")
    db_password = not_falsy(os.getenv("MMS_DB_PASSWORD"), "MMS_DB_PASSWORD")

    # Run Alembic migrations (no-op when already at head).
    # Runs in a thread to avoid blocking the async event loop at startup.
    await asyncio.to_thread(run_migrations)

    # Initialize shared database pool (must come before auth for profile capture)
    logger.info("Initializing database pool...")
    db_pool = await DatabasePool.create(
        host=db_host,
        port=db_port,
        dbname=db_name,
        user=db_user,
        password=db_password,
    )
    logger.info("Database pool initialized")

    # Initialize stores backed by the shared pool
    s3_credential_store = S3CredentialStore(
        pool=db_pool.pool,
        encryption_key=not_falsy(
            os.getenv("MMS_DB_ENCRYPTION_KEY"), "MMS_DB_ENCRYPTION_KEY"
        ),
    )
    user_profile_store = UserProfileStore(pool=db_pool.pool)
    tenant_metadata_store = TenantMetadataStore(pool=db_pool.pool)
    logger.info("Database stores initialized")

    # Initialize auth with KBase auth URL and admin roles from environment variables
    auth_url = os.environ.get("KBASE_AUTH_URL", "https://ci.kbase.us/services/auth/")
    admin_roles = os.environ.get("KBASE_ADMIN_ROLES", "KBASE_ADMIN").split(",")
    required_roles = os.environ.get("KBASE_REQUIRED_ROLES", "BERDL_USER").split(",")

    logger.info("Connecting to KBase auth service...")
    auth = await KBaseAuth.create(
        auth_url,
        required_roles=required_roles,
        full_admin_roles=admin_roles,
        profile_store=user_profile_store,
    )
    logger.info("KBase auth service connected")

    # Initialize S3 configuration and client
    logger.info("Initializing S3 client and managers...")
    config = S3Config(
        endpoint=not_falsy(os.getenv("MINIO_ENDPOINT"), "MINIO_ENDPOINT"),
        access_key=not_falsy(os.getenv("MINIO_ROOT_USER"), "MINIO_ROOT_USER"),
        secret_key=not_falsy(os.getenv("MINIO_ROOT_PASSWORD"), "MINIO_ROOT_PASSWORD"),
    )

    s3_client = await S3Client.create(config)
    logger.info("S3 client session initialized")

    iam_client = await S3IAMClient.create(
        endpoint_url=str(config.endpoint),
        access_key=config.access_key,
        secret_key=config.secret_key,
        path_prefix=os.getenv("MMS_IAM_PATH_PREFIX", "/data_governance_service"),
    )
    logger.info("IAM client initialized")

    # Initialize distributed lock manager
    logger.info("Initializing distributed lock manager...")
    lock_manager = DistributedLockManager()

    # Verify Redis connection
    if not await lock_manager.health_check():
        raise RuntimeError(
            "Failed to connect to Redis. Redis is required for distributed coordination."
        )
    logger.info("Distributed lock manager initialized and Redis connection verified")

    # Initialize all managers with the shared clients
    policy_manager = PolicyManager(iam_client, config, lock_manager=lock_manager)
    group_manager = GroupManager(iam_client, s3_client, policy_manager, config)
    user_manager = UserManager(
        iam_client, s3_client, policy_manager, group_manager, config
    )
    sharing_manager = SharingManager(
        policy_manager=policy_manager,
        user_manager=user_manager,
        group_manager=group_manager,
    )
    logger.info("S3 managers initialized")

    # Initialize credential service (coordinates lock + S3 + DB)
    s3_credential_service = S3CredentialService(
        user_manager=user_manager,
        credential_store=s3_credential_store,
        lock_manager=lock_manager,
    )
    logger.info("S3 credential service initialized")

    # Initialize profile client and tenant manager
    profile_client = KBaseUserProfileClient(auth_url, pool=db_pool.pool)
    tenant_manager = TenantManager(
        metadata_store=tenant_metadata_store,
        group_manager=group_manager,
        profile_client=profile_client,
        s3_config=config,
    )
    logger.info("Tenant manager initialized")

    # Store teardown-only resources directly on app state (only accessed in app_state.py)
    app.state._s3_client = s3_client
    app.state._iam_client = iam_client
    app.state._lock_manager = lock_manager
    app.state._db_pool = db_pool

    app.state._minio_manager_state = AppState(
        auth=auth,
        user_manager=user_manager,
        group_manager=group_manager,
        policy_manager=policy_manager,
        sharing_manager=sharing_manager,
        s3_credential_service=s3_credential_service,
        tenant_manager=tenant_manager,
        # ruff is forcing these long lines, yuck
        users_sql_warehouse_base=f"s3a://{config.default_bucket}/{config.users_sql_warehouse_prefix}",
        tenant_sql_warehouse_base=f"s3a://{config.default_bucket}/{config.tenant_sql_warehouse_prefix}",
    )
    logger.info("Application state initialized")


async def destroy_app_state(app: FastAPI) -> None:
    """
    Destroy the application state, shutting down services and releasing resources.

    Args:
        app: The FastAPI app.
    """
    # Close services if they exist
    if hasattr(app.state, "_lock_manager"):
        try:
            # Close Redis connection
            await app.state._lock_manager.close()
            logger.info("Redis connection closed")
        except Exception as e:
            logger.warning(f"Error closing Redis connection: {e}")

    if hasattr(app.state, "_iam_client"):
        try:
            await app.state._iam_client.close()
            logger.info("IAM client closed")
        except Exception as e:
            logger.warning(f"Error closing IAM client: {e}")

    if hasattr(app.state, "_s3_client"):
        try:
            # Close S3 client session
            await app.state._s3_client.close_session()
            logger.info("S3 client session closed")
        except Exception as e:
            logger.warning(f"Error closing S3 client session: {e}")

    if hasattr(app.state, "_db_pool"):
        try:
            # Close shared database pool (covers credential store, profile store, etc.)
            await app.state._db_pool.close()
            logger.info("Database pool closed")
        except Exception as e:
            logger.warning(f"Error closing database pool: {e}")

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
