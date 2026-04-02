"""
Credential coordination service.

Encapsulates the lock → cache → S3 → store workflow so that credential
routes (user-facing and management) are thin one-liner callers.
"""

import logging

from src.s3.core.distributed_lock import DistributedLockManager
from ..minio.managers.user_manager import UserManager
from .store import CredentialStore

logger = logging.getLogger(__name__)


class CredentialService:
    """Coordinates distributed locking, S3 operations, and DB caching for credentials."""

    def __init__(
        self,
        user_manager: UserManager,
        credential_store: CredentialStore,
        lock_manager: DistributedLockManager,
    ) -> None:
        self._user_manager = user_manager
        self._credential_store = credential_store
        self._lock_manager = lock_manager

    async def get_or_create(self, username: str) -> tuple[str, str]:
        """
        Return cached credentials or create new ones (cache-first with distributed lock).

        Flow:
        1. Fast path: return from DB cache without locking.
        2. Cache miss: acquire lock → double-check cache → create/rotate in S3 → store.

        Returns:
            (access_key, secret_key)
        """
        # Fast path — no lock needed
        cached = await self._credential_store.get_credentials(username)
        if cached is not None:
            logger.info(f"Returning cached credentials for user {username}")
            return cached

        # Slow path — lock, double-check, create
        async with self._lock_manager.credential_lock(username):
            cached = await self._credential_store.get_credentials(username)
            if cached is not None:
                logger.info(
                    f"Returning cached credentials for user {username} (post-lock)"
                )
                return cached

            access_key, secret_key = await self._ensure_and_rotate(username)
            await self._credential_store.store_credentials(
                username, access_key, secret_key
            )
            logger.info(f"Issued and cached new credentials for user {username}")
            return access_key, secret_key

    async def rotate(self, username: str) -> tuple[str, str]:
        """
        Force-rotate credentials: delete stale cache, rotate in S3, store new ones.

        Returns:
            (access_key, secret_key)
        """
        async with self._lock_manager.credential_lock(username):
            # Delete first so a partial failure doesn't leave stale creds
            await self._credential_store.delete_credentials(username)

            access_key, secret_key = await self._ensure_and_rotate(username)
            await self._credential_store.store_credentials(
                username, access_key, secret_key
            )
            logger.info(f"Rotated and cached new credentials for user {username}")
            return access_key, secret_key

    async def _ensure_and_rotate(self, username: str) -> tuple[str, str]:
        """Create the user if needed, then return fresh credentials."""
        user_exists = await self._user_manager.resource_exists(username)
        if not user_exists:
            logger.info(f"Auto-creating user {username} for credential request")
            user_model = await self._user_manager.create_user(username=username)
            return user_model.access_key, user_model.secret_key
        return await self._user_manager.get_or_rotate_user_credentials(username)

    async def delete_credentials(self, username: str) -> None:
        """Delete cached credentials for a user (e.g. on user deletion)."""
        async with self._lock_manager.credential_lock(username):
            await self._credential_store.delete_credentials(username)

    async def close(self) -> None:
        """Close the underlying credential store connection pool."""
        await self._credential_store.close()
