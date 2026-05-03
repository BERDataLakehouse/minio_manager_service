"""
Polaris credential coordination service.

Mirrors :class:`S3CredentialService` in shape: cache-first on the fast
path, distributed lock + double-check on the slow path, self-bootstraps
the underlying identity (Polaris principal + personal catalog + role
bindings) the same way S3's service auto-creates a missing MinIO user
on cache miss.

Caller surface:
    await get_or_create(username) -> PolarisCredentialRecord
    await rotate(username) -> PolarisCredentialRecord
    await delete_credentials(username) -> None
    await close() -> None

The personal catalog name is derived from ``username`` via
:func:`personal_catalog_name`, so callers don't need to pass it.
"""

import logging

from credentials.polaris_store import PolarisCredentialRecord, PolarisCredentialStore
from polaris.constants import personal_catalog_name
from polaris.managers.user_manager import PolarisUserManager
from s3.core.distributed_lock import DistributedLockManager
from service.exceptions import PolarisOperationError

logger = logging.getLogger(__name__)

# Lock-key prefix used with DistributedLockManager.credential_lock so that
# Polaris credential locks (Redis key "credential_lock:polaris:<user>") don't
# collide with MinIO credential locks (Redis key "credential_lock:<user>") for
# the same username. Tests assert this prefix to prevent accidental removal.
_LOCK_KEY_PREFIX = "polaris:"


class PolarisCredentialService:
    """Coordinates Polaris principal credential caching and explicit rotation."""

    def __init__(
        self,
        polaris_user_manager: PolarisUserManager,
        credential_store: PolarisCredentialStore,
        lock_manager: DistributedLockManager,
    ) -> None:
        self._polaris_user_manager = polaris_user_manager
        self._credential_store = credential_store
        self._lock_manager = lock_manager

    async def get_or_create(self, username: str) -> PolarisCredentialRecord:
        """Return cached credentials or bootstrap + issue them on cache miss.

        Mirrors :meth:`S3CredentialService.get_or_create`: the underlying
        Polaris identity (principal, personal catalog, ``catalog_admin``
        role, ``{username}_role`` principal-role binding) is provisioned
        on cache miss before the credential reset runs.
        """
        # Fast path: cache hit returns without acquiring the distributed lock.
        cached = await self._credential_store.get_credentials(username)
        if cached is not None:
            logger.info("Returning cached Polaris credentials for user %s", username)
            return cached

        async with self._lock_manager.credential_lock(f"{_LOCK_KEY_PREFIX}{username}"):
            # Double-check under the lock: another instance may have populated
            # the cache while we waited.
            cached = await self._credential_store.get_credentials(username)
            if cached is not None:
                logger.info(
                    "Returning cached Polaris credentials for user %s (post-lock)",
                    username,
                )
                return cached

            record = await self._ensure_and_reset(username)
            logger.info("Issued and cached Polaris credentials for user %s", username)
            return record

    async def rotate(self, username: str) -> PolarisCredentialRecord:
        """Explicitly rotate Polaris principal credentials and update the cache.

        Self-bootstraps the principal first (idempotent) so an admin
        rotating a user that pre-dates Polaris integration doesn't fail
        with a missing-principal 404.
        """
        async with self._lock_manager.credential_lock(f"{_LOCK_KEY_PREFIX}{username}"):
            # Delete first so a partial failure (e.g., Polaris reset succeeds
            # but the DB write fails) leaves no stale cache row behind.
            await self._credential_store.delete_credentials(username)
            record = await self._ensure_and_reset(username)
            logger.info("Rotated and cached Polaris credentials for user %s", username)
            return record

    async def delete_credentials(self, username: str) -> None:
        """Delete cached Polaris credentials for a user."""
        async with self._lock_manager.credential_lock(f"{_LOCK_KEY_PREFIX}{username}"):
            await self._credential_store.delete_credentials(username)

    async def close(self) -> None:
        """Close the underlying credential store connection pool."""
        await self._credential_store.close()

    async def _ensure_and_reset(self, username: str) -> PolarisCredentialRecord:
        """Bootstrap the principal if missing, reset credentials, persist encrypted.

        Failure mode: if the Polaris reset succeeds but ``store_credentials``
        fails (e.g., DB outage), the issued client_secret is lost — Polaris
        only returns the secret material on the reset call. The next
        ``get_or_create`` will simply trigger another reset, so the cache is
        self-healing at the cost of one extra rotation.
        """
        # Idempotent bootstrap of personal Polaris assets. Mirrors
        # S3CredentialService._ensure_and_rotate calling user_manager.create_user.
        await self._polaris_user_manager.create_user(username)

        creds = await self._polaris_user_manager.reset_credentials(username)
        credential_data = creds.get("credentials", {})
        client_id = credential_data.get("clientId")
        client_secret = credential_data.get("clientSecret")
        if not client_id or not client_secret:
            raise PolarisOperationError(
                f"Polaris did not return client credentials for user '{username}'"
            )

        catalog = personal_catalog_name(username)
        await self._credential_store.store_credentials(
            username=username,
            client_id=client_id,
            client_secret=client_secret,
            personal_catalog=catalog,
        )
        return PolarisCredentialRecord(
            client_id=client_id,
            client_secret=client_secret,
            personal_catalog=catalog,
        )
