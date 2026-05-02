"""Polaris credential coordination service."""

import logging
from typing import Any, Protocol

from polaris.credential_store import PolarisCredentialRecord, PolarisCredentialStore
from s3.core.distributed_lock import DistributedLockManager
from service.exceptions import PolarisOperationError

logger = logging.getLogger(__name__)

# Lock-key prefix used with DistributedLockManager.credential_lock so that
# Polaris credential locks (Redis key "credential_lock:polaris:<user>") don't
# collide with MinIO credential locks (Redis key "credential_lock:<user>") for
# the same username. Tests assert this prefix to prevent accidental removal.
_LOCK_KEY_PREFIX = "polaris:"


class PolarisCredentialIssuer(Protocol):
    """Minimal Polaris client surface needed to issue principal credentials."""

    async def reset_principal_credentials(self, name: str) -> dict[str, Any]:
        """Reset and return credentials for a Polaris principal."""


class PolarisCredentialService:
    """Coordinates Polaris principal credential caching and explicit rotation."""

    def __init__(
        self,
        polaris_service: PolarisCredentialIssuer,
        credential_store: PolarisCredentialStore,
        lock_manager: DistributedLockManager,
    ) -> None:
        self._polaris_service = polaris_service
        self._credential_store = credential_store
        self._lock_manager = lock_manager

    async def get_or_create(
        self, username: str, personal_catalog: str
    ) -> PolarisCredentialRecord:
        """Return cached credentials or create them once for the Polaris principal."""
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

            record = await self._reset_and_store(username, personal_catalog)
            logger.info("Issued and cached Polaris credentials for user %s", username)
            return record

    async def rotate(
        self, username: str, personal_catalog: str
    ) -> PolarisCredentialRecord:
        """Explicitly rotate Polaris principal credentials and update the cache."""
        async with self._lock_manager.credential_lock(f"{_LOCK_KEY_PREFIX}{username}"):
            # Delete first so a partial failure (e.g., Polaris reset succeeds
            # but the DB write fails) leaves no stale cache row behind.
            await self._credential_store.delete_credentials(username)
            record = await self._reset_and_store(username, personal_catalog)
            logger.info("Rotated and cached Polaris credentials for user %s", username)
            return record

    async def delete_credentials(self, username: str) -> None:
        """Delete cached Polaris credentials for a user."""
        async with self._lock_manager.credential_lock(f"{_LOCK_KEY_PREFIX}{username}"):
            await self._credential_store.delete_credentials(username)

    async def close(self) -> None:
        """Close the underlying credential store connection pool."""
        await self._credential_store.close()

    async def _reset_and_store(
        self, username: str, personal_catalog: str
    ) -> PolarisCredentialRecord:
        """Reset credentials in Polaris, then persist them encrypted.

        Failure mode: if the Polaris reset succeeds but ``store_credentials``
        fails (e.g., DB outage), the issued client_secret is lost — Polaris
        only returns the secret material on the reset call. The next
        ``get_or_create`` will simply trigger another reset, so the cache is
        self-healing at the cost of one extra rotation.
        """
        creds = await self._polaris_service.reset_principal_credentials(name=username)
        credential_data = creds.get("credentials", {})
        client_id = credential_data.get("clientId")
        client_secret = credential_data.get("clientSecret")
        if not client_id or not client_secret:
            raise PolarisOperationError(
                f"Polaris did not return client credentials for user '{username}'"
            )

        await self._credential_store.store_credentials(
            username=username,
            client_id=client_id,
            client_secret=client_secret,
            personal_catalog=personal_catalog,
        )
        return PolarisCredentialRecord(
            client_id=client_id,
            client_secret=client_secret,
            personal_catalog=personal_catalog,
        )
