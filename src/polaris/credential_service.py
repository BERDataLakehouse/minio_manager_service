"""Polaris credential coordination service."""

import logging

from polaris.credential_store import PolarisCredentialRecord, PolarisCredentialStore
from polaris.polaris_service import PolarisService
from s3.core.distributed_lock import DistributedLockManager

logger = logging.getLogger(__name__)


class PolarisCredentialService:
    """Coordinates Polaris principal credential caching and explicit rotation."""

    def __init__(
        self,
        polaris_service: PolarisService,
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
        cached = await self._credential_store.get_credentials(username)
        if cached is not None:
            logger.info("Returning cached Polaris credentials for user %s", username)
            return cached

        async with self._lock_manager.credential_lock(f"polaris:{username}"):
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
        async with self._lock_manager.credential_lock(f"polaris:{username}"):
            await self._credential_store.delete_credentials(username)
            record = await self._reset_and_store(username, personal_catalog)
            logger.info("Rotated and cached Polaris credentials for user %s", username)
            return record

    async def delete_credentials(self, username: str) -> None:
        """Delete cached Polaris credentials for a user."""
        async with self._lock_manager.credential_lock(f"polaris:{username}"):
            await self._credential_store.delete_credentials(username)

    async def _reset_and_store(
        self, username: str, personal_catalog: str
    ) -> PolarisCredentialRecord:
        """Reset credentials in Polaris, then persist them encrypted."""
        creds = await self._polaris_service.reset_principal_credentials(name=username)
        credential_data = creds.get("credentials", {})
        client_id = credential_data.get("clientId")
        client_secret = credential_data.get("clientSecret")
        if not client_id or not client_secret:
            raise RuntimeError("Polaris did not return client credentials")

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
