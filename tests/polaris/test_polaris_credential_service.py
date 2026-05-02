"""Tests for PolarisCredentialService."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from polaris.credential_service import PolarisCredentialService
from polaris.credential_store import PolarisCredentialRecord


def _make_credential_lock():
    """Create a mock credential_lock async context manager."""

    @asynccontextmanager
    async def credential_lock(username, timeout=None):
        yield MagicMock()

    return credential_lock


@pytest.fixture
def mock_polaris_service():
    """Create a mock Polaris credential issuer."""
    service = AsyncMock()
    service.reset_principal_credentials = AsyncMock(
        return_value={
            "credentials": {
                "clientId": "client-id",
                "clientSecret": "client-secret",
            }
        }
    )
    return service


@pytest.fixture
def mock_store():
    """Create a mock PolarisCredentialStore."""
    store = AsyncMock()
    store.get_credentials = AsyncMock(return_value=None)
    store.store_credentials = AsyncMock()
    store.delete_credentials = AsyncMock()
    return store


@pytest.fixture
def mock_lock_manager():
    """Create a mock DistributedLockManager."""
    manager = MagicMock()
    manager.credential_lock = _make_credential_lock()
    return manager


@pytest.fixture
def service(mock_polaris_service, mock_store, mock_lock_manager):
    """Create a PolarisCredentialService with mocked dependencies."""
    return PolarisCredentialService(
        polaris_service=mock_polaris_service,
        credential_store=mock_store,
        lock_manager=mock_lock_manager,
    )


class TestPolarisCredentialServiceGetOrCreate:
    """Tests for get_or_create."""

    @pytest.mark.asyncio
    async def test_cache_hit_returns_without_reset(
        self, service, mock_store, mock_polaris_service
    ):
        """Test cache hit does not reset Polaris credentials."""
        cached = PolarisCredentialRecord(
            client_id="cached-id",
            client_secret="cached-secret",
            personal_catalog="user_testuser",
        )
        mock_store.get_credentials.return_value = cached

        result = await service.get_or_create("testuser", "user_testuser")

        assert result == cached
        mock_store.get_credentials.assert_called_once_with("testuser")
        mock_polaris_service.reset_principal_credentials.assert_not_called()
        mock_store.store_credentials.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_miss_resets_and_stores(
        self, service, mock_store, mock_polaris_service
    ):
        """Test cache miss resets Polaris credentials and stores them."""
        result = await service.get_or_create("testuser", "user_testuser")

        assert result == PolarisCredentialRecord(
            client_id="client-id",
            client_secret="client-secret",
            personal_catalog="user_testuser",
        )
        mock_polaris_service.reset_principal_credentials.assert_called_once_with(
            name="testuser"
        )
        mock_store.store_credentials.assert_called_once_with(
            username="testuser",
            client_id="client-id",
            client_secret="client-secret",
            personal_catalog="user_testuser",
        )

    @pytest.mark.asyncio
    async def test_post_lock_cache_hit_returns_without_reset(
        self, service, mock_store, mock_polaris_service
    ):
        """Test a concurrent creator can populate the cache while we wait."""
        cached = PolarisCredentialRecord(
            client_id="cached-id",
            client_secret="cached-secret",
            personal_catalog="user_testuser",
        )
        mock_store.get_credentials.side_effect = [None, cached]

        result = await service.get_or_create("testuser", "user_testuser")

        assert result == cached
        assert mock_store.get_credentials.call_count == 2
        mock_polaris_service.reset_principal_credentials.assert_not_called()
        mock_store.store_credentials.assert_not_called()


class TestPolarisCredentialServiceRotate:
    """Tests for rotate."""

    @pytest.mark.asyncio
    async def test_rotate_deletes_resets_and_stores(
        self, service, mock_store, mock_polaris_service
    ):
        """Test rotate deletes cached credentials before resetting."""
        result = await service.rotate("testuser", "user_testuser")

        assert result.client_id == "client-id"
        mock_store.delete_credentials.assert_called_once_with("testuser")
        mock_polaris_service.reset_principal_credentials.assert_called_once_with(
            name="testuser"
        )
        mock_store.store_credentials.assert_called_once()

    @pytest.mark.asyncio
    async def test_missing_credentials_raises(self, service, mock_polaris_service):
        """Test malformed Polaris reset response raises."""
        mock_polaris_service.reset_principal_credentials.return_value = {
            "credentials": {}
        }

        with pytest.raises(RuntimeError, match="Polaris did not return"):
            await service.rotate("testuser", "user_testuser")


class TestPolarisCredentialServiceDelete:
    """Tests for delete_credentials."""

    @pytest.mark.asyncio
    async def test_delete_credentials_uses_lock(self, service, mock_store):
        """Test cached credentials are deleted under the per-user lock."""
        await service.delete_credentials("testuser")

        mock_store.delete_credentials.assert_called_once_with("testuser")
