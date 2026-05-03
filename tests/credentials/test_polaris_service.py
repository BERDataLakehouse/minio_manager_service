"""Tests for PolarisCredentialService."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from credentials.polaris_service import PolarisCredentialService
from credentials.polaris_store import PolarisCredentialRecord
from service.exceptions import PolarisOperationError


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
    store.close = AsyncMock()
    return store


@pytest.fixture
def lock_calls():
    """Per-test list capturing the (lock_key, timeout) tuples passed to the lock."""
    return []


@pytest.fixture
def mock_lock_manager(lock_calls):
    """Create a mock DistributedLockManager whose lock records its keys."""

    @asynccontextmanager
    async def credential_lock(lock_key, timeout=None):
        lock_calls.append((lock_key, timeout))
        yield MagicMock()

    manager = MagicMock()
    manager.credential_lock = credential_lock
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
    async def test_no_lock_acquired_on_cache_hit(self, service, mock_store, lock_calls):
        """Test fast path: cache hit must NOT acquire the distributed lock."""
        mock_store.get_credentials.return_value = PolarisCredentialRecord(
            client_id="cached-id",
            client_secret="cached-secret",
            personal_catalog="user_testuser",
        )

        await service.get_or_create("testuser", "user_testuser")

        assert lock_calls == []

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
    async def test_cache_miss_acquires_namespaced_lock(self, service, lock_calls):
        """Test the lock key is namespaced with the 'polaris:' prefix.

        The MinIO CredentialService locks on plain ``{username}``; without the
        ``polaris:`` prefix the two would share a Redis key and serialize each
        other unnecessarily. Asserting the prefix here prevents regressions.
        """
        await service.get_or_create("alice", "user_alice")

        assert lock_calls == [("polaris:alice", None)]

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
    async def test_rotate_acquires_namespaced_lock(self, service, lock_calls):
        """Test rotate locks on the polaris-prefixed key."""
        await service.rotate("alice", "user_alice")

        assert lock_calls == [("polaris:alice", None)]

    @pytest.mark.asyncio
    async def test_missing_credentials_raises_polaris_error(
        self, service, mock_polaris_service, mock_store
    ):
        """Test a malformed Polaris reset response raises PolarisOperationError.

        The store must NOT be written when Polaris returns garbage.
        """
        mock_polaris_service.reset_principal_credentials.return_value = {
            "credentials": {}
        }

        with pytest.raises(PolarisOperationError, match="Polaris did not return"):
            await service.rotate("testuser", "user_testuser")

        mock_store.store_credentials.assert_not_called()


class TestPolarisCredentialServiceDelete:
    """Tests for delete_credentials."""

    @pytest.mark.asyncio
    async def test_delete_credentials_uses_lock(self, service, mock_store):
        """Test cached credentials are deleted under the per-user lock."""
        await service.delete_credentials("testuser")

        mock_store.delete_credentials.assert_called_once_with("testuser")

    @pytest.mark.asyncio
    async def test_delete_acquires_namespaced_lock(self, service, lock_calls):
        """Test delete_credentials locks on the polaris-prefixed key."""
        await service.delete_credentials("alice")

        assert lock_calls == [("polaris:alice", None)]


class TestPolarisCredentialServiceClose:
    """Tests for close."""

    @pytest.mark.asyncio
    async def test_close_delegates_to_store(self, service, mock_store):
        """Test close() forwards to the underlying credential store."""
        await service.close()

        mock_store.close.assert_called_once_with()
