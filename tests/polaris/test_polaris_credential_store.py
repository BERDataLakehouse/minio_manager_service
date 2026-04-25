"""Tests for the PolarisCredentialStore class."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from polaris.credential_store import PolarisCredentialRecord, PolarisCredentialStore


@pytest.fixture
def mock_pool():
    """Create a mock AsyncConnectionPool."""
    pool = MagicMock()
    pool.close = AsyncMock()

    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.commit = AsyncMock()

    class MockConnectionCM:
        async def __aenter__(self):
            return mock_conn

        async def __aexit__(self, *args):
            pass

    pool.connection = MockConnectionCM
    pool._mock_conn = mock_conn
    return pool


@pytest.fixture
def store(mock_pool):
    """Create a PolarisCredentialStore with a mocked pool."""
    return PolarisCredentialStore(mock_pool, encryption_key="test-encryption-key")


class TestPolarisCredentialStoreGetCredentials:
    """Tests for get_credentials."""

    @pytest.mark.asyncio
    async def test_returns_none_on_miss(self, store, mock_pool):
        """Test returns None when no credentials are cached."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_credentials("testuser")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_record_on_hit(self, store, mock_pool):
        """Test returns a PolarisCredentialRecord on cache hit."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(
            return_value=("client-id", "client-secret", "user_testuser")
        )
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_credentials("testuser")
        assert result == PolarisCredentialRecord(
            client_id="client-id",
            client_secret="client-secret",
            personal_catalog="user_testuser",
        )


class TestPolarisCredentialStoreStoreCredentials:
    """Tests for store_credentials."""

    @pytest.mark.asyncio
    async def test_store_calls_execute_and_commit(self, store, mock_pool):
        """Test store_credentials executes the encrypted upsert and commits."""
        await store.store_credentials(
            "testuser",
            "client-id",
            "client-secret",
            "user_testuser",
        )

        mock_pool._mock_conn.execute.assert_called_once()
        mock_pool._mock_conn.commit.assert_called_once()

        params = mock_pool._mock_conn.execute.call_args[0][1]
        assert params["username"] == "testuser"
        assert params["client_id"] == "client-id"
        assert params["client_secret"] == "client-secret"
        assert params["personal_catalog"] == "user_testuser"
        assert params["enc_key"] == "test-encryption-key"


class TestPolarisCredentialStoreDeleteCredentials:
    """Tests for delete_credentials."""

    @pytest.mark.asyncio
    async def test_delete_calls_execute_and_commit(self, store, mock_pool):
        """Test delete_credentials executes delete and commits."""
        await store.delete_credentials("testuser")

        mock_pool._mock_conn.execute.assert_called_once()
        mock_pool._mock_conn.commit.assert_called_once()

        params = mock_pool._mock_conn.execute.call_args[0][1]
        assert params["username"] == "testuser"
