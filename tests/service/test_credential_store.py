"""
Tests for the CredentialStore class.

Since CredentialStore requires a real PostgreSQL connection with pgcrypto,
these tests mock the connection pool to verify the logic without a database.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.credentials.store import CredentialStore


@pytest.fixture
def mock_pool():
    """Create a mock AsyncConnectionPool."""
    pool = MagicMock()
    pool.open = AsyncMock()
    pool.close = AsyncMock()

    # Mock connection context manager
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
def credential_store(mock_pool):
    """Create a CredentialStore with a mocked pool."""
    return CredentialStore(mock_pool, encryption_key="test-encryption-key")


class TestCredentialStoreGetCredentials:
    """Tests for get_credentials method."""

    @pytest.mark.asyncio
    async def test_returns_none_on_miss(self, credential_store, mock_pool):
        """Test returns None when no credentials are cached."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await credential_store.get_credentials("testuser")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_tuple_on_hit(self, credential_store, mock_pool):
        """Test returns (access_key, secret_key) tuple on cache hit."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=("testuser", "secret123"))
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await credential_store.get_credentials("testuser")
        assert result == ("testuser", "secret123")


class TestCredentialStoreStoreCredentials:
    """Tests for store_credentials method."""

    @pytest.mark.asyncio
    async def test_store_calls_execute_and_commit(self, credential_store, mock_pool):
        """Test store_credentials executes upsert and commits."""
        await credential_store.store_credentials("testuser", "testuser", "secret123")

        mock_pool._mock_conn.execute.assert_called_once()
        mock_pool._mock_conn.commit.assert_called_once()

        # Verify the params include the encryption key
        call_args = mock_pool._mock_conn.execute.call_args
        params = call_args[0][1]
        assert params["username"] == "testuser"
        assert params["access_key"] == "testuser"
        assert params["secret_key"] == "secret123"
        assert params["enc_key"] == "test-encryption-key"


class TestCredentialStoreDeleteCredentials:
    """Tests for delete_credentials method."""

    @pytest.mark.asyncio
    async def test_delete_calls_execute_and_commit(self, credential_store, mock_pool):
        """Test delete_credentials executes delete and commits."""
        await credential_store.delete_credentials("testuser")

        mock_pool._mock_conn.execute.assert_called_once()
        mock_pool._mock_conn.commit.assert_called_once()

        call_args = mock_pool._mock_conn.execute.call_args
        params = call_args[0][1]
        assert params["username"] == "testuser"


class TestCredentialStoreHealthCheck:
    """Tests for health_check method."""

    @pytest.mark.asyncio
    async def test_health_check_returns_true(self, credential_store, mock_pool):
        """Test health_check returns True on success."""
        result = await credential_store.health_check()
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_returns_false_on_error(
        self, credential_store, mock_pool
    ):
        """Test health_check returns False on connection error."""
        mock_pool._mock_conn.execute.side_effect = Exception("Connection refused")
        result = await credential_store.health_check()
        assert result is False


class TestCredentialStoreClose:
    """Tests for close method."""

    @pytest.mark.asyncio
    async def test_close_is_noop(self, credential_store, mock_pool):
        """Test close is a no-op (pool lifecycle managed by DatabasePool)."""
        await credential_store.close()
        mock_pool.close.assert_not_called()
