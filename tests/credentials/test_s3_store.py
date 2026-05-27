"""
Tests for the CredentialStore class.

Since CredentialStore requires a real PostgreSQL connection with pgcrypto,
these tests mock the connection pool to verify the logic without a database.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from credentials.s3_store import S3CredentialStore


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
    return S3CredentialStore(
        rw=mock_pool, ro=mock_pool, encryption_key="test-encryption-key"
    )


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


# ── Pool selection (rw vs ro routing) ─────────────────────────────────────


def _tracked_pool(*, fetchone=None, rowcount=0):
    """Return a mock AsyncConnectionPool whose .connection() call is trackable.

    Distinct from the module's `mock_pool` fixture (which uses a class-level
    context manager) — these tests need to assert `pool.connection.called`,
    which requires connection to be a MagicMock attribute.
    """
    cur = AsyncMock()
    cur.fetchone = AsyncMock(return_value=fetchone)
    cur.rowcount = rowcount

    conn = AsyncMock()
    conn.execute = AsyncMock(return_value=cur)
    conn.commit = AsyncMock()

    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=None)

    pool = MagicMock()
    pool.connection = MagicMock(return_value=cm)
    return pool


class TestPoolSelection:
    """Lock down which pool each S3CredentialStore method routes to.

    Plain reads -> ro. Mutations -> rw. Lock-and-check reads -> rw (because
    replica lag would let two pods generate duplicate credentials).
    """

    @pytest.fixture
    def store(self):
        self.rw = _tracked_pool()
        self.ro = _tracked_pool()
        return S3CredentialStore(rw=self.rw, ro=self.ro, encryption_key="k")

    @pytest.mark.asyncio
    async def test_get_credentials_reads_ro(self, store):
        await store.get_credentials("u")
        assert self.ro.connection.called
        assert not self.rw.connection.called

    @pytest.mark.asyncio
    async def test_get_credentials_for_writer_reads_rw(self, store):
        await store.get_credentials_for_writer("u")
        assert self.rw.connection.called
        assert not self.ro.connection.called

    @pytest.mark.asyncio
    async def test_store_credentials_writes_rw(self, store):
        await store.store_credentials("u", "ak", "sk")
        assert self.rw.connection.called
        assert not self.ro.connection.called

    @pytest.mark.asyncio
    async def test_delete_credentials_writes_rw(self, store):
        await store.delete_credentials("u")
        assert self.rw.connection.called
        assert not self.ro.connection.called

    @pytest.mark.asyncio
    async def test_health_check_pings_rw(self, store):
        await store.health_check()
        assert self.rw.connection.called
        assert not self.ro.connection.called
