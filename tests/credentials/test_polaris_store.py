"""Tests for the PolarisCredentialStore class."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from credentials.polaris_store import PolarisCredentialRecord, PolarisCredentialStore


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
    return PolarisCredentialStore(
        rw=mock_pool, ro=mock_pool, encryption_key="test-encryption-key"
    )


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


class TestPolarisCredentialStoreHealthCheck:
    """Tests for health_check."""

    @pytest.mark.asyncio
    async def test_health_check_returns_true_on_success(self, store):
        """Test health_check returns True when SELECT 1 succeeds."""
        result = await store.health_check()
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_returns_false_on_error(self, store, mock_pool):
        """Test health_check returns False when the connection raises."""
        mock_pool._mock_conn.execute.side_effect = Exception("Connection refused")

        result = await store.health_check()
        assert result is False


class TestPolarisCredentialStoreClose:
    """Tests for close."""

    @pytest.mark.asyncio
    async def test_close_is_noop(self, store, mock_pool):
        """Test close() does not close the shared pool (DatabasePool owns it)."""
        await store.close()
        mock_pool.close.assert_not_called()


# ── Pool selection (rw vs ro routing) ─────────────────────────────────────


def _tracked_pool(*, fetchone=None):
    cur = AsyncMock()
    cur.fetchone = AsyncMock(return_value=fetchone)
    cur.rowcount = 0

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
    """Lock down which pool each PolarisCredentialStore method routes to."""

    @pytest.fixture
    def store(self):
        self.rw = _tracked_pool()
        self.ro = _tracked_pool()
        return PolarisCredentialStore(rw=self.rw, ro=self.ro, encryption_key="k")

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
        await store.store_credentials("u", "cid", "csec", "user_u")
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
