"""Tests for the UserProfileStore class."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from tenant_metadata.user_profile_store import UserProfileStore


@pytest.fixture
def mock_pool():
    pool = MagicMock()
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
    return UserProfileStore(pool=mock_pool)


class TestUpsert:
    @pytest.mark.asyncio
    async def test_upsert_executes_and_commits(self, store, mock_pool):
        await store.upsert("alice", "Alice Smith", "alice@org.com")
        mock_pool._mock_conn.execute.assert_called_once()
        mock_pool._mock_conn.commit.assert_called_once()

        params = mock_pool._mock_conn.execute.call_args[0][1]
        assert params["username"] == "alice"
        assert params["display_name"] == "Alice Smith"
        assert params["email"] == "alice@org.com"

    @pytest.mark.asyncio
    async def test_upsert_with_none_values(self, store, mock_pool):
        await store.upsert("alice", None, None)
        params = mock_pool._mock_conn.execute.call_args[0][1]
        assert params["display_name"] is None
        assert params["email"] is None


class TestGetProfiles:
    @pytest.mark.asyncio
    async def test_returns_dict(self, store, mock_pool):
        rows = [
            ("alice", "Alice Smith", "alice@org.com"),
            ("bob", "Bob Jones", None),
        ]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_profiles(["alice", "bob"])
        assert result["alice"] == ("Alice Smith", "alice@org.com")
        assert result["bob"] == ("Bob Jones", None)

    @pytest.mark.asyncio
    async def test_returns_empty_for_empty_input(self, store, mock_pool):
        result = await store.get_profiles([])
        assert result == {}
        mock_pool._mock_conn.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_matches(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=[])
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_profiles(["unknown"])
        assert result == {}


class TestGetEmail:
    @pytest.mark.asyncio
    async def test_returns_email(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=("Alice Smith", "alice@org.com"))
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_email("alice")
        assert result == "alice@org.com"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_email("unknown")
        assert result is None
