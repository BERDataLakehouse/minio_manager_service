"""Tests for the KBaseUserProfileClient class."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.minio.clients.kbase_profile_client import KBaseUserProfileClient


# ── Helper ───────────────────────────────────────────────────────────────


class AsyncCM:
    """Async context manager wrapper for mocks."""

    def __init__(self, value):
        self._value = value

    async def __aenter__(self):
        return self._value

    async def __aexit__(self, *args):
        pass


def _mock_aiohttp_session(resp):
    """Build a mock that satisfies `async with aiohttp.ClientSession() as session:`."""
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=AsyncCM(resp))
    # ClientSession() returns an object used as `async with ... as session:`
    return AsyncCM(mock_session)


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def mock_pool():
    pool = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()

    class MockConnectionCM:
        async def __aenter__(self):
            return mock_conn

        async def __aexit__(self, *args):
            pass

    pool.connection = MockConnectionCM
    pool._mock_conn = mock_conn
    return pool


@pytest.fixture
def client(mock_pool):
    return KBaseUserProfileClient("http://auth:5000/", pool=mock_pool)


# ── Constructor ──────────────────────────────────────────────────────────


class TestInit:
    def test_strips_trailing_slash(self, mock_pool):
        c = KBaseUserProfileClient("http://auth:5000/", pool=mock_pool)
        assert c._auth_url == "http://auth:5000"
        assert c._users_url == "http://auth:5000/api/V2/users/"

    def test_no_trailing_slash(self, mock_pool):
        c = KBaseUserProfileClient("http://auth:5000", pool=mock_pool)
        assert c._auth_url == "http://auth:5000"


# ── get_user_profiles ────────────────────────────────────────────────────


class TestGetUserProfiles:
    @pytest.mark.asyncio
    async def test_empty_input_returns_empty(self, client):
        result = await client.get_user_profiles([], "token")
        assert result == {}

    @pytest.mark.asyncio
    async def test_merges_display_and_email(self, client, mock_pool):
        # Mock email fetch from DB
        email_rows = [("alice", "alice@org.com")]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=email_rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        # Mock KBase Auth HTTP call
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={"alice": "Alice Smith"})

        with patch(
            "src.minio.clients.kbase_profile_client.aiohttp.ClientSession",
            return_value=_mock_aiohttp_session(mock_resp),
        ):
            result = await client.get_user_profiles(["alice"], "token")

        assert result["alice"].display_name == "Alice Smith"
        assert result["alice"].email == "alice@org.com"

    @pytest.mark.asyncio
    async def test_uses_cache_on_second_call(self, client, mock_pool):
        # Seed cache — LRUCache uses .set(), not [] assignment
        client._display_cache.set("alice", "Alice Smith")

        email_rows = [("alice", "alice@org.com")]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=email_rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        # No HTTP call should be made since alice is cached
        with patch(
            "src.minio.clients.kbase_profile_client.aiohttp.ClientSession"
        ) as mock_cls:
            result = await client.get_user_profiles(["alice"], "token")
            mock_cls.assert_not_called()

        assert result["alice"].display_name == "Alice Smith"

    @pytest.mark.asyncio
    async def test_missing_user_gets_none_values(self, client, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=[])
        mock_pool._mock_conn.execute.return_value = mock_cursor

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={})

        with patch(
            "src.minio.clients.kbase_profile_client.aiohttp.ClientSession",
            return_value=_mock_aiohttp_session(mock_resp),
        ):
            result = await client.get_user_profiles(["unknown"], "token")

        assert result["unknown"].display_name is None
        assert result["unknown"].email is None


# ── _fetch_display_names ─────────────────────────────────────────────────


class TestFetchDisplayNames:
    @pytest.mark.asyncio
    async def test_populates_cache_on_success(self, client):
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={"alice": "Alice S", "bob": "Bob J"})

        with patch(
            "src.minio.clients.kbase_profile_client.aiohttp.ClientSession",
            return_value=_mock_aiohttp_session(mock_resp),
        ):
            await client._fetch_display_names(["alice", "bob"], "token")

        assert client._display_cache.get("alice") == "Alice S"
        assert client._display_cache.get("bob") == "Bob J"

    @pytest.mark.asyncio
    async def test_non_200_logs_warning(self, client):
        mock_resp = AsyncMock()
        mock_resp.status = 500

        with patch(
            "src.minio.clients.kbase_profile_client.aiohttp.ClientSession",
            return_value=_mock_aiohttp_session(mock_resp),
        ):
            await client._fetch_display_names(["alice"], "token")

        assert client._display_cache.get("alice") is None

    @pytest.mark.asyncio
    async def test_exception_is_swallowed(self, client):
        with patch(
            "src.minio.clients.kbase_profile_client.aiohttp.ClientSession",
            side_effect=Exception("Network error"),
        ):
            await client._fetch_display_names(["alice"], "token")
        # Should not raise


# ── _fetch_emails ────────────────────────────────────────────────────────


class TestFetchEmails:
    @pytest.mark.asyncio
    async def test_returns_email_map(self, client, mock_pool):
        rows = [("alice", "alice@org.com"), ("bob", None)]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await client._fetch_emails(["alice", "bob"])
        assert result["alice"] == "alice@org.com"
        assert result["bob"] is None
