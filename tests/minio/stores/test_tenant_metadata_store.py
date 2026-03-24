"""Tests for the TenantMetadataStore class."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.minio.stores.tenant_metadata_store import (
    TenantMetadataStore,
    _row_to_metadata,
    _row_to_steward,
)


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def mock_pool():
    """Create a mock AsyncConnectionPool with context-manager connection."""
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
    return TenantMetadataStore(pool=mock_pool)


# ── Helper function tests ────────────────────────────────────────────────


class TestHelpers:
    def test_row_to_metadata(self):
        row = ("t1", "T1", "desc", "org", "admin", "2024-01-01", "2024-01-02", None)
        result = _row_to_metadata(row)
        assert result["tenant_name"] == "t1"
        assert result["display_name"] == "T1"
        assert result["description"] == "desc"
        assert result["organization"] == "org"
        assert result["created_by"] == "admin"
        assert result["updated_by"] is None

    def test_row_to_steward(self):
        row = ("t1", "alice", "admin", "2024-01-01")
        result = _row_to_steward(row)
        assert result["tenant_name"] == "t1"
        assert result["username"] == "alice"
        assert result["assigned_by"] == "admin"


# ── Metadata CRUD ────────────────────────────────────────────────────────


class TestCreateMetadata:
    @pytest.mark.asyncio
    async def test_create_returns_dict(self, store, mock_pool):
        row = ("t1", "t1", None, None, "admin", "2024-01-01", "2024-01-01", None)
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=row)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.create_metadata("t1", "admin")
        assert result["tenant_name"] == "t1"
        assert result["created_by"] == "admin"
        mock_pool._mock_conn.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_returns_none_on_conflict(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.create_metadata("t1", "admin")
        assert result is None

    @pytest.mark.asyncio
    async def test_create_with_optional_fields(self, store, mock_pool):
        row = (
            "t1",
            "Display",
            "Desc",
            "Org",
            "admin",
            "2024-01-01",
            "2024-01-01",
            None,
        )
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=row)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.create_metadata(
            "t1",
            "admin",
            display_name="Display",
            description="Desc",
            organization="Org",
        )
        assert result["display_name"] == "Display"
        assert result["description"] == "Desc"
        assert result["organization"] == "Org"


class TestGetMetadata:
    @pytest.mark.asyncio
    async def test_get_returns_dict(self, store, mock_pool):
        row = ("t1", "T1", "desc", None, "admin", "2024-01-01", "2024-01-01", None)
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=row)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_metadata("t1")
        assert result["tenant_name"] == "t1"

    @pytest.mark.asyncio
    async def test_get_returns_none_when_not_found(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_metadata("nonexistent")
        assert result is None


class TestUpdateMetadata:
    @pytest.mark.asyncio
    async def test_update_returns_dict(self, store, mock_pool):
        row = (
            "t1",
            "New Name",
            "desc",
            None,
            "admin",
            "2024-01-01",
            "2024-01-02",
            "steward",
        )
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=row)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.update_metadata("t1", "steward", display_name="New Name")
        assert result["display_name"] == "New Name"
        assert result["updated_by"] == "steward"
        mock_pool._mock_conn.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_returns_none_when_not_found(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.update_metadata("nonexistent", "admin")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_includes_all_provided_fields(self, store, mock_pool):
        row = ("t1", "N", "D", "O", "admin", "2024-01-01", "2024-01-02", "user")
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=row)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        await store.update_metadata(
            "t1", "user", display_name="N", description="D", organization="O"
        )
        sql_arg = mock_pool._mock_conn.execute.call_args[0][0]
        assert "display_name" in sql_arg
        assert "description" in sql_arg
        assert "organization" in sql_arg


class TestDeleteMetadata:
    @pytest.mark.asyncio
    async def test_delete_returns_true(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.rowcount = 1
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.delete_metadata("t1")
        assert result is True
        mock_pool._mock_conn.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_returns_false_when_not_found(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.rowcount = 0
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.delete_metadata("nonexistent")
        assert result is False


class TestListMetadata:
    @pytest.mark.asyncio
    async def test_list_returns_all(self, store, mock_pool):
        rows = [
            ("t1", "T1", None, None, "admin", "2024-01-01", "2024-01-01", None),
            ("t2", "T2", "desc", None, "admin", "2024-01-01", "2024-01-01", None),
        ]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.list_metadata()
        assert len(result) == 2
        assert result[0]["tenant_name"] == "t1"
        assert result[1]["tenant_name"] == "t2"

    @pytest.mark.asyncio
    async def test_list_returns_empty(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=[])
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.list_metadata()
        assert result == []


# ── Steward operations ───────────────────────────────────────────────────


class TestAddSteward:
    @pytest.mark.asyncio
    async def test_add_returns_dict(self, store, mock_pool):
        row = ("t1", "alice", "admin", "2024-01-01")
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=row)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.add_steward("t1", "alice", "admin")
        assert result["username"] == "alice"
        assert result["assigned_by"] == "admin"
        mock_pool._mock_conn.commit.assert_called_once()


class TestRemoveSteward:
    @pytest.mark.asyncio
    async def test_remove_returns_true(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.rowcount = 1
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.remove_steward("t1", "alice")
        assert result is True

    @pytest.mark.asyncio
    async def test_remove_returns_false_when_not_found(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.rowcount = 0
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.remove_steward("t1", "nobody")
        assert result is False


class TestGetStewards:
    @pytest.mark.asyncio
    async def test_get_returns_list(self, store, mock_pool):
        rows = [
            ("t1", "alice", "admin", "2024-01-01"),
            ("t1", "bob", "admin", "2024-01-02"),
        ]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_stewards("t1")
        assert len(result) == 2
        assert result[0]["username"] == "alice"

    @pytest.mark.asyncio
    async def test_get_returns_empty(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=[])
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_stewards("t1")
        assert result == []


class TestIsSteward:
    @pytest.mark.asyncio
    async def test_is_steward_true(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=(1,))
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.is_steward("t1", "alice")
        assert result is True

    @pytest.mark.asyncio
    async def test_is_steward_false(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.is_steward("t1", "nobody")
        assert result is False


class TestGetStewardTenants:
    @pytest.mark.asyncio
    async def test_returns_tenant_names(self, store, mock_pool):
        rows = [("t1",), ("t2",)]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_steward_tenants("alice")
        assert result == ["t1", "t2"]

    @pytest.mark.asyncio
    async def test_returns_empty(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=[])
        mock_pool._mock_conn.execute.return_value = mock_cursor

        result = await store.get_steward_tenants("nobody")
        assert result == []
