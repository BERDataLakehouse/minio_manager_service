"""Tests for the TenantMetadataStore class."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from tenant_metadata.tenant_metadata_store import (
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
        row = (
            "t1",
            "T1",
            "desc",
            "https://example.com",
            "org",
            "admin",
            "2024-01-01",
            "2024-01-02",
            None,
        )
        result = _row_to_metadata(row)
        assert result["tenant_name"] == "t1"
        assert result["display_name"] == "T1"
        assert result["description"] == "desc"
        assert result["website"] == "https://example.com"
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
        row = ("t1", "t1", None, None, None, "admin", "2024-01-01", "2024-01-01", None)
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
            "https://example.com",
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
            website="https://example.com",
            organization="Org",
        )
        assert result["display_name"] == "Display"
        assert result["description"] == "Desc"
        assert result["website"] == "https://example.com"
        assert result["organization"] == "Org"


class TestGetMetadata:
    @pytest.mark.asyncio
    async def test_get_returns_dict(self, store, mock_pool):
        row = (
            "t1",
            "T1",
            "desc",
            None,
            None,
            "admin",
            "2024-01-01",
            "2024-01-01",
            None,
        )
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
        row = (
            "t1",
            "N",
            "D",
            "https://example.com",
            "O",
            "admin",
            "2024-01-01",
            "2024-01-02",
            "user",
        )
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=row)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        await store.update_metadata(
            "t1",
            "user",
            display_name="N",
            description="D",
            website="https://example.com",
            organization="O",
        )
        sql_arg = mock_pool._mock_conn.execute.call_args[0][0]
        assert "display_name" in sql_arg
        assert "description" in sql_arg
        assert "website" in sql_arg
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
            ("t1", "T1", None, None, None, "admin", "2024-01-01", "2024-01-01", None),
            ("t2", "T2", "desc", None, None, "admin", "2024-01-01", "2024-01-01", None),
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


# ── Read-side caches + mutation invalidation ────────────────────────────


def _meta_row(name: str = "t1") -> tuple:
    """Build a minimal SELECT * tenant_metadata row tuple."""
    return (
        name,
        name.upper(),
        None,
        None,
        None,
        "admin",
        "2024-01-01",
        "2024-01-01",
        None,
    )


class TestMetadataReadCaches:
    """Each read method is fronted by a SingleFlightTTLCache."""

    @pytest.mark.asyncio
    async def test_get_metadata_caches_hit(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=_meta_row("t1"))
        mock_pool._mock_conn.execute.return_value = mock_cursor

        first = await store.get_metadata("t1")
        second = await store.get_metadata("t1")

        assert first == second
        assert first["tenant_name"] == "t1"
        # One SQL execute across two reads.
        assert mock_pool._mock_conn.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_get_metadata_caches_none_value(self, store, mock_pool):
        """A None result (no metadata row) is cached, not re-queried."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        assert await store.get_metadata("ghost") is None
        assert await store.get_metadata("ghost") is None
        assert mock_pool._mock_conn.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_get_metadata_distinct_keys_independent(self, store, mock_pool):
        """Different tenant names -> independent cache keys."""

        def fetchone_for(_args):
            cur = AsyncMock()
            cur.fetchone = AsyncMock(return_value=_meta_row("anything"))
            return cur

        mock_pool._mock_conn.execute.side_effect = lambda *a, **kw: fetchone_for(a)

        await store.get_metadata("t1")
        await store.get_metadata("t2")
        assert mock_pool._mock_conn.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_list_metadata_caches_hit(self, store, mock_pool):
        rows = [_meta_row("t1"), _meta_row("t2")]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        first = await store.list_metadata()
        second = await store.list_metadata()
        assert first == second
        assert len(first) == 2
        assert mock_pool._mock_conn.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_get_stewards_caches_hit(self, store, mock_pool):
        rows = [("t1", "alice", "admin", "2024-01-01")]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        first = await store.get_stewards("t1")
        second = await store.get_stewards("t1")
        assert first == second
        assert mock_pool._mock_conn.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_is_steward_caches_hit(self, store, mock_pool):
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=(1,))
        mock_pool._mock_conn.execute.return_value = mock_cursor

        assert await store.is_steward("t1", "alice") is True
        assert await store.is_steward("t1", "alice") is True
        assert mock_pool._mock_conn.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_is_steward_caches_false(self, store, mock_pool):
        """is_steward returning False must also cache (avoids re-query storms)."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        assert await store.is_steward("t1", "alice") is False
        assert await store.is_steward("t1", "alice") is False
        assert mock_pool._mock_conn.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_is_steward_keyed_by_tenant_user_pair(self, store, mock_pool):
        """The cache key is (tenant, user); different pairs are independent."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=(1,))
        mock_pool._mock_conn.execute.return_value = mock_cursor

        await store.is_steward("t1", "alice")
        await store.is_steward("t1", "bob")
        await store.is_steward("t2", "alice")
        # 3 distinct (tenant, user) pairs -> 3 SQL queries.
        assert mock_pool._mock_conn.execute.call_count == 3

    @pytest.mark.asyncio
    async def test_get_steward_tenants_caches_hit(self, store, mock_pool):
        rows = [("t1",), ("t2",)]
        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=rows)
        mock_pool._mock_conn.execute.return_value = mock_cursor

        first = await store.get_steward_tenants("alice")
        second = await store.get_steward_tenants("alice")
        assert first == second == ["t1", "t2"]
        assert mock_pool._mock_conn.execute.call_count == 1


class TestMetadataMutationInvalidation:
    """Mutations must bust the affected per-key caches in-pod."""

    @pytest.mark.asyncio
    async def test_create_metadata_invalidates_caches(self, store, mock_pool):
        # 1) Prime get_metadata("t1") and list_metadata() with the
        #    "doesn't exist" / empty-list state.
        primed = AsyncMock()
        primed.fetchone = AsyncMock(return_value=None)
        primed.fetchall = AsyncMock(return_value=[])
        mock_pool._mock_conn.execute.return_value = primed

        assert await store.get_metadata("t1") is None
        assert await store.list_metadata() == []
        baseline = mock_pool._mock_conn.execute.call_count

        # 2) Create the tenant metadata. Should invalidate both caches.
        created = AsyncMock()
        created.fetchone = AsyncMock(return_value=_meta_row("t1"))
        mock_pool._mock_conn.execute.return_value = created
        await store.create_metadata("t1", "admin")

        # 3) Re-read both — must hit DB again, not the stale caches.
        await store.get_metadata("t1")
        await store.list_metadata()
        # baseline + create + 2 refreshes = baseline + 3
        assert mock_pool._mock_conn.execute.call_count == baseline + 3

    @pytest.mark.asyncio
    async def test_update_metadata_invalidates_caches(self, store, mock_pool):
        # Prime.
        primed = AsyncMock()
        primed.fetchone = AsyncMock(return_value=_meta_row("t1"))
        primed.fetchall = AsyncMock(return_value=[_meta_row("t1")])
        mock_pool._mock_conn.execute.return_value = primed
        await store.get_metadata("t1")
        await store.list_metadata()
        baseline = mock_pool._mock_conn.execute.call_count

        # Update.
        await store.update_metadata("t1", "user", display_name="New")

        # Re-read both should hit DB.
        await store.get_metadata("t1")
        await store.list_metadata()
        # baseline + update + 2 refetches.
        assert mock_pool._mock_conn.execute.call_count == baseline + 3

    @pytest.mark.asyncio
    async def test_delete_metadata_invalidates_metadata_and_all_stewardship(
        self, store, mock_pool
    ):
        # Prime: list_metadata, get_metadata(t1), get_stewards(t1),
        # is_steward(t1, alice), get_steward_tenants(alice).
        primed = AsyncMock()
        primed.fetchone = AsyncMock(return_value=_meta_row("t1"))
        primed.fetchall = AsyncMock(
            return_value=[("t1", "alice", "admin", "2024-01-01")]
        )
        primed.rowcount = 1
        mock_pool._mock_conn.execute.return_value = primed

        await store.get_metadata("t1")
        await store.list_metadata()
        await store.get_stewards("t1")
        # is_steward_true: fetchone = (1,)
        primed.fetchone = AsyncMock(return_value=(1,))
        await store.is_steward("t1", "alice")
        # get_steward_tenants: fetchall = [("t1",)]
        primed.fetchall = AsyncMock(return_value=[("t1",)])
        await store.get_steward_tenants("alice")
        baseline = mock_pool._mock_conn.execute.call_count

        # Delete.
        primed.rowcount = 1
        assert await store.delete_metadata("t1") is True

        # All five must re-query (none cached).
        await store.get_metadata("t1")
        await store.list_metadata()
        await store.get_stewards("t1")
        await store.is_steward("t1", "alice")
        await store.get_steward_tenants("alice")
        # baseline + 1 (delete) + 5 refetches.
        assert mock_pool._mock_conn.execute.call_count == baseline + 6

    @pytest.mark.asyncio
    async def test_add_steward_invalidates_stewardship_caches(self, store, mock_pool):
        # Prime get_stewards(t1), is_steward(t1, alice)=False,
        # get_steward_tenants(alice)=[].
        primed = AsyncMock()
        primed.fetchall = AsyncMock(return_value=[])
        primed.fetchone = AsyncMock(return_value=None)
        mock_pool._mock_conn.execute.return_value = primed

        await store.get_stewards("t1")
        await store.is_steward("t1", "alice")
        await store.get_steward_tenants("alice")
        baseline = mock_pool._mock_conn.execute.call_count

        # add_steward returns the upserted row.
        primed.fetchone = AsyncMock(return_value=("t1", "alice", "admin", "2024-01-01"))
        await store.add_steward("t1", "alice", "admin")

        # All three must re-query.
        primed.fetchall = AsyncMock(
            return_value=[("t1", "alice", "admin", "2024-01-01")]
        )
        await store.get_stewards("t1")
        primed.fetchone = AsyncMock(return_value=(1,))
        await store.is_steward("t1", "alice")
        primed.fetchall = AsyncMock(return_value=[("t1",)])
        await store.get_steward_tenants("alice")
        assert mock_pool._mock_conn.execute.call_count == baseline + 4

    @pytest.mark.asyncio
    async def test_remove_steward_invalidates_stewardship_caches(
        self, store, mock_pool
    ):
        # Prime to "alice is a steward of t1" state.
        primed = AsyncMock()
        primed.fetchall = AsyncMock(
            return_value=[("t1", "alice", "admin", "2024-01-01")]
        )
        primed.fetchone = AsyncMock(return_value=(1,))
        mock_pool._mock_conn.execute.return_value = primed

        await store.get_stewards("t1")
        await store.is_steward("t1", "alice")
        baseline = mock_pool._mock_conn.execute.call_count

        primed.rowcount = 1
        await store.remove_steward("t1", "alice")

        # Re-reads must miss cache.
        primed.fetchall = AsyncMock(return_value=[])
        await store.get_stewards("t1")
        primed.fetchone = AsyncMock(return_value=None)
        await store.is_steward("t1", "alice")
        # baseline + remove (1) + 2 refetches.
        assert mock_pool._mock_conn.execute.call_count == baseline + 3

    @pytest.mark.asyncio
    async def test_add_steward_does_not_invalidate_unrelated_user(
        self, store, mock_pool
    ):
        """Adding alice as steward must not invalidate bob's get_steward_tenants."""
        primed = AsyncMock()
        primed.fetchall = AsyncMock(return_value=[("t1",)])
        primed.fetchone = AsyncMock(return_value=("t1", "alice", "admin", "2024-01-01"))
        mock_pool._mock_conn.execute.return_value = primed

        await store.get_steward_tenants("bob")
        baseline = mock_pool._mock_conn.execute.call_count

        await store.add_steward("t1", "alice", "admin")

        # bob's cache must still hit.
        await store.get_steward_tenants("bob")
        # baseline + add (1) only.
        assert mock_pool._mock_conn.execute.call_count == baseline + 1


class TestSingleFlightOnStore:
    """Concurrent misses for the same key invoke the underlying SQL once."""

    @pytest.mark.asyncio
    async def test_concurrent_get_metadata_dedup(self, store, mock_pool):
        import asyncio as _aio

        execute_calls = 0
        loader_started = _aio.Event()
        loader_can_finish = _aio.Event()

        async def slow_execute(*_a, **_kw):
            nonlocal execute_calls
            execute_calls += 1
            loader_started.set()
            await loader_can_finish.wait()
            cur = AsyncMock()
            cur.fetchone = AsyncMock(return_value=_meta_row("t1"))
            return cur

        mock_pool._mock_conn.execute.side_effect = slow_execute

        tasks = [_aio.create_task(store.get_metadata("t1")) for _ in range(8)]
        await loader_started.wait()
        loader_can_finish.set()
        results = await _aio.gather(*tasks)

        assert all(r["tenant_name"] == "t1" for r in results)
        # 8 concurrent reads -> 1 SQL execute (single-flight).
        assert execute_calls == 1
