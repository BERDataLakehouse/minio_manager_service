"""Tests for the DatabasePool class and run_migrations helper."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from service.database import DatabasePool, run_migrations


# ── run_migrations ────────────────────────────────────────────────────────


class TestRunMigrations:
    def test_calls_alembic_upgrade(self):
        with (
            patch("service.database._ALEMBIC_INI") as mock_path,
            patch("service.database.Config") as mock_config_cls,
            patch("service.database.command") as mock_command,
        ):
            mock_path.exists.return_value = True
            mock_cfg = MagicMock()
            mock_config_cls.return_value = mock_cfg

            run_migrations()

            mock_command.upgrade.assert_called_once_with(mock_cfg, "head")

    def test_skips_when_ini_missing(self):
        with (
            patch("service.database._ALEMBIC_INI") as mock_path,
            patch("service.database.command") as mock_command,
        ):
            mock_path.exists.return_value = False

            run_migrations()

            mock_command.upgrade.assert_not_called()


# ── Helpers ───────────────────────────────────────────────────────────────


def _make_pool(fetchone_return=(1,)):
    """Create an AsyncMock pool whose `.connection()` context manager yields
    a connection whose `.execute()` returns a cursor with the given fetchone."""
    cursor = AsyncMock()
    cursor.fetchone = AsyncMock(return_value=fetchone_return)

    conn = AsyncMock()
    conn.execute = AsyncMock(return_value=cursor)

    class CM:
        async def __aenter__(self):
            return conn

        async def __aexit__(self, *args):
            pass

    pool = AsyncMock()
    pool.open = AsyncMock()
    pool.close = AsyncMock()
    pool.connection = CM
    return pool


# ── Constructor ───────────────────────────────────────────────────────────


class TestInit:
    def test_stores_rw_and_ro(self):
        rw, ro = MagicMock(), MagicMock()
        db = DatabasePool(rw=rw, ro=ro, replica_enabled=True)
        assert db.rw is rw
        assert db.ro is ro
        assert db.replica_enabled is True

    def test_ro_alias_when_disabled(self):
        rw = MagicMock()
        db = DatabasePool(rw=rw, ro=rw, replica_enabled=False)
        assert db.rw is rw
        assert db.ro is rw
        assert db.replica_enabled is False


# ── create ────────────────────────────────────────────────────────────────


class TestCreate:
    @pytest.mark.asyncio
    async def test_create_success_with_replica(self):
        """Both pools open; pgcrypto verifies; replica_enabled=True."""
        primary = _make_pool(fetchone_return=(1,))
        replica = _make_pool(fetchone_return=(1,))

        with (
            patch(
                "service.database.AsyncConnectionPool",
                side_effect=[primary, replica],
            ),
            patch("service.database.make_conninfo", return_value="conninfo"),
        ):
            db = await DatabasePool.create(
                host="h", port=5432, dbname="mms", user="u", password="p",
                ro_dbname="mms_ro",
            )

        assert isinstance(db, DatabasePool)
        assert db.rw is primary
        assert db.ro is replica
        assert db.replica_enabled is True
        primary.open.assert_called_once()
        replica.open.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_replica_disabled_by_flag(self):
        """read_from_replica=False → ro aliased to primary, only one pool opened."""
        primary = _make_pool(fetchone_return=(1,))

        with (
            patch("service.database.AsyncConnectionPool", return_value=primary),
            patch("service.database.make_conninfo", return_value="conninfo"),
        ):
            db = await DatabasePool.create(
                host="h", port=5432, dbname="mms", user="u", password="p",
                ro_dbname="mms_ro", read_from_replica=False,
            )

        assert db.rw is primary
        assert db.ro is primary  # aliased
        assert db.replica_enabled is False

    @pytest.mark.asyncio
    async def test_create_no_ro_dbname_aliases_to_primary(self):
        """ro_dbname=None → ro aliased to primary."""
        primary = _make_pool(fetchone_return=(1,))

        with (
            patch("service.database.AsyncConnectionPool", return_value=primary),
            patch("service.database.make_conninfo", return_value="conninfo"),
        ):
            db = await DatabasePool.create(
                host="h", port=5432, dbname="mms", user="u", password="p",
                ro_dbname=None,
            )

        assert db.replica_enabled is False
        assert db.ro is primary

    @pytest.mark.asyncio
    async def test_create_replica_open_failure_falls_back(self):
        """Replica open fails → ro falls back to primary, no raise."""
        primary = _make_pool(fetchone_return=(1,))
        replica = _make_pool(fetchone_return=(1,))
        replica.open = AsyncMock(side_effect=TimeoutError("replica unreachable"))

        with (
            patch(
                "service.database.AsyncConnectionPool",
                side_effect=[primary, replica],
            ),
            patch("service.database.make_conninfo", return_value="conninfo"),
        ):
            db = await DatabasePool.create(
                host="h", port=5432, dbname="mms", user="u", password="p",
                ro_dbname="mms_ro",
            )

        assert db.rw is primary
        assert db.ro is primary  # fell back
        assert db.replica_enabled is False

    @pytest.mark.asyncio
    async def test_create_no_pgcrypto_raises(self):
        primary = _make_pool(fetchone_return=None)  # pgcrypto absent

        with (
            patch("service.database.AsyncConnectionPool", return_value=primary),
            patch("service.database.make_conninfo", return_value="conninfo"),
        ):
            with pytest.raises(RuntimeError, match="pgcrypto"):
                await DatabasePool.create(
                    host="h", port=5432, dbname="mms", user="u", password="p",
                )

        primary.close.assert_called_once()


# ── health_check ──────────────────────────────────────────────────────────


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_both_healthy(self):
        rw = _make_pool()
        ro = _make_pool()
        db = DatabasePool(rw=rw, ro=ro, replica_enabled=True)
        assert await db.health_check() == {"primary": True, "replica": True}

    @pytest.mark.asyncio
    async def test_replica_unhealthy(self):
        rw = _make_pool()
        ro = AsyncMock()

        class FailCM:
            async def __aenter__(self):
                raise Exception("replica boom")

            async def __aexit__(self, *args):
                pass

        ro.connection = FailCM
        db = DatabasePool(rw=rw, ro=ro, replica_enabled=True)
        result = await db.health_check()
        assert result == {"primary": True, "replica": False}

    @pytest.mark.asyncio
    async def test_aliased_ro_reports_primary_status(self):
        """When ro is aliased to rw, both keys reflect the same SELECT 1."""
        rw = _make_pool()
        db = DatabasePool(rw=rw, ro=rw, replica_enabled=False)
        result = await db.health_check()
        assert result == {"primary": True, "replica": True}


# ── close ─────────────────────────────────────────────────────────────────


class TestClose:
    @pytest.mark.asyncio
    async def test_close_both_pools_when_replica_enabled(self):
        rw, ro = AsyncMock(), AsyncMock()
        rw.close, ro.close = AsyncMock(), AsyncMock()

        db = DatabasePool(rw=rw, ro=ro, replica_enabled=True)
        await db.close()
        rw.close.assert_called_once()
        ro.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_only_primary_when_aliased(self):
        """ro aliased to rw → close once."""
        rw = AsyncMock()
        rw.close = AsyncMock()

        db = DatabasePool(rw=rw, ro=rw, replica_enabled=False)
        await db.close()
        assert rw.close.call_count == 1
