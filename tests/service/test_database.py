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


# ── Constructor ───────────────────────────────────────────────────────────


class TestInit:
    def test_stores_pool(self):
        mock_pool = MagicMock()
        db = DatabasePool(mock_pool)
        assert db.pool is mock_pool


# ── create ────────────────────────────────────────────────────────────────


class TestCreate:
    @pytest.mark.asyncio
    async def test_create_success(self):
        mock_pool = AsyncMock()
        mock_pool.open = AsyncMock()

        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=(1,))

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=mock_cursor)

        class MockConnectionCM:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool.connection = MockConnectionCM

        with (
            patch("service.database.AsyncConnectionPool", return_value=mock_pool),
            patch("service.database.make_conninfo", return_value="conninfo"),
        ):
            db = await DatabasePool.create(
                host="localhost",
                port=5432,
                dbname="testdb",
                user="user",
                password="pass",
            )

        assert isinstance(db, DatabasePool)
        assert db.pool is mock_pool
        mock_pool.open.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_no_pgcrypto_raises(self):
        mock_pool = AsyncMock()
        mock_pool.open = AsyncMock()
        mock_pool.close = AsyncMock()

        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)  # pgcrypto not found

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=mock_cursor)

        class MockConnectionCM:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool.connection = MockConnectionCM

        with (
            patch("service.database.AsyncConnectionPool", return_value=mock_pool),
            patch("service.database.make_conninfo", return_value="conninfo"),
        ):
            with pytest.raises(RuntimeError, match="pgcrypto"):
                await DatabasePool.create(
                    host="localhost",
                    port=5432,
                    dbname="testdb",
                    user="user",
                    password="pass",
                )

        mock_pool.close.assert_called_once()


# ── pool property ─────────────────────────────────────────────────────────


class TestPoolProperty:
    def test_returns_underlying_pool(self):
        mock_pool = MagicMock()
        db = DatabasePool(mock_pool)
        assert db.pool is mock_pool


# ── health_check ──────────────────────────────────────────────────────────


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy(self):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        class MockConnectionCM:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = MagicMock()
        mock_pool.connection = MockConnectionCM

        db = DatabasePool(mock_pool)
        assert await db.health_check() is True

    @pytest.mark.asyncio
    async def test_unhealthy(self):
        class MockConnectionCM:
            async def __aenter__(self):
                raise Exception("connection refused")

            async def __aexit__(self, *args):
                pass

        mock_pool = MagicMock()
        mock_pool.connection = MockConnectionCM

        db = DatabasePool(mock_pool)
        assert await db.health_check() is False


# ── close ─────────────────────────────────────────────────────────────────


class TestClose:
    @pytest.mark.asyncio
    async def test_close_delegates(self):
        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock()

        db = DatabasePool(mock_pool)
        await db.close()
        mock_pool.close.assert_called_once()
