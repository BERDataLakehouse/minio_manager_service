"""Shared async connection pools (primary + replica) for all PostgreSQL stores.

All stores receive both pools at construction. Each store routes its own SQL:
writes and "lock-and-check" reads go to ``rw``; plain reads go to ``ro``.
"""

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from psycopg.conninfo import make_conninfo
from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)

# Alembic config lives at the repo root (one level above src/)
_ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


def run_migrations() -> None:
    """Run Alembic migrations to head.

    Uses the project's alembic.ini which reads MMS_DB_* env vars in env.py.
    Safe to call on every startup — Alembic is a no-op when already at head.
    """
    if not _ALEMBIC_INI.exists():
        logger.warning("alembic.ini not found at %s, skipping migrations", _ALEMBIC_INI)
        return

    logger.info("Running database migrations...")
    cfg = Config(str(_ALEMBIC_INI))
    # Prevent Alembic's fileConfig() from overwriting the app's logging setup.
    cfg.attributes["configure_logger"] = False
    command.upgrade(cfg, "head")
    logger.info("Database migrations complete")


class DatabasePool:
    """Shared async connection pools (primary + replica) backed by psycopg v3.

    The primary pool (``rw``) is mandatory; the replica pool (``ro``) is
    opened with a short timeout and fails soft — if the replica is unreachable
    at startup or ``READ_FROM_REPLICA_ENABLED`` is false, ``ro`` is aliased to
    ``rw`` and the service degrades to single-pool behaviour.
    """

    def __init__(
        self,
        rw: AsyncConnectionPool,
        ro: AsyncConnectionPool,
        *,
        replica_enabled: bool,
    ) -> None:
        self._rw = rw
        self._ro = ro
        self._replica_enabled = replica_enabled

    @classmethod
    async def create(
        cls,
        *,
        host: str,
        port: int,
        dbname: str,
        user: str,
        password: str,
        ro_dbname: str | None = None,
        read_from_replica: bool = True,
        replica_open_timeout: float = 5.0,
    ) -> "DatabasePool":
        """Create and open both pools.

        The primary pool is opened first and verifies pgcrypto. If
        ``read_from_replica`` is false or ``ro_dbname`` is None, the replica
        pool is aliased to the primary (no separate connection — the same
        ``AsyncConnectionPool`` object is reused). Otherwise the replica pool
        is opened with ``replica_open_timeout``; on failure it falls back to
        the primary alias and logs a warning.
        """
        rw_conninfo = make_conninfo(
            host=host, port=port, dbname=dbname, user=user, password=password
        )
        rw_pool = AsyncConnectionPool(
            conninfo=rw_conninfo, min_size=1, max_size=4, open=False
        )
        await rw_pool.open()

        # Verify pgcrypto is available on the primary (required by
        # S3CredentialStore for encrypted secret storage).
        async with rw_pool.connection() as conn:
            cur = await conn.execute(
                "SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'"
            )
            if await cur.fetchone() is None:
                await rw_pool.close()
                raise RuntimeError(
                    "pgcrypto extension is not installed. "
                    "Run 'CREATE EXTENSION pgcrypto;' as a superuser."
                )

        replica_enabled = read_from_replica and ro_dbname is not None
        if not replica_enabled:
            logger.info(
                "DatabasePool: replica disabled (read_from_replica=%s, ro_dbname=%s); "
                "ro pool aliased to primary",
                read_from_replica,
                ro_dbname,
            )
            return cls(rw=rw_pool, ro=rw_pool, replica_enabled=False)

        ro_conninfo = make_conninfo(
            host=host, port=port, dbname=ro_dbname, user=user, password=password
        )
        ro_pool = AsyncConnectionPool(
            conninfo=ro_conninfo, min_size=1, max_size=4, open=False
        )
        try:
            await ro_pool.open(wait=True, timeout=replica_open_timeout)
        except Exception:
            logger.exception(
                "DatabasePool: replica pool failed to open within %.1fs; "
                "aliasing ro to primary",
                replica_open_timeout,
            )
            await ro_pool.close()
            return cls(rw=rw_pool, ro=rw_pool, replica_enabled=False)

        logger.info("DatabasePool initialized (pgcrypto verified, replica enabled)")
        return cls(rw=rw_pool, ro=ro_pool, replica_enabled=True)

    @property
    def rw(self) -> AsyncConnectionPool:
        """Primary pool. Use for writes and lock-and-check reads."""
        return self._rw

    @property
    def ro(self) -> AsyncConnectionPool:
        """Read pool. Aliased to the primary when the replica is unavailable
        or `READ_FROM_REPLICA_ENABLED=false`."""
        return self._ro

    @property
    def replica_enabled(self) -> bool:
        """True when ro is a distinct replica pool (not an alias of rw)."""
        return self._replica_enabled

    async def health_check(self) -> dict[str, bool]:
        """Verify each pool independently. Returns {"primary": bool, "replica": bool}.

        When the replica is aliased to the primary, both keys reflect the same
        underlying SELECT 1 — but readiness logic should still gate only on
        ``primary`` (the alias means we can serve reads from the primary).
        """
        primary_ok = await self._ping(self._rw)
        if self._replica_enabled:
            replica_ok = await self._ping(self._ro)
        else:
            replica_ok = primary_ok
        return {"primary": primary_ok, "replica": replica_ok}

    @staticmethod
    async def _ping(pool: AsyncConnectionPool) -> bool:
        try:
            async with pool.connection() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            logger.exception("DatabasePool ping failed")
            return False

    async def close(self) -> None:
        """Close both connection pools (no-op if ro is aliased to rw)."""
        await self._rw.close()
        if self._replica_enabled:
            await self._ro.close()
        logger.info("DatabasePool connection pools closed")
