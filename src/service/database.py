"""Shared async connection pool for all PostgreSQL stores.

All stores (CredentialStore, UserProfileStore, TenantMetadataStore) receive
the shared pool at construction time rather than creating their own.
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
    """Shared async connection pool backed by psycopg v3."""

    def __init__(self, pool: AsyncConnectionPool) -> None:
        self._pool = pool

    @classmethod
    async def create(
        cls,
        *,
        host: str,
        port: int,
        dbname: str,
        user: str,
        password: str,
    ) -> "DatabasePool":
        """Create and open the shared connection pool.

        Also verifies that the pgcrypto extension is installed (required by
        CredentialStore for encrypted secret storage).
        """
        conninfo = make_conninfo(
            host=host, port=port, dbname=dbname, user=user, password=password
        )
        pool = AsyncConnectionPool(
            conninfo=conninfo, min_size=2, max_size=10, open=False
        )
        await pool.open()

        # Verify pgcrypto is available (required by CredentialStore)
        async with pool.connection() as conn:
            cur = await conn.execute(
                "SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'"
            )
            if await cur.fetchone() is None:
                await pool.close()
                raise RuntimeError(
                    "pgcrypto extension is not installed. "
                    "Run 'CREATE EXTENSION pgcrypto;' as a superuser."
                )

        logger.info("DatabasePool initialized (pgcrypto verified)")
        return cls(pool)

    @property
    def pool(self) -> AsyncConnectionPool:
        """Return the underlying connection pool."""
        return self._pool

    async def health_check(self) -> bool:
        """Verify the database connection is alive."""
        try:
            async with self._pool.connection() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            logger.exception("DatabasePool health check failed")
            return False

    async def close(self) -> None:
        """Close the connection pool."""
        await self._pool.close()
        logger.info("DatabasePool connection pool closed")
