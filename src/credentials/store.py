"""
Encrypted credential storage backed by PostgreSQL with pgcrypto.

Provides idempotent credential caching so that GET /credentials returns
the same MinIO credentials for a user until explicitly rotated.
"""

import logging

from psycopg.conninfo import make_conninfo
from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS user_credentials (
    username    TEXT PRIMARY KEY,
    access_key  TEXT NOT NULL,
    secret_key  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

_UPSERT = """
INSERT INTO user_credentials (username, access_key, secret_key)
VALUES (%(username)s, %(access_key)s, pgp_sym_encrypt(%(secret_key)s, %(enc_key)s))
ON CONFLICT (username) DO UPDATE
    SET access_key  = EXCLUDED.access_key,
        secret_key  = EXCLUDED.secret_key,
        updated_at  = now();
"""

_SELECT = """
SELECT access_key,
       pgp_sym_decrypt(secret_key, %(enc_key)s) AS secret_key
  FROM user_credentials
 WHERE username = %(username)s;
"""

_DELETE = """
DELETE FROM user_credentials WHERE username = %(username)s;
"""


class CredentialStore:
    """Async PostgreSQL credential store with pgcrypto encryption."""

    def __init__(self, pool: AsyncConnectionPool, encryption_key: str) -> None:
        self._pool = pool
        self._encryption_key = encryption_key

    @classmethod
    async def create(
        cls,
        *,
        host: str,
        port: int,
        dbname: str,
        user: str,
        password: str,
        encryption_key: str,
    ) -> "CredentialStore":
        conninfo = make_conninfo(
            host=host, port=port, dbname=dbname, user=user, password=password
        )
        pool = AsyncConnectionPool(
            conninfo=conninfo, min_size=1, max_size=10, open=False
        )
        await pool.open()

        async with pool.connection() as conn:
            # Fail fast if pgcrypto is not installed
            cur = await conn.execute(
                "SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'"
            )
            if await cur.fetchone() is None:
                await pool.close()
                raise RuntimeError(
                    "pgcrypto extension is not installed. "
                    "Run 'CREATE EXTENSION pgcrypto;' as a superuser."
                )
            # Ensure the table exists
            await conn.execute(_CREATE_TABLE)
            await conn.commit()

        logger.info("CredentialStore initialized (pgcrypto verified, table ensured)")
        return cls(pool, encryption_key)

    async def get_credentials(self, username: str) -> tuple[str, str] | None:
        """Return (access_key, secret_key) or None if not cached."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _SELECT, {"username": username, "enc_key": self._encryption_key}
            )
            row = await cur.fetchone()
        if row is None:
            return None
        return (row[0], row[1])

    async def store_credentials(
        self, username: str, access_key: str, secret_key: str
    ) -> None:
        """Insert or update encrypted credentials."""
        async with self._pool.connection() as conn:
            await conn.execute(
                _UPSERT,
                {
                    "username": username,
                    "access_key": access_key,
                    "secret_key": secret_key,
                    "enc_key": self._encryption_key,
                },
            )
            await conn.commit()
        logger.info(f"Stored credentials for user {username}")

    async def delete_credentials(self, username: str) -> None:
        """Remove cached credentials for a user."""
        async with self._pool.connection() as conn:
            await conn.execute(_DELETE, {"username": username})
            await conn.commit()
        logger.info(f"Deleted cached credentials for user {username}")

    async def health_check(self) -> bool:
        """Verify the database connection is alive."""
        try:
            async with self._pool.connection() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            logger.exception("CredentialStore health check failed")
            return False

    async def close(self) -> None:
        """Close the connection pool."""
        await self._pool.close()
        logger.info("CredentialStore connection pool closed")
