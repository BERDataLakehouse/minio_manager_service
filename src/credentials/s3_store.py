"""
Encrypted credential storage backed by PostgreSQL with pgcrypto.

Provides idempotent credential caching so that GET /credentials returns
the same S3 credentials for a user until explicitly rotated.
"""

import logging

from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)

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


class S3CredentialStore:
    """Async PostgreSQL credential store with pgcrypto encryption.

    Accepts a shared ``AsyncConnectionPool`` from ``DatabasePool``.
    Table creation and pgcrypto verification are handled by Alembic
    migrations and ``DatabasePool.create()`` respectively.
    """

    def __init__(self, pool: AsyncConnectionPool, encryption_key: str) -> None:
        self._pool = pool
        self._encryption_key = encryption_key

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
        """No-op. Pool lifecycle is managed by DatabasePool."""
