"""Encrypted Polaris credential storage backed by PostgreSQL with pgcrypto."""

import logging
from dataclasses import dataclass

from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)

_UPSERT = """
INSERT INTO polaris_user_credentials (
    username,
    client_id,
    client_secret,
    personal_catalog
)
VALUES (
    %(username)s,
    %(client_id)s,
    pgp_sym_encrypt(%(client_secret)s, %(enc_key)s),
    %(personal_catalog)s
)
ON CONFLICT (username) DO UPDATE
    SET client_id        = EXCLUDED.client_id,
        client_secret    = EXCLUDED.client_secret,
        personal_catalog = EXCLUDED.personal_catalog,
        updated_at       = now();
"""

_SELECT = """
SELECT client_id,
       pgp_sym_decrypt(client_secret, %(enc_key)s) AS client_secret,
       personal_catalog
  FROM polaris_user_credentials
 WHERE username = %(username)s;
"""

_DELETE = """
DELETE FROM polaris_user_credentials WHERE username = %(username)s;
"""


@dataclass(frozen=True)
class PolarisCredentialRecord:
    """Cached Polaris credential material for one user."""

    client_id: str
    client_secret: str
    personal_catalog: str


class PolarisCredentialStore:
    """Async PostgreSQL store for encrypted Polaris principal credentials."""

    def __init__(self, pool: AsyncConnectionPool, encryption_key: str) -> None:
        self._pool = pool
        self._encryption_key = encryption_key

    async def get_credentials(self, username: str) -> PolarisCredentialRecord | None:
        """Return cached credentials or None if no cache entry exists."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                _SELECT, {"username": username, "enc_key": self._encryption_key}
            )
            row = await cur.fetchone()
        if row is None:
            return None
        return PolarisCredentialRecord(
            client_id=row[0],
            client_secret=row[1],
            personal_catalog=row[2],
        )

    async def store_credentials(
        self,
        username: str,
        client_id: str,
        client_secret: str,
        personal_catalog: str,
    ) -> None:
        """Insert or update encrypted Polaris credentials."""
        async with self._pool.connection() as conn:
            await conn.execute(
                _UPSERT,
                {
                    "username": username,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "personal_catalog": personal_catalog,
                    "enc_key": self._encryption_key,
                },
            )
            await conn.commit()
        logger.info("Stored Polaris credentials for user %s", username)

    async def delete_credentials(self, username: str) -> None:
        """Remove cached Polaris credentials for a user."""
        async with self._pool.connection() as conn:
            await conn.execute(_DELETE, {"username": username})
            await conn.commit()
        logger.info("Deleted cached Polaris credentials for user %s", username)

    async def close(self) -> None:
        """No-op. Pool lifecycle is managed by DatabasePool."""
