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
    """Cached Polaris credential material for one user.

    ``personal_catalog`` is co-located with the credentials because the catalog
    name is provisioned together with the principal and is treated as immutable
    for the lifetime of that principal. If the catalog assignment ever needs to
    change independently of the credentials, lift it into a separate table.
    """

    client_id: str
    client_secret: str
    personal_catalog: str


class PolarisCredentialStore:
    """Async PostgreSQL store for encrypted Polaris principal credentials.

    Same dual-pool contract as ``S3CredentialStore``: plain reads from ``ro``,
    mutations and lock-protected re-checks (``get_credentials_for_writer``)
    from ``rw``.
    """

    def __init__(
        self,
        *,
        rw: AsyncConnectionPool,
        ro: AsyncConnectionPool,
        encryption_key: str,
    ) -> None:
        self._rw = rw
        self._ro = ro
        self._encryption_key = encryption_key

    async def get_credentials(self, username: str) -> PolarisCredentialRecord | None:
        """Return cached credentials or None if no cache entry exists. Reads from ro."""
        return await self._select(self._ro, username)

    async def get_credentials_for_writer(
        self, username: str
    ) -> PolarisCredentialRecord | None:
        """Same as ``get_credentials`` but reads from rw. Required inside any
        distributed-lock re-check; see ``S3CredentialStore.get_credentials_for_writer``.
        """
        return await self._select(self._rw, username)

    async def _select(
        self, pool: AsyncConnectionPool, username: str
    ) -> PolarisCredentialRecord | None:
        async with pool.connection() as conn:
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
        async with self._rw.connection() as conn:
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
        async with self._rw.connection() as conn:
            await conn.execute(_DELETE, {"username": username})
            await conn.commit()
        logger.info("Deleted cached Polaris credentials for user %s", username)

    async def health_check(self) -> bool:
        """Verify the primary database connection is alive."""
        try:
            async with self._rw.connection() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            logger.exception("PolarisCredentialStore health check failed")
            return False

    async def close(self) -> None:
        """No-op. Pool lifecycle is managed by DatabasePool."""
