"""PostgreSQL repository for user_profiles table.

Stores display_name and email captured at authentication time from
KBase Auth /api/V2/me responses.
"""

import logging

from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)

_UPSERT = """
INSERT INTO user_profiles (username, display_name, email, captured_at)
VALUES (%(username)s, %(display_name)s, %(email)s, now())
ON CONFLICT (username) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        email        = EXCLUDED.email,
        captured_at  = now();
"""

_SELECT_BATCH = """
SELECT username, display_name, email
  FROM user_profiles
 WHERE username = ANY(%(usernames)s);
"""

_SELECT_ONE = """
SELECT display_name, email
  FROM user_profiles
 WHERE username = %(username)s;
"""


class UserProfileStore:
    """Async PostgreSQL store for cached user profiles."""

    def __init__(self, pool: AsyncConnectionPool) -> None:
        self._pool = pool

    async def upsert(
        self,
        username: str,
        display_name: str | None,
        email: str | None,
    ) -> None:
        """Insert or update a user profile."""
        async with self._pool.connection() as conn:
            await conn.execute(
                _UPSERT,
                {
                    "username": username,
                    "display_name": display_name,
                    "email": email,
                },
            )
            await conn.commit()

    async def get_profiles(
        self, usernames: list[str]
    ) -> dict[str, tuple[str | None, str | None]]:
        """Batch-fetch profiles. Returns {username: (display_name, email)}."""
        if not usernames:
            return {}
        async with self._pool.connection() as conn:
            cur = await conn.execute(_SELECT_BATCH, {"usernames": usernames})
            rows = await cur.fetchall()
        return {row[0]: (row[1], row[2]) for row in rows}

    async def get_email(self, username: str) -> str | None:
        """Get a single user's email, or None if not captured."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_SELECT_ONE, {"username": username})
            row = await cur.fetchone()
        if row is None:
            return None
        return row[1]
