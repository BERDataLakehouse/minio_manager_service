"""KBase Auth display name fetcher with local email merge.

Batch-fetches display names from KBase Auth /api/V2/users/?list= and
merges with locally stored emails from the user_profiles table.
"""

import logging

import aiohttp
from cacheout.lru import LRUCache
from psycopg_pool import AsyncConnectionPool

from s3.models.tenant import UserProfile

logger = logging.getLogger(__name__)

_SELECT_EMAILS = """
SELECT username, email
  FROM user_profiles
 WHERE username = ANY(%(usernames)s);
"""


class KBaseUserProfileClient:
    """Fetches user profiles: display names from KBase Auth, emails from local store."""

    def __init__(self, auth_url: str, pool: AsyncConnectionPool) -> None:
        self._auth_url = auth_url.rstrip("/")
        self._users_url = f"{self._auth_url}/api/V2/users/"
        self._pool = pool
        self._display_cache: LRUCache = LRUCache(maxsize=10_000, ttl=300)

    async def get_user_profiles(
        self, usernames: list[str], token: str
    ) -> dict[str, UserProfile]:
        """Batch-fetch profiles for multiple users.

        Args:
            usernames: List of KBase usernames to look up.
            token: A valid KBase auth token for the batch lookup API.

        Returns:
            Mapping of username to UserProfile with display_name and email.
        """
        if not usernames:
            return {}

        # 1. Batch-fetch display names from KBase Auth (cache-first)
        uncached = [u for u in usernames if u not in self._display_cache]
        if uncached:
            await self._fetch_display_names(uncached, token)

        # 2. Fetch emails from local user_profiles table
        email_map = await self._fetch_emails(usernames)

        # 3. Merge
        return {
            u: UserProfile(
                username=u,
                display_name=self._display_cache.get(u),
                email=email_map.get(u),
            )
            for u in usernames
        }

    async def _fetch_display_names(self, usernames: list[str], token: str) -> None:
        """Fetch display names from KBase Auth batch endpoint and populate cache."""
        user_list = ",".join(usernames)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._users_url}?list={user_list}",
                    headers={"Authorization": token},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for uname in usernames:
                            self._display_cache.set(uname, data.get(uname))
                    else:
                        logger.warning(
                            "KBase batch user lookup returned status %s", resp.status
                        )
        except Exception:
            logger.exception("Failed to fetch display names from KBase Auth")

    async def _fetch_emails(self, usernames: list[str]) -> dict[str, str | None]:
        """Fetch emails from local user_profiles table."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(_SELECT_EMAILS, {"usernames": usernames})
            rows = await cur.fetchall()
        return {row[0]: row[1] for row in rows}
