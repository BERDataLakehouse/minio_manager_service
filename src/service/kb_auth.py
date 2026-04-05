"""
A client for the KBase Auth2 server.
"""

# Mostly copied from https://github.com/kbase/cdm-task-service/blob/main/cdmtaskservice/kb_auth.py

from __future__ import annotations

import asyncio
import logging
import time
from enum import IntEnum
from typing import TYPE_CHECKING, NamedTuple, Self

import aiohttp
from cacheout.lru import LRUCache

from service.arg_checkers import not_falsy as _not_falsy
from service.exceptions import InvalidTokenError, MissingRoleError

if TYPE_CHECKING:
    from tenant_metadata.user_profile_store import UserProfileStore


class AdminPermission(IntEnum):
    """
    The different levels of admin permissions.
    """

    NONE = 1
    # leave some space for potential future levels
    FULL = 10


class KBaseUser(NamedTuple):
    user: str
    admin_perm: AdminPermission


async def _get(url, headers):
    # TODO PERF keep a single session and add a close method
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as r:
            await _check_error(r)
            return await r.json()


async def _check_error(r):
    if r.status != 200:
        try:
            j = await r.json()
        except Exception:
            err = "Non-JSON response from KBase auth server, status code: " + str(
                r.status
            )
            logging.getLogger(__name__).info("%s, response:\n%s", err, r.text)
            raise IOError(err)
        # assume that if we get json then at least this is the auth server and we can
        # rely on the error structure.
        if j["error"].get("appcode") == 10020:  # Invalid token
            raise InvalidTokenError("KBase auth server reported token is invalid.")
        # don't really see any other error codes we need to worry about - maybe disabled?
        # worry about it later.
        raise IOError("Error from KBase auth server: " + j["error"]["message"])


class KBaseAuth:
    """A client for contacting the KBase authentication server."""

    @classmethod
    async def create(
        cls,
        auth_url: str,
        required_roles: list[str] | None = None,
        full_admin_roles: list[str] | None = None,
        cache_max_size: int = 10000,
        cache_expiration: int = 300,
        profile_store: UserProfileStore | None = None,
    ) -> Self:
        """
        Create the client.
        auth_url - The root url of the authentication service.
        required_roles - The KBase Auth2 roles that the user must possess in order to be allowed
            to use the service.
        full_admin_roles -  The KBase Auth2 roles that determine that user is an administrator.
        cache_max_size -  the maximum size of the token cache.
        cache_expiration -  the expiration time for the token cache in
            seconds.
        profile_store - Optional UserProfileStore for capturing display name
            and email from /api/V2/me on cache miss (zero extra HTTP calls).
        """
        if not _not_falsy(auth_url, "auth_url").endswith("/"):
            auth_url += "/"
        j = await _get(auth_url, {"Accept": "application/json"})
        return cls(
            auth_url,
            required_roles,
            full_admin_roles,
            cache_max_size,
            cache_expiration,
            j.get("servicename"),
            profile_store,
        )

    def __init__(
        self,
        auth_url: str,
        required_roles: list[str] | None,
        full_admin_roles: list[str] | None,
        cache_max_size: int,
        cache_expiration: int,
        service_name: str,
        profile_store: UserProfileStore | None = None,
    ):
        self._url = auth_url
        self._me_url = self._url + "api/V2/me"
        self._req_roles = set(required_roles) if required_roles else None
        self._full_roles = set(full_admin_roles) if full_admin_roles else set()
        self._profile_store = profile_store
        self._cache_timer = (
            time.time
        )  # TODO TEST figure out how to replace the timer to test
        self._cache = LRUCache(
            timer=self._cache_timer, maxsize=cache_max_size, ttl=cache_expiration
        )

        if service_name != "Authentication Service":
            raise IOError(
                f"The service at {self._url} does not appear to be the KBase "
                + "Authentication Service"
            )

        # could use the server time to adjust for clock skew, probably not worth the trouble

    async def get_user(self, token: str) -> KBaseUser:
        """
        Get a username from a token as well as the user's administration status.
        Verifies the user has all the required roles set in the create() method.

        token - The user's token.

        Returns the user.
        """
        # TODO CODE should check the token for \n etc.
        _not_falsy(token, "token")

        admin_cache = self._cache.get(token, default=False)
        if admin_cache:
            return KBaseUser(admin_cache[0], admin_cache[1])
        j = await _get(self._me_url, {"Authorization": token})
        croles = set(j["customroles"])
        if self._req_roles and not self._req_roles <= croles:
            raise MissingRoleError(
                f"The user is missing required authentication roles to use the service. Required roles: {self._req_roles}"
            )
        v = (j["user"], self._get_admin_role(croles))
        self._cache.set(token, v)

        # Capture display name and email from the response we already have.
        # Fire-and-forget so auth latency is not affected.
        if self._profile_store:
            asyncio.create_task(
                self._safe_profile_upsert(j["user"], j.get("display"), j.get("email"))
            )

        return KBaseUser(v[0], v[1])

    async def _safe_profile_upsert(
        self, username: str, display_name: str | None, email: str | None
    ) -> None:
        """Upsert user profile, swallowing errors so auth is never blocked."""
        try:
            await self._profile_store.upsert(username, display_name, email)
        except Exception:
            logging.getLogger(__name__).warning(
                "Failed to capture profile for %s", username, exc_info=True
            )

    def _get_admin_role(self, roles: set[str]):
        if roles & self._full_roles:
            return AdminPermission.FULL
        return AdminPermission.NONE
