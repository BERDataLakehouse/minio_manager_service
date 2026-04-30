"""Single-flight TTL cache for read-heavy backend calls.

This module wraps :class:`cacheout.lru.LRUCache` with two extra
properties needed by the MMS read paths:

1. **TTL with explicit invalidation.** Cache entries expire after
   ``ttl_seconds`` *or* when a mutation calls :meth:`invalidate`. The
   TTL bounds staleness on its own; explicit invalidation makes
   "I just changed this, why isn't it reflected" debugging simple.

2. **Single-flight (request coalescing).** When ``N`` concurrent
   coroutines miss the cache for the same key, only one runs the
   loader; the others ``await`` its result. This eliminates the
   thundering-herd amplification we saw in prod when many users hit
   the Tenants page simultaneously after an MMS pod cold start
   (every one of them spawned a fresh ``mc admin group info`` storm).

The cache is **per-process**: each MMS replica maintains its own
state. That is intentional. We only need a few seconds of TTL to
collapse the request rate dramatically; cross-replica sharing
(e.g. Redis) is a future optimization, not a requirement.

Mutations explicitly invalidate keys so that an operator running an
``add_member`` request inside the same pod sees the new state on the
next read, regardless of TTL.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Generic, Hashable, TypeVar

from cacheout.lru import LRUCache

logger = logging.getLogger(__name__)

T = TypeVar("T")


class SingleFlightTTLCache(Generic[T]):
    """An LRU+TTL cache with per-key request coalescing.

    Concurrency model:

    * The internal ``LRUCache`` is thread-safe for individual operations
      (``get``/``set``/``delete``) by construction. We additionally hold
      a single :class:`asyncio.Lock` while bookkeeping the in-flight
      futures map, but the loader runs *outside* that lock so that
      concurrent loads for *different* keys still proceed in parallel.

    * If the loader raises, the exception is propagated to *every*
      coroutine that was awaiting the same key, and no value is cached.

    Args:
        name: Logical name used in log messages.
        maxsize: Maximum number of distinct keys retained.
        ttl_seconds: Time-to-live applied uniformly to every entry.
    """

    def __init__(self, name: str, maxsize: int, ttl_seconds: float) -> None:
        self._name = name
        self._cache: LRUCache = LRUCache(maxsize=maxsize, ttl=ttl_seconds)
        self._inflight: dict[Hashable, asyncio.Future[T]] = {}
        self._lock = asyncio.Lock()

    async def get_or_load(
        self,
        key: Hashable,
        loader: Callable[[], Awaitable[T]],
    ) -> T:
        """Return the cached value for ``key``, or run ``loader`` once and cache it.

        Concurrent ``get_or_load`` calls for the same key share one
        loader invocation: the first caller runs ``loader``, the rest
        ``await`` the resulting future.

        Args:
            key: A hashable cache key. For composite keys use a tuple.
            loader: Zero-arg async callable that produces the value
                when there is no cache entry. Only invoked on a miss
                (and exactly once per concurrent miss group).

        Returns:
            The cached or freshly-loaded value.

        Raises:
            Whatever ``loader`` raises. The exception is *not* cached.
        """
        # Fast path: cache hit, no lock acquisition.
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        async with self._lock:
            # Re-check under the lock: another coroutine may have just
            # populated the cache while we were waiting.
            cached = self._cache.get(key)
            if cached is not None:
                return cached

            inflight = self._inflight.get(key)
            if inflight is not None:
                # Another coroutine is already loading this key; piggyback.
                run_loader = False
            else:
                # We are the leader for this key.
                inflight = asyncio.get_running_loop().create_future()
                self._inflight[key] = inflight
                run_loader = True

        if not run_loader:
            return await inflight

        try:
            value = await loader()
        except BaseException as exc:
            inflight.set_exception(exc)
            # Mark the exception as retrieved on the leader's path so
            # asyncio does not log "Future exception was never retrieved"
            # when there happened to be no concurrent waiters. Followers
            # awaiting this same future still receive the exception via
            # ``await inflight`` above.
            inflight.exception()
            async with self._lock:
                # Remove the failed future so the *next* request retries.
                if self._inflight.get(key) is inflight:
                    del self._inflight[key]
            raise

        self._cache.set(key, value)
        inflight.set_result(value)
        async with self._lock:
            if self._inflight.get(key) is inflight:
                del self._inflight[key]
        return value

    def invalidate(self, key: Hashable) -> None:
        """Remove a single cache entry.

        In-flight loads for ``key`` are *not* cancelled — coroutines
        that were awaiting them still receive the result they were
        waiting for. The next read after the in-flight load completes
        will see the freshly-loaded value (and re-cache it). The point
        of invalidate is to ensure the *next* read does not return a
        stale cached value.
        """
        self._cache.delete(key)

    def invalidate_all(self) -> None:
        """Clear every cache entry. In-flight loads are unaffected."""
        self._cache.clear()

    def size(self) -> int:
        """Number of currently cached entries (excluding expired)."""
        return self._cache.size()

    def __repr__(self) -> str:
        return (
            f"SingleFlightTTLCache(name={self._name!r}, size={self.size()})"
        )
