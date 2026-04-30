"""Tests for service.cache.SingleFlightTTLCache.

We focus on the two non-trivial properties:

1. Single-flight: concurrent misses for the same key invoke the loader
   exactly once and all callers get the same value.
2. Mutation invalidation: ``invalidate(key)`` forces the next read to
   re-run the loader even before TTL has elapsed.
"""

import asyncio

import pytest

from service.cache import SingleFlightTTLCache


# ── Basic ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_or_load_caches_value():
    """Second read for the same key does not invoke the loader."""
    cache: SingleFlightTTLCache[int] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )
    calls = 0

    async def loader():
        nonlocal calls
        calls += 1
        return 42

    assert await cache.get_or_load("k", loader) == 42
    assert await cache.get_or_load("k", loader) == 42
    assert calls == 1


@pytest.mark.asyncio
async def test_distinct_keys_call_loader_independently():
    """Different keys do not share cached values or single-flight slots."""
    cache: SingleFlightTTLCache[str] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )

    async def loader_for(key):
        async def loader():
            return f"value-of-{key}"

        return loader

    assert await cache.get_or_load("a", await loader_for("a")) == "value-of-a"
    assert await cache.get_or_load("b", await loader_for("b")) == "value-of-b"
    assert cache.size() == 2


# ── TTL ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ttl_expiry_re_invokes_loader():
    cache: SingleFlightTTLCache[int] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=0.05
    )
    calls = 0

    async def loader():
        nonlocal calls
        calls += 1
        return calls

    assert await cache.get_or_load("k", loader) == 1
    await asyncio.sleep(0.10)
    assert await cache.get_or_load("k", loader) == 2
    assert calls == 2


# ── Invalidation ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_invalidate_forces_reload_before_ttl():
    cache: SingleFlightTTLCache[int] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )
    calls = 0

    async def loader():
        nonlocal calls
        calls += 1
        return calls

    assert await cache.get_or_load("k", loader) == 1
    cache.invalidate("k")
    assert await cache.get_or_load("k", loader) == 2
    assert calls == 2


@pytest.mark.asyncio
async def test_invalidate_other_key_does_not_affect_target():
    cache: SingleFlightTTLCache[int] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )
    counter = 0

    async def loader():
        nonlocal counter
        counter += 1
        return counter

    await cache.get_or_load("a", loader)  # counter=1
    await cache.get_or_load("b", loader)  # counter=2
    cache.invalidate("a")
    # 'b' is still cached; loader not invoked again.
    assert await cache.get_or_load("b", loader) == 2
    assert counter == 2


@pytest.mark.asyncio
async def test_invalidate_all_clears_every_key():
    cache: SingleFlightTTLCache[int] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )
    counter = 0

    async def loader():
        nonlocal counter
        counter += 1
        return counter

    await cache.get_or_load("a", loader)
    await cache.get_or_load("b", loader)
    cache.invalidate_all()
    assert cache.size() == 0
    # Both reload now.
    await cache.get_or_load("a", loader)
    await cache.get_or_load("b", loader)
    assert counter == 4


# ── Single-flight ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_misses_share_one_loader_call():
    """N concurrent misses for the same key must invoke the loader once."""
    cache: SingleFlightTTLCache[int] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )
    call_count = 0
    loader_started = asyncio.Event()
    loader_can_finish = asyncio.Event()

    async def slow_loader():
        nonlocal call_count
        call_count += 1
        loader_started.set()
        await loader_can_finish.wait()
        return 99

    # Fire 10 concurrent get_or_load calls for the same key. Wait until
    # the first loader is in-flight before letting it finish, so every
    # other coroutine has had a chance to attempt its own miss.
    tasks = [
        asyncio.create_task(cache.get_or_load("k", slow_loader)) for _ in range(10)
    ]
    await loader_started.wait()
    loader_can_finish.set()
    results = await asyncio.gather(*tasks)

    assert results == [99] * 10
    assert call_count == 1


@pytest.mark.asyncio
async def test_concurrent_misses_different_keys_run_in_parallel():
    """Misses for different keys do not block each other."""
    cache: SingleFlightTTLCache[str] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )

    DELAY = 0.05

    def make_loader(value):
        async def loader():
            await asyncio.sleep(DELAY)
            return value

        return loader

    loop = asyncio.get_running_loop()
    start = loop.time()
    results = await asyncio.gather(
        cache.get_or_load("a", make_loader("a")),
        cache.get_or_load("b", make_loader("b")),
        cache.get_or_load("c", make_loader("c")),
    )
    elapsed = loop.time() - start

    assert results == ["a", "b", "c"]
    # Sequential would be 3 * DELAY; concurrent should be ~DELAY.
    assert elapsed < 2 * DELAY


@pytest.mark.asyncio
async def test_loader_exception_is_propagated_and_not_cached():
    """A loader failure propagates to all waiters and does NOT cache."""
    cache: SingleFlightTTLCache[int] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )
    attempts = 0

    async def flaky_loader():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("boom")
        return 7

    with pytest.raises(RuntimeError, match="boom"):
        await cache.get_or_load("k", flaky_loader)

    # Next call retries (failure is not cached).
    assert await cache.get_or_load("k", flaky_loader) == 7
    assert attempts == 2


@pytest.mark.asyncio
async def test_concurrent_loader_failure_propagates_to_all_waiters():
    """All concurrent waiters see the same loader exception."""
    cache: SingleFlightTTLCache[int] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )
    loader_started = asyncio.Event()
    loader_can_finish = asyncio.Event()

    async def slow_failing_loader():
        loader_started.set()
        await loader_can_finish.wait()
        raise ValueError("nope")

    tasks = [
        asyncio.create_task(cache.get_or_load("k", slow_failing_loader))
        for _ in range(5)
    ]
    await loader_started.wait()
    loader_can_finish.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)

    assert all(isinstance(r, ValueError) and str(r) == "nope" for r in results)
    # Cache must still be empty so the next call retries.
    assert cache.size() == 0


# ── Composite keys ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tuple_keys_supported():
    """Composite (tuple) keys are valid and treated independently."""
    cache: SingleFlightTTLCache[str] = SingleFlightTTLCache(
        name="t", maxsize=8, ttl_seconds=60
    )

    async def loader_for(value):
        async def loader():
            return value

        return loader

    assert await cache.get_or_load(("a", 1), await loader_for("first")) == "first"
    assert await cache.get_or_load(("a", 2), await loader_for("second")) == "second"
    assert cache.size() == 2
