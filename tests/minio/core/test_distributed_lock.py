"""Comprehensive tests for the minio.core.distributed_lock module."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.minio.core.distributed_lock import DistributedLockManager, REDIS_LOCK_TIMEOUT
from src.service.exceptions import PolicyOperationError


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def mock_redis_url():
    """Mock REDIS_URL environment variable."""
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"}):
        yield


@pytest.fixture
def mock_redis_client():
    """Create a mock Redis client."""
    redis_client = AsyncMock()
    redis_client.close = AsyncMock()
    redis_client.ping = AsyncMock(return_value=True)
    redis_client.exists = AsyncMock(return_value=0)

    # Create mock lock
    mock_lock = AsyncMock()
    mock_lock.acquire = AsyncMock(return_value=True)
    mock_lock.release = AsyncMock()
    redis_client.lock = MagicMock(return_value=mock_lock)

    return redis_client


@pytest.fixture
def lock_manager_with_mock_redis(mock_redis_client):
    """Create a DistributedLockManager with mocked Redis client."""
    with patch("src.minio.core.distributed_lock.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis_client
        manager = DistributedLockManager()
        manager.redis = mock_redis_client
        yield manager


# =============================================================================
# TEST INITIALIZATION
# =============================================================================


class TestDistributedLockManagerInit:
    """Tests for DistributedLockManager initialization."""

    def test_init_with_redis_url(self):
        """Test successful initialization with REDIS_URL."""
        with patch("src.minio.core.distributed_lock.redis") as mock_redis:
            mock_redis.from_url.return_value = MagicMock()

            manager = DistributedLockManager()

            assert manager.redis_url == "redis://localhost:6379/0"
            assert manager.default_timeout == REDIS_LOCK_TIMEOUT
            mock_redis.from_url.assert_called_once()

    def test_init_without_redis_url(self):
        """Test initialization fails without REDIS_URL."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove REDIS_URL from environment
            os.environ.pop("REDIS_URL", None)

            with pytest.raises(ValueError) as exc_info:
                DistributedLockManager()

            assert "REDIS_URL" in str(exc_info.value)

    def test_init_redis_connection_parameters(self):
        """Test Redis connection is created with correct parameters."""
        with patch("src.minio.core.distributed_lock.redis") as mock_redis:
            mock_redis.from_url.return_value = MagicMock()

            DistributedLockManager()

            mock_redis.from_url.assert_called_once_with(
                "redis://localhost:6379/0",
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )


# =============================================================================
# TEST CLOSE
# =============================================================================


class TestClose:
    """Tests for close method."""

    @pytest.mark.asyncio
    async def test_close_redis_connection(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test close properly closes Redis connection."""
        await lock_manager_with_mock_redis.close()

        mock_redis_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_multiple_times(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test close can be called multiple times safely."""
        await lock_manager_with_mock_redis.close()
        await lock_manager_with_mock_redis.close()

        assert mock_redis_client.close.call_count == 2


# =============================================================================
# TEST POLICY UPDATE LOCK
# =============================================================================


class TestPolicyUpdateLock:
    """Tests for policy_update_lock context manager."""

    @pytest.mark.asyncio
    async def test_acquire_and_release_lock_success(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test successfully acquiring and releasing a lock."""
        mock_lock = mock_redis_client.lock.return_value

        async with lock_manager_with_mock_redis.policy_update_lock("test-policy"):
            # Inside the context, lock should have been acquired
            mock_lock.acquire.assert_called_once_with(blocking=False)

        # After context, lock should be released
        mock_lock.release.assert_called_once()

    @pytest.mark.asyncio
    async def test_lock_key_format(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test lock key is formatted correctly."""
        async with lock_manager_with_mock_redis.policy_update_lock("my-policy"):
            pass

        mock_redis_client.lock.assert_called_once_with(
            name="policy_lock:my-policy", timeout=REDIS_LOCK_TIMEOUT
        )

    @pytest.mark.asyncio
    async def test_lock_with_custom_timeout(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test lock with custom timeout."""
        custom_timeout = 60

        async with lock_manager_with_mock_redis.policy_update_lock(
            "test-policy", timeout=custom_timeout
        ):
            pass

        mock_redis_client.lock.assert_called_once_with(
            name="policy_lock:test-policy", timeout=custom_timeout
        )

    @pytest.mark.asyncio
    async def test_lock_acquisition_failure(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test lock acquisition failure raises PolicyOperationError."""
        mock_lock = mock_redis_client.lock.return_value
        mock_lock.acquire.return_value = False

        with pytest.raises(PolicyOperationError) as exc_info:
            async with lock_manager_with_mock_redis.policy_update_lock("locked-policy"):
                pass

        assert "locked" in str(exc_info.value).lower()
        assert "locked-policy" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_lock_release_failure_handled(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test lock release failure is handled gracefully (logged, not raised)."""
        mock_lock = mock_redis_client.lock.return_value
        mock_lock.release.side_effect = Exception("Release failed")

        # Should not raise - exception is logged but not propagated
        async with lock_manager_with_mock_redis.policy_update_lock("test-policy"):
            pass

        # Release was attempted
        mock_lock.release.assert_called_once()

    @pytest.mark.asyncio
    async def test_lock_releases_on_exception_in_context(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test lock is released even when exception occurs in context."""
        mock_lock = mock_redis_client.lock.return_value

        with pytest.raises(RuntimeError):
            async with lock_manager_with_mock_redis.policy_update_lock("test-policy"):
                raise RuntimeError("Something went wrong")

        # Lock should still be released
        mock_lock.release.assert_called_once()

    @pytest.mark.asyncio
    async def test_lock_yields_lock_object(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test the context manager yields the lock object."""
        mock_lock = mock_redis_client.lock.return_value

        async with lock_manager_with_mock_redis.policy_update_lock(
            "test-policy"
        ) as lock:
            assert lock is mock_lock

    @pytest.mark.asyncio
    async def test_multiple_locks_different_policies(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test acquiring locks for different policies."""
        async with lock_manager_with_mock_redis.policy_update_lock("policy-a"):
            pass

        mock_redis_client.lock.reset_mock()

        async with lock_manager_with_mock_redis.policy_update_lock("policy-b"):
            pass

        # Both locks should use different keys
        calls = mock_redis_client.lock.call_args_list
        assert len(calls) >= 1
        assert calls[0][1]["name"] == "policy_lock:policy-b"


# =============================================================================
# TEST IS POLICY LOCKED
# =============================================================================


class TestIsPolicyLocked:
    """Tests for is_policy_locked method."""

    @pytest.mark.asyncio
    async def test_policy_is_locked(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test is_policy_locked returns True when policy is locked."""
        mock_redis_client.exists.return_value = 1

        result = await lock_manager_with_mock_redis.is_policy_locked("locked-policy")

        assert result is True
        mock_redis_client.exists.assert_called_once_with("policy_lock:locked-policy")

    @pytest.mark.asyncio
    async def test_policy_is_not_locked(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test is_policy_locked returns False when policy is not locked."""
        mock_redis_client.exists.return_value = 0

        result = await lock_manager_with_mock_redis.is_policy_locked("unlocked-policy")

        assert result is False
        mock_redis_client.exists.assert_called_once_with("policy_lock:unlocked-policy")

    @pytest.mark.asyncio
    async def test_is_policy_locked_key_format(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test is_policy_locked uses correct key format."""
        await lock_manager_with_mock_redis.is_policy_locked("test-policy")

        mock_redis_client.exists.assert_called_once_with("policy_lock:test-policy")


# =============================================================================
# TEST HEALTH CHECK
# =============================================================================


class TestHealthCheck:
    """Tests for health_check method."""

    @pytest.mark.asyncio
    async def test_health_check_success(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test health_check returns True when Redis is accessible."""
        mock_redis_client.ping.return_value = True

        result = await lock_manager_with_mock_redis.health_check()

        assert result is True
        mock_redis_client.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_failure(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test health_check returns False when Redis is not accessible."""
        mock_redis_client.ping.side_effect = Exception("Connection refused")

        result = await lock_manager_with_mock_redis.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_timeout(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test health_check returns False on timeout."""

        mock_redis_client.ping.side_effect = asyncio.TimeoutError("Timeout")

        result = await lock_manager_with_mock_redis.health_check()

        assert result is False


# =============================================================================
# TEST EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_lock_with_special_characters_in_policy_name(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test lock handling policy names with special characters."""
        policy_name = "user-home-policy-user.name@domain"

        async with lock_manager_with_mock_redis.policy_update_lock(policy_name):
            pass

        mock_redis_client.lock.assert_called_once_with(
            name=f"policy_lock:{policy_name}", timeout=REDIS_LOCK_TIMEOUT
        )

    @pytest.mark.asyncio
    async def test_lock_with_empty_policy_name(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test lock with empty policy name (edge case)."""
        async with lock_manager_with_mock_redis.policy_update_lock(""):
            pass

        mock_redis_client.lock.assert_called_once_with(
            name="policy_lock:", timeout=REDIS_LOCK_TIMEOUT
        )

    @pytest.mark.asyncio
    async def test_lock_with_unicode_policy_name(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test lock with unicode characters in policy name."""
        policy_name = "policy-数据-policy"

        async with lock_manager_with_mock_redis.policy_update_lock(policy_name):
            pass

        mock_redis_client.lock.assert_called_once_with(
            name=f"policy_lock:{policy_name}", timeout=REDIS_LOCK_TIMEOUT
        )

    @pytest.mark.asyncio
    async def test_default_timeout_value(self, lock_manager_with_mock_redis):
        """Test default timeout is set correctly."""
        assert lock_manager_with_mock_redis.default_timeout == 30
        assert REDIS_LOCK_TIMEOUT == 30

    def test_redis_url_attribute(self, lock_manager_with_mock_redis):
        """Test redis_url attribute is set."""
        assert lock_manager_with_mock_redis.redis_url == "redis://localhost:6379/0"

    @pytest.mark.asyncio
    async def test_concurrent_lock_attempts_same_policy(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test that second lock attempt fails when policy is already locked."""
        mock_lock = mock_redis_client.lock.return_value

        # First attempt succeeds
        mock_lock.acquire.return_value = True
        async with lock_manager_with_mock_redis.policy_update_lock("shared-policy"):
            # Second attempt fails (simulating concurrent access)
            mock_lock.acquire.return_value = False

            with pytest.raises(PolicyOperationError):
                async with lock_manager_with_mock_redis.policy_update_lock(
                    "shared-policy"
                ):
                    pass

    @pytest.mark.asyncio
    async def test_lock_non_blocking(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test lock is acquired in non-blocking mode."""
        mock_lock = mock_redis_client.lock.return_value

        async with lock_manager_with_mock_redis.policy_update_lock("test-policy"):
            pass

        # Verify blocking=False was passed
        mock_lock.acquire.assert_called_with(blocking=False)


# =============================================================================
# TEST CONSTANTS
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_redis_lock_timeout_value(self):
        """Test REDIS_LOCK_TIMEOUT is set to expected value."""
        assert REDIS_LOCK_TIMEOUT == 30

    def test_redis_lock_timeout_is_int(self):
        """Test REDIS_LOCK_TIMEOUT is an integer."""
        assert isinstance(REDIS_LOCK_TIMEOUT, int)


# =============================================================================
# TEST INTEGRATION SCENARIOS
# =============================================================================


class TestIntegrationScenarios:
    """Tests for integration-like scenarios."""

    @pytest.mark.asyncio
    async def test_lock_workflow_complete(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test complete lock workflow: acquire, use, release."""
        mock_lock = mock_redis_client.lock.return_value
        workflow_steps = []

        mock_lock.acquire.side_effect = (
            lambda **kwargs: workflow_steps.append("acquire") or True
        )
        mock_lock.release.side_effect = lambda: workflow_steps.append("release")

        async with lock_manager_with_mock_redis.policy_update_lock("workflow-policy"):
            workflow_steps.append("work")

        assert workflow_steps == ["acquire", "work", "release"]

    @pytest.mark.asyncio
    async def test_error_recovery_workflow(
        self, lock_manager_with_mock_redis, mock_redis_client
    ):
        """Test error recovery: exception in context still releases lock."""
        mock_lock = mock_redis_client.lock.return_value
        release_called = []

        mock_lock.release.side_effect = lambda: release_called.append(True)

        with pytest.raises(ValueError):
            async with lock_manager_with_mock_redis.policy_update_lock("error-policy"):
                raise ValueError("Simulated error")

        assert len(release_called) == 1
