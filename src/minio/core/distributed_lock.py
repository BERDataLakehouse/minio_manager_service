import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

import redis.asyncio as redis

from ...service.exceptions import PolicyOperationError

logger = logging.getLogger(__name__)

REDIS_LOCK_TIMEOUT = (
    30  # seconds; ensure this safely exceeds worst-case critical section duration
)


class DistributedLockManager:
    """
    Redis-based distributed locking for coordinating policy updates across multiple instances.

    This manager provides distributed mutual exclusion to prevent race conditions when
    multiple service instances attempt to update the same MinIO policy simultaneously.
    """

    def __init__(self):
        """
        Initialize the distributed lock manager.
        """
        self.redis_url = os.getenv("REDIS_URL")
        if not self.redis_url:
            raise ValueError("REDIS_URL is missing from environment variables")
        self.default_timeout = REDIS_LOCK_TIMEOUT
        self.redis = redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )

    async def close(self):
        """Close Redis connection."""
        await self.redis.close()

    @asynccontextmanager
    async def policy_update_lock(self, policy_name: str, timeout: Optional[int] = None):
        """
        Acquire a distributed lock for policy updates.

        This context manager ensures that only one instance can update a specific
        policy at a time. The lock automatically expires after the timeout period
        to prevent deadlocks from crashed instances.

        Args:
            policy_name: Name of the policy to lock
            timeout: Lock timeout in seconds (uses default if None). Set this high
                enough to cover the entire critical section. If too short, the lock
                may expire mid-operation, especially under slow networks or high
                server load, which risks concurrent modifications.

        Raises:
            PolicyOperationError: If the lock cannot be acquired
        """
        timeout = timeout or self.default_timeout

        lock_key = f"policy_lock:{policy_name}"

        lock = self.redis.lock(name=lock_key, timeout=timeout)

        if not await lock.acquire(blocking=False):
            raise PolicyOperationError(
                f"Policy '{policy_name}' is currently locked. Try again later."
            )

        logger.info(f"Acquired lock on '{policy_name}'")
        try:
            yield lock
        finally:
            try:
                await lock.release()
                logger.info(f"Released lock on '{policy_name}'")
            except Exception as e:
                logger.warning(f"Failed to release lock '{lock_key}': {e}")

    async def is_policy_locked(self, policy_name: str) -> bool:
        """
        Check if a policy is currently locked by any instance.

        Args:
            policy_name: Name of the policy to check

        Returns:
            bool: True if the policy is locked, False otherwise
        """
        lock_key = f"policy_lock:{policy_name}"
        return await self.redis.exists(lock_key) == 1

    async def health_check(self) -> bool:
        """
        Perform a health check on the Redis connection.

        Returns:
            bool: True if Redis is accessible, False otherwise
        """
        try:
            await self.redis.ping()
            return True
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False
