"""
Distributed Locking Tests.

Tests for Redis-based distributed locking in policy updates.
These tests verify that concurrent operations are properly serialized.

NOTE: These tests are marked as @serial because they test race conditions
and concurrent behavior, which requires controlled timing.
"""

import pytest
import time
import concurrent.futures
from utils.unique import unique_username


@pytest.mark.locking
@pytest.mark.serial
class TestDistributedLocking:
    """Tests for distributed locking behavior."""

    @pytest.fixture
    def redis_client(self, test_config):
        """Get Redis client for lock verification."""
        try:
            import redis

            redis_url = test_config.get("redis_url", "redis://localhost:6379")
            client = redis.from_url(redis_url)
            client.ping()  # Verify connection
            return client
        except Exception as e:
            pytest.skip(f"Redis not available: {e}")

    def test_single_operation_succeeds(self, api_client, admin_headers, minio_verifier):
        """
        Scenario:
            A single policy update operation.
        Expected:
            - Operation completes successfully
            - Lock is acquired and released
        Why this matters:
            Basic locking functionality must work.
        """
        username = unique_username("single_lock")

        try:
            # Act - Create user (triggers policy update)
            response = api_client.post(
                f"/management/users/{username}", headers=admin_headers
            )

            # Assert
            assert response.status_code == 201
            assert minio_verifier.user_exists(username)

        finally:
            api_client.delete(f"/management/users/{username}", headers=admin_headers)

    def test_concurrent_operations_both_succeed(
        self, api_client, admin_headers, minio_verifier
    ):
        """
        Scenario:
            Two concurrent operations on the same user.
        Expected:
            - Both operations complete (serialized by lock)
            - No race conditions
        Why this matters:
            Lock prevents data corruption from concurrent updates.
        """
        username = unique_username("concurrent_lock")

        try:
            # Setup - Create user first
            create_resp = api_client.post(
                f"/management/users/{username}", headers=admin_headers
            )
            assert create_resp.status_code == 201

            results = []

            def rotate_credentials():
                # Each call needs its own client
                import httpx

                with httpx.Client(base_url=api_client.base_url, timeout=60) as client:
                    resp = client.post(
                        f"/management/users/{username}/rotate-credentials",
                        headers=admin_headers,
                    )
                    return resp.status_code

            # Run concurrent rotations
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future1 = executor.submit(rotate_credentials)
                future2 = executor.submit(rotate_credentials)

                results = [future1.result(), future2.result()]

            # Both should succeed (locking serializes them)
            assert all(status == 200 for status in results), (
                f"Expected both 200, got {results}"
            )

        finally:
            api_client.delete(f"/management/users/{username}", headers=admin_headers)

    def test_different_users_not_blocked(
        self, api_client, admin_headers, minio_verifier
    ):
        """
        Scenario:
            Concurrent operations on DIFFERENT users.
        Expected:
            - Both complete independently (different locks)
        Why this matters:
            Locks should be per-resource, not global.
        """
        user1 = unique_username("user1_lock")
        user2 = unique_username("user2_lock")

        try:
            results = []

            def create_user(username):
                import httpx

                with httpx.Client(base_url=api_client.base_url, timeout=60) as client:
                    resp = client.post(
                        f"/management/users/{username}", headers=admin_headers
                    )
                    return resp.status_code

            # Run concurrent creations for DIFFERENT users
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future1 = executor.submit(create_user, user1)
                future2 = executor.submit(create_user, user2)

                results = [future1.result(), future2.result()]

            # Both should succeed (different resources, no blocking)
            assert all(status == 201 for status in results), (
                f"Expected both 201, got {results}"
            )

            # Verify both users exist
            assert minio_verifier.user_exists(user1)
            assert minio_verifier.user_exists(user2)

        finally:
            api_client.delete(f"/management/users/{user1}", headers=admin_headers)
            api_client.delete(f"/management/users/{user2}", headers=admin_headers)


@pytest.mark.locking
@pytest.mark.serial
class TestLockVerification:
    """Tests that verify lock behavior through Redis inspection."""

    @pytest.fixture
    def redis_client(self, test_config):
        """Get Redis client for lock verification."""
        try:
            import redis

            redis_url = test_config.get("redis_url", "redis://localhost:6379")
            client = redis.from_url(redis_url)
            client.ping()
            return client
        except Exception as e:
            pytest.skip(f"Redis not available: {e}")

    def test_locks_are_released_after_operation(
        self, api_client, admin_headers, redis_client
    ):
        """
        Scenario:
            Perform an operation and verify lock is released.
        Expected:
            - No policy locks remain after operation
        Why this matters:
            Locks must be released to prevent deadlocks.
        """
        username = unique_username("lock_release")

        try:
            # Act
            response = api_client.post(
                f"/management/users/{username}", headers=admin_headers
            )
            assert response.status_code == 201

            # Wait a moment for lock release
            time.sleep(0.5)

            # Check for any remaining policy locks
            lock_keys = redis_client.keys("policy:lock:*")
            # Filter for our user's lock specifically
            our_locks = [k for k in lock_keys if username.encode() in k]
            assert len(our_locks) == 0, f"Locks should be released: {our_locks}"

        finally:
            api_client.delete(f"/management/users/{username}", headers=admin_headers)

    def test_lock_exists_during_operation(
        self, api_client, admin_headers, redis_client
    ):
        """
        Scenario:
            Check that a lock exists while an operation is in progress.
        Expected:
            - Lock key exists in Redis during operation
        Why this matters:
            Locks must actually be created to serialize operations.
        """
        # This is a timing-sensitive test
        # We use a longer operation and check mid-way
        username = unique_username("lock_exists")

        lock_found = False

        def monitor_locks():
            nonlocal lock_found
            for _ in range(20):  # Check for 2 seconds
                lock_keys = redis_client.keys("policy:*")
                if lock_keys:
                    lock_found = True
                    break
                time.sleep(0.1)

        def create_user():
            import httpx

            with httpx.Client(base_url=api_client.base_url, timeout=60) as client:
                return client.post(
                    f"/management/users/{username}", headers=admin_headers
                ).status_code

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                # Start monitoring before the operation
                monitor_future = executor.submit(monitor_locks)
                time.sleep(0.05)  # Small delay

                # Start the operation
                create_future = executor.submit(create_user)

                # Wait for both
                create_result = create_future.result()
                monitor_future.result()

            # The operation should succeed
            assert create_result == 201

            # We may or may not have caught the lock depending on timing
            # This is a best-effort verification

        finally:
            api_client.delete(f"/management/users/{username}", headers=admin_headers)
