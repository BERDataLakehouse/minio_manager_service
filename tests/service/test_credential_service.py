"""
Tests for the CredentialService class.

Tests cover:
- get_or_create: cache hit fast path, cache miss with lock, double-check pattern
- rotate: lock + delete + rotate + store flow
- Auto-creation of new users
- Distributed lock acquisition and contention
- Error propagation from MinIO and DB layers
"""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.credentials.service import CredentialService
from src.service.exceptions import CredentialOperationError


# === FIXTURES ===


def _make_credential_lock():
    """Create a mock credential_lock async context manager."""

    @asynccontextmanager
    async def credential_lock(username, timeout=None):
        yield MagicMock()

    return credential_lock


@pytest.fixture
def mock_user_manager():
    """Create a mock UserManager."""
    mgr = AsyncMock()
    mgr.resource_exists = AsyncMock(return_value=True)
    mgr.get_or_rotate_user_credentials = AsyncMock(
        return_value=("testuser", "rotated-secret-123")
    )
    mock_user_model = MagicMock()
    mock_user_model.access_key = "testuser"
    mock_user_model.secret_key = "created-secret-456"
    mgr.create_user = AsyncMock(return_value=mock_user_model)
    return mgr


@pytest.fixture
def mock_credential_store():
    """Create a mock CredentialStore."""
    store = AsyncMock()
    store.get_credentials = AsyncMock(return_value=None)
    store.store_credentials = AsyncMock()
    store.delete_credentials = AsyncMock()
    return store


@pytest.fixture
def mock_lock_manager():
    """Create a mock DistributedLockManager."""
    mgr = MagicMock()
    mgr.credential_lock = _make_credential_lock()
    return mgr


@pytest.fixture
def service(mock_user_manager, mock_credential_store, mock_lock_manager):
    """Create a CredentialService with mocked dependencies."""
    return CredentialService(
        user_manager=mock_user_manager,
        credential_store=mock_credential_store,
        lock_manager=mock_lock_manager,
    )


# === GET_OR_CREATE TESTS ===


class TestGetOrCreate:
    """Tests for CredentialService.get_or_create."""

    @pytest.mark.asyncio
    async def test_cache_hit_returns_immediately(self, service, mock_credential_store):
        """Test fast path: cache hit returns without locking or MinIO calls."""
        mock_credential_store.get_credentials.return_value = (
            "testuser",
            "cached-secret",
        )

        result = await service.get_or_create("testuser")

        assert result == ("testuser", "cached-secret")
        # Only one cache check (fast path), no store, no MinIO
        mock_credential_store.get_credentials.assert_called_once_with("testuser")
        mock_credential_store.store_credentials.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_miss_existing_user_rotates(
        self, service, mock_user_manager, mock_credential_store
    ):
        """Test cache miss for existing user: lock → rotate → store."""
        mock_credential_store.get_credentials.return_value = None
        mock_user_manager.resource_exists.return_value = True

        result = await service.get_or_create("testuser")

        assert result == ("testuser", "rotated-secret-123")
        mock_user_manager.get_or_rotate_user_credentials.assert_called_once_with(
            "testuser"
        )
        mock_credential_store.store_credentials.assert_called_once_with(
            "testuser", "testuser", "rotated-secret-123"
        )

    @pytest.mark.asyncio
    async def test_cache_miss_new_user_creates(
        self, service, mock_user_manager, mock_credential_store
    ):
        """Test cache miss for new user: lock → create → store."""
        mock_credential_store.get_credentials.return_value = None
        mock_user_manager.resource_exists.return_value = False

        result = await service.get_or_create("newuser")

        assert result == ("testuser", "created-secret-456")
        mock_user_manager.create_user.assert_called_once_with(username="newuser")
        mock_credential_store.store_credentials.assert_called_once_with(
            "newuser", "testuser", "created-secret-456"
        )

    @pytest.mark.asyncio
    async def test_double_check_prevents_duplicate_work(
        self, service, mock_user_manager, mock_credential_store, mock_lock_manager
    ):
        """Test double-check pattern: cache populated between fast-path miss and lock acquire."""
        call_count = 0

        async def get_creds_side_effect(username):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None  # Fast path: miss
            return ("testuser", "populated-by-another-request")  # Post-lock: hit

        mock_credential_store.get_credentials = AsyncMock(
            side_effect=get_creds_side_effect
        )

        result = await service.get_or_create("testuser")

        assert result == ("testuser", "populated-by-another-request")
        # MinIO should NOT be called — another request already populated the cache
        mock_user_manager.resource_exists.assert_not_called()
        mock_user_manager.get_or_rotate_user_credentials.assert_not_called()
        mock_credential_store.store_credentials.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_lock_on_cache_hit(
        self, service, mock_credential_store, mock_lock_manager
    ):
        """Test that lock is not acquired when cache hits on fast path."""
        mock_credential_store.get_credentials.return_value = (
            "testuser",
            "cached-secret",
        )
        lock_acquired = []

        @asynccontextmanager
        async def tracking_lock(username, timeout=None):
            lock_acquired.append(username)
            yield MagicMock()

        mock_lock_manager.credential_lock = tracking_lock
        service._lock_manager = mock_lock_manager

        await service.get_or_create("testuser")

        assert lock_acquired == []

    @pytest.mark.asyncio
    async def test_lock_acquired_on_cache_miss(
        self, service, mock_credential_store, mock_lock_manager
    ):
        """Test that lock IS acquired when cache misses."""
        mock_credential_store.get_credentials.return_value = None
        lock_acquired = []

        @asynccontextmanager
        async def tracking_lock(username, timeout=None):
            lock_acquired.append(username)
            yield MagicMock()

        mock_lock_manager.credential_lock = tracking_lock
        service._lock_manager = mock_lock_manager

        await service.get_or_create("alice")

        assert lock_acquired == ["alice"]

    @pytest.mark.asyncio
    async def test_lock_contention_raises(
        self, service, mock_credential_store, mock_lock_manager
    ):
        """Test that CredentialOperationError propagates on lock contention."""
        mock_credential_store.get_credentials.return_value = None

        @asynccontextmanager
        async def failing_lock(username, timeout=None):
            raise CredentialOperationError(
                f"Credential operation for user '{username}' timed out."
            )
            yield  # pragma: no cover

        mock_lock_manager.credential_lock = failing_lock
        service._lock_manager = mock_lock_manager

        with pytest.raises(CredentialOperationError, match="timed out"):
            await service.get_or_create("alice")

    @pytest.mark.asyncio
    async def test_minio_create_user_error_propagates(
        self, service, mock_user_manager, mock_credential_store
    ):
        """Test that MinIO errors propagate without storing credentials."""
        mock_credential_store.get_credentials.return_value = None
        mock_user_manager.resource_exists.return_value = False
        mock_user_manager.create_user.side_effect = Exception("MinIO unreachable")

        with pytest.raises(Exception, match="MinIO unreachable"):
            await service.get_or_create("newuser")

        mock_credential_store.store_credentials.assert_not_called()

    @pytest.mark.asyncio
    async def test_minio_rotate_error_propagates(
        self, service, mock_user_manager, mock_credential_store
    ):
        """Test that MinIO rotation errors propagate without storing."""
        mock_credential_store.get_credentials.return_value = None
        mock_user_manager.resource_exists.return_value = True
        mock_user_manager.get_or_rotate_user_credentials.side_effect = Exception(
            "Rotation failed"
        )

        with pytest.raises(Exception, match="Rotation failed"):
            await service.get_or_create("testuser")

        mock_credential_store.store_credentials.assert_not_called()

    @pytest.mark.asyncio
    async def test_store_error_propagates(
        self, service, mock_user_manager, mock_credential_store
    ):
        """Test that DB store errors propagate (credentials rotated but not cached)."""
        mock_credential_store.get_credentials.return_value = None
        mock_user_manager.resource_exists.return_value = True
        mock_credential_store.store_credentials.side_effect = Exception("DB timeout")

        with pytest.raises(Exception, match="DB timeout"):
            await service.get_or_create("testuser")


# === ROTATE TESTS ===


class TestRotate:
    """Tests for CredentialService.rotate."""

    @pytest.mark.asyncio
    async def test_rotate_existing_user(
        self, service, mock_user_manager, mock_credential_store
    ):
        """Test rotate: delete stale → rotate in MinIO → store new."""
        mock_user_manager.resource_exists.return_value = True

        result = await service.rotate("testuser")

        assert result == ("testuser", "rotated-secret-123")

        # Verify order: delete first, then rotate, then store
        mock_credential_store.delete_credentials.assert_called_once_with("testuser")
        mock_user_manager.get_or_rotate_user_credentials.assert_called_once_with(
            "testuser"
        )
        mock_credential_store.store_credentials.assert_called_once_with(
            "testuser", "testuser", "rotated-secret-123"
        )

    @pytest.mark.asyncio
    async def test_rotate_new_user_auto_creates(
        self, service, mock_user_manager, mock_credential_store
    ):
        """Test rotate auto-creates user if not exists."""
        mock_user_manager.resource_exists.return_value = False

        result = await service.rotate("newuser")

        assert result == ("testuser", "created-secret-456")
        mock_credential_store.delete_credentials.assert_called_once_with("newuser")
        mock_user_manager.create_user.assert_called_once_with(username="newuser")
        mock_credential_store.store_credentials.assert_called_once_with(
            "newuser", "testuser", "created-secret-456"
        )

    @pytest.mark.asyncio
    async def test_rotate_always_acquires_lock(
        self, service, mock_lock_manager, mock_credential_store
    ):
        """Test that rotate always acquires the lock."""
        lock_acquired = []

        @asynccontextmanager
        async def tracking_lock(username, timeout=None):
            lock_acquired.append(username)
            yield MagicMock()

        mock_lock_manager.credential_lock = tracking_lock
        service._lock_manager = mock_lock_manager

        await service.rotate("alice")

        assert lock_acquired == ["alice"]

    @pytest.mark.asyncio
    async def test_rotate_lock_contention_raises(
        self, service, mock_lock_manager, mock_credential_store
    ):
        """Test that lock contention during rotate raises CredentialOperationError."""

        @asynccontextmanager
        async def failing_lock(username, timeout=None):
            raise CredentialOperationError(
                f"Credential operation for user '{username}' timed out."
            )
            yield  # pragma: no cover

        mock_lock_manager.credential_lock = failing_lock
        service._lock_manager = mock_lock_manager

        with pytest.raises(CredentialOperationError, match="timed out"):
            await service.rotate("alice")

    @pytest.mark.asyncio
    async def test_rotate_deletes_before_minio_call(
        self, service, mock_user_manager, mock_credential_store
    ):
        """Test that stale creds are deleted before MinIO rotation.

        This ensures that if MinIO rotation succeeds but store fails,
        a subsequent GET won't return the old (now invalid) credentials.
        """
        call_order = []

        async def track_delete(username):
            call_order.append("delete")

        async def track_rotate(username):
            call_order.append("rotate")
            return ("testuser", "new-secret")

        async def track_store(username, ak, sk):
            call_order.append("store")

        mock_credential_store.delete_credentials = AsyncMock(side_effect=track_delete)
        mock_user_manager.resource_exists.return_value = True
        mock_user_manager.get_or_rotate_user_credentials = AsyncMock(
            side_effect=track_rotate
        )
        mock_credential_store.store_credentials = AsyncMock(side_effect=track_store)

        await service.rotate("testuser")

        assert call_order == ["delete", "rotate", "store"]

    @pytest.mark.asyncio
    async def test_rotate_minio_error_leaves_no_stale_creds(
        self, service, mock_user_manager, mock_credential_store
    ):
        """Test that if MinIO rotation fails, stale creds are already deleted."""
        mock_user_manager.resource_exists.return_value = True
        mock_user_manager.get_or_rotate_user_credentials.side_effect = Exception(
            "MinIO error"
        )

        with pytest.raises(Exception, match="MinIO error"):
            await service.rotate("testuser")

        # Delete should have been called before the error
        mock_credential_store.delete_credentials.assert_called_once_with("testuser")
        # Store should NOT have been called
        mock_credential_store.store_credentials.assert_not_called()


# === CONSTRUCTOR TESTS ===


class TestCredentialServiceInit:
    """Tests for CredentialService initialization."""

    def test_init_stores_dependencies(
        self, mock_user_manager, mock_credential_store, mock_lock_manager
    ):
        """Test that constructor stores all dependencies."""
        svc = CredentialService(
            user_manager=mock_user_manager,
            credential_store=mock_credential_store,
            lock_manager=mock_lock_manager,
        )
        assert svc._user_manager is mock_user_manager
        assert svc._credential_store is mock_credential_store
        assert svc._lock_manager is mock_lock_manager
