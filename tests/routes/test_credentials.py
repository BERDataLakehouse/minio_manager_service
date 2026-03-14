"""
Comprehensive tests for the routes.credentials module.

Tests cover:
- get_credentials endpoint (cache-first behavior)
- rotate_credentials endpoint
- User auto-creation for new users
- Credential caching via CredentialStore
- Authentication dependency integration
- Response model validation
- Error handling scenarios
"""

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.routes.credentials import (
    CredentialsResponse,
    get_credentials,
    rotate_credentials,
    router,
)
from src.service.app_state import AppState
from src.service.dependencies import auth
from src.service.exceptions import CredentialOperationError
from src.service.kb_auth import AdminPermission, KBaseUser


# === FIXTURES ===


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Ensure MC_PATH is set for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


def _make_credential_lock():
    """Create a mock credential_lock async context manager."""

    @asynccontextmanager
    async def credential_lock(username, timeout=None):
        yield MagicMock()

    return credential_lock


@pytest.fixture
def mock_app_state():
    """Create a mock application state."""
    app_state = MagicMock(spec=AppState)

    # Mock user manager
    app_state.user_manager = AsyncMock()
    app_state.user_manager.resource_exists = AsyncMock(return_value=True)
    app_state.user_manager.get_or_rotate_user_credentials = AsyncMock(
        return_value=("testuser", "test-secret-key-123")
    )

    # Mock create_user return value
    mock_user_model = MagicMock()
    mock_user_model.access_key = "testuser"
    mock_user_model.secret_key = "new-secret-key-123"
    app_state.user_manager.create_user = AsyncMock(return_value=mock_user_model)

    # Mock credential store — default: cache miss
    app_state.credential_store = AsyncMock()
    app_state.credential_store.get_credentials = AsyncMock(return_value=None)
    app_state.credential_store.store_credentials = AsyncMock()
    app_state.credential_store.delete_credentials = AsyncMock()

    # Mock lock manager with credential_lock as async context manager
    app_state.lock_manager = MagicMock()
    app_state.lock_manager.credential_lock = _make_credential_lock()

    return app_state


@pytest.fixture
def mock_auth_user():
    """Create a mock authenticated user."""
    return KBaseUser(user="testuser", admin_perm=AdminPermission.FULL)


@pytest.fixture
def test_app(mock_app_state, mock_auth_user):
    """Create a test FastAPI application with mocked dependencies."""
    app = FastAPI()
    app.include_router(router)

    # Override auth dependency
    app.dependency_overrides[auth] = lambda: mock_auth_user

    return app


@pytest.fixture
def client(test_app, mock_app_state):
    """Create a test client with get_app_state patched."""
    with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
        yield TestClient(test_app)


# === CREDENTIALS RESPONSE MODEL TESTS ===


class TestCredentialsResponse:
    """Tests for CredentialsResponse model."""

    def test_credentials_response_valid(self):
        """Test creating a valid CredentialsResponse."""
        response = CredentialsResponse(
            username="testuser",
            access_key="testuser",
            secret_key="test-secret-key-123456",
        )
        assert response.username == "testuser"
        assert response.access_key == "testuser"
        assert response.secret_key == "test-secret-key-123456"

    def test_credentials_response_strips_whitespace(self):
        """Test that CredentialsResponse strips whitespace."""
        response = CredentialsResponse(
            username="  testuser  ",
            access_key="  testuser  ",
            secret_key="test-secret-key-123456",
        )
        assert response.username == "testuser"
        assert response.access_key == "testuser"

    def test_credentials_response_frozen(self):
        """Test that CredentialsResponse is immutable."""
        response = CredentialsResponse(
            username="testuser",
            access_key="testuser",
            secret_key="test-secret-key-123456",
        )
        with pytest.raises(Exception):  # frozen models raise on assignment
            response.username = "changed"

    def test_credentials_response_username_min_length(self):
        """Test username minimum length validation."""
        with pytest.raises(ValueError):
            CredentialsResponse(
                username="",
                access_key="testuser",
                secret_key="test-secret-key-123456",
            )

    def test_credentials_response_secret_key_min_length(self):
        """Test secret_key minimum length validation."""
        with pytest.raises(ValueError):
            CredentialsResponse(
                username="testuser",
                access_key="testuser",
                secret_key="short",  # less than 8 characters
            )


# === GET CREDENTIALS ENDPOINT TESTS ===


class TestGetCredentialsEndpoint:
    """Tests for get_credentials endpoint (cache-first behavior)."""

    def test_get_credentials_cache_hit(self, client, mock_app_state):
        """Test returning cached credentials from credential store."""
        mock_app_state.credential_store.get_credentials.return_value = (
            "testuser",
            "cached-secret-key-123",
        )

        response = client.get("/credentials/")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["access_key"] == "testuser"
        assert data["secret_key"] == "cached-secret-key-123"

        # Should NOT call MinIO user manager
        mock_app_state.user_manager.resource_exists.assert_not_called()
        mock_app_state.user_manager.get_or_rotate_user_credentials.assert_not_called()

    def test_get_credentials_cache_miss_existing_user(self, client, mock_app_state):
        """Test cache miss for existing user — rotates and stores."""
        mock_app_state.credential_store.get_credentials.return_value = None
        mock_app_state.user_manager.resource_exists.return_value = True

        response = client.get("/credentials/")

        assert response.status_code == 200
        data = response.json()
        assert data["secret_key"] == "test-secret-key-123"

        # Should store in credential store
        mock_app_state.credential_store.store_credentials.assert_called_once_with(
            "testuser", "testuser", "test-secret-key-123"
        )

    def test_get_credentials_cache_miss_new_user(self, client, mock_app_state):
        """Test cache miss for new user — creates and stores."""
        mock_app_state.credential_store.get_credentials.return_value = None
        mock_app_state.user_manager.resource_exists.return_value = False

        response = client.get("/credentials/")

        assert response.status_code == 200
        data = response.json()
        assert data["secret_key"] == "new-secret-key-123"

        mock_app_state.user_manager.create_user.assert_called_once_with(
            username="testuser"
        )
        mock_app_state.credential_store.store_credentials.assert_called_once_with(
            "testuser", "testuser", "new-secret-key-123"
        )

    def test_get_credentials_idempotent(self, client, mock_app_state):
        """Test that multiple calls return same cached credentials."""
        mock_app_state.credential_store.get_credentials.return_value = (
            "testuser",
            "cached-secret-key-123",
        )

        response1 = client.get("/credentials/")
        response2 = client.get("/credentials/")

        assert response1.json() == response2.json()
        # MinIO rotation should never be called
        mock_app_state.user_manager.get_or_rotate_user_credentials.assert_not_called()


# === ROTATE CREDENTIALS ENDPOINT TESTS ===


class TestRotateCredentialsEndpoint:
    """Tests for POST /credentials/rotate endpoint."""

    def test_rotate_credentials_existing_user(self, client, mock_app_state):
        """Test rotating credentials for an existing user."""
        mock_app_state.user_manager.resource_exists.return_value = True

        response = client.post("/credentials/rotate")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["secret_key"] == "test-secret-key-123"

        # Should delete old, rotate, then store new
        mock_app_state.credential_store.delete_credentials.assert_called_once_with(
            "testuser"
        )
        mock_app_state.user_manager.get_or_rotate_user_credentials.assert_called_once_with(
            "testuser"
        )
        mock_app_state.credential_store.store_credentials.assert_called_once_with(
            "testuser", "testuser", "test-secret-key-123"
        )

    def test_rotate_credentials_new_user(self, client, mock_app_state):
        """Test rotating credentials creates user if not exists."""
        mock_app_state.user_manager.resource_exists.return_value = False

        response = client.post("/credentials/rotate")

        assert response.status_code == 200
        data = response.json()
        assert data["secret_key"] == "new-secret-key-123"

        mock_app_state.credential_store.delete_credentials.assert_called_once_with(
            "testuser"
        )
        mock_app_state.user_manager.create_user.assert_called_once_with(
            username="testuser"
        )


# === ASYNC FUNCTION TESTS ===


class TestGetCredentialsAsync:
    """Async tests for get_credentials function."""

    @pytest.mark.asyncio
    async def test_get_credentials_cache_hit_async(self, mock_app_state):
        """Test get_credentials returns cached credentials."""
        mock_request = MagicMock()
        mock_app_state.credential_store.get_credentials.return_value = (
            "alice",
            "cached-secret-123",
        )

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            response = await get_credentials(user, mock_request)

            assert response.username == "alice"
            assert response.secret_key == "cached-secret-123"
            mock_app_state.user_manager.resource_exists.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_credentials_cache_miss_async(self, mock_app_state):
        """Test get_credentials creates and stores on cache miss."""
        mock_request = MagicMock()
        mock_app_state.credential_store.get_credentials.return_value = None
        mock_app_state.user_manager.resource_exists.return_value = True

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            response = await get_credentials(user, mock_request)

            assert response.username == "alice"
            mock_app_state.credential_store.store_credentials.assert_called_once()

    @pytest.mark.asyncio
    async def test_rotate_credentials_async(self, mock_app_state):
        """Test rotate_credentials deletes, rotates, and stores."""
        mock_request = MagicMock()
        mock_app_state.user_manager.resource_exists.return_value = True

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            response = await rotate_credentials(user, mock_request)

            assert response.username == "alice"
            mock_app_state.credential_store.delete_credentials.assert_called_once_with(
                "alice"
            )
            mock_app_state.credential_store.store_credentials.assert_called_once()


# === ERROR HANDLING TESTS ===


class TestGetCredentialsErrors:
    """Tests for error handling in get_credentials."""

    @pytest.mark.asyncio
    async def test_get_credentials_user_creation_error(self, mock_app_state):
        """Test handling of user creation errors."""
        mock_request = MagicMock()

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            mock_app_state.credential_store.get_credentials.return_value = None
            mock_app_state.user_manager.resource_exists.return_value = False
            mock_app_state.user_manager.create_user.side_effect = Exception(
                "Creation failed"
            )

            user = KBaseUser(user="newuser", admin_perm=AdminPermission.FULL)

            with pytest.raises(Exception) as exc_info:
                await get_credentials(user, mock_request)

            assert "Creation failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_credentials_rotation_error(self, mock_app_state):
        """Test handling of credential rotation errors."""
        mock_request = MagicMock()

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            mock_app_state.credential_store.get_credentials.return_value = None
            mock_app_state.user_manager.resource_exists.return_value = True
            mock_app_state.user_manager.get_or_rotate_user_credentials.side_effect = (
                Exception("Rotation failed")
            )

            user = KBaseUser(user="existinguser", admin_perm=AdminPermission.FULL)

            with pytest.raises(Exception) as exc_info:
                await get_credentials(user, mock_request)

            assert "Rotation failed" in str(exc_info.value)


# === INTEGRATION TESTS ===


class TestCredentialsIntegration:
    """Integration-like tests for credentials workflow."""

    def test_credentials_workflow_cache_then_rotate(self, client, mock_app_state):
        """Test complete workflow: cache miss → cached → rotate."""
        # First request: cache miss, creates user
        mock_app_state.credential_store.get_credentials.return_value = None
        mock_app_state.user_manager.resource_exists.return_value = False

        response1 = client.get("/credentials/")
        assert response1.status_code == 200
        assert response1.json()["secret_key"] == "new-secret-key-123"

        # Second request: cache hit
        mock_app_state.credential_store.get_credentials.return_value = (
            "testuser",
            "new-secret-key-123",
        )

        response2 = client.get("/credentials/")
        assert response2.status_code == 200
        assert response2.json()["secret_key"] == "new-secret-key-123"

        # Rotate: forces new credentials
        mock_app_state.user_manager.resource_exists.return_value = True
        response3 = client.post("/credentials/rotate")
        assert response3.status_code == 200
        assert response3.json()["secret_key"] == "test-secret-key-123"

    def test_credentials_response_format(self, client, mock_app_state):
        """Test that response format matches expected schema."""
        mock_app_state.credential_store.get_credentials.return_value = (
            "testuser",
            "cached-secret-key-123",
        )

        response = client.get("/credentials/")
        data = response.json()

        assert "username" in data
        assert "access_key" in data
        assert "secret_key" in data
        assert len(data) == 3  # Only these three fields


# === DISTRIBUTED LOCK BEHAVIOR TESTS ===


class TestCredentialLocking:
    """Tests for distributed lock behavior in credential routes."""

    @pytest.mark.asyncio
    async def test_get_credentials_double_check_returns_cached(self, mock_app_state):
        """Test double-check pattern: cache populated between fast-path and lock."""
        mock_request = MagicMock()
        call_count = 0

        async def get_credentials_side_effect(username):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None  # Fast path: cache miss
            return ("alice", "populated-secret-123")  # Post-lock: cache hit

        mock_app_state.credential_store.get_credentials = AsyncMock(
            side_effect=get_credentials_side_effect
        )
        mock_app_state.lock_manager.credential_lock = _make_credential_lock()

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            response = await get_credentials(user, mock_request)

            assert response.secret_key == "populated-secret-123"
            # Should NOT have called MinIO since cache was populated post-lock
            mock_app_state.user_manager.resource_exists.assert_not_called()
            mock_app_state.credential_store.store_credentials.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_credentials_lock_contention_raises(self, mock_app_state):
        """Test that lock contention raises CredentialOperationError."""
        mock_request = MagicMock()
        mock_app_state.credential_store.get_credentials = AsyncMock(return_value=None)

        @asynccontextmanager
        async def failing_lock(username, timeout=None):
            raise CredentialOperationError(
                f"Credential operation for user '{username}' is already in progress."
            )
            yield  # pragma: no cover

        mock_app_state.lock_manager.credential_lock = failing_lock

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)

            with pytest.raises(CredentialOperationError, match="already in progress"):
                await get_credentials(user, mock_request)

    @pytest.mark.asyncio
    async def test_rotate_credentials_lock_contention_raises(self, mock_app_state):
        """Test that rotate lock contention raises CredentialOperationError."""
        mock_request = MagicMock()

        @asynccontextmanager
        async def failing_lock(username, timeout=None):
            raise CredentialOperationError(
                f"Credential operation for user '{username}' is already in progress."
            )
            yield  # pragma: no cover

        mock_app_state.lock_manager.credential_lock = failing_lock

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)

            with pytest.raises(CredentialOperationError, match="already in progress"):
                await rotate_credentials(user, mock_request)

    @pytest.mark.asyncio
    async def test_get_credentials_lock_acquired_for_cache_miss(self, mock_app_state):
        """Test that lock is acquired when cache misses."""
        mock_request = MagicMock()
        lock_acquired = []

        @asynccontextmanager
        async def tracking_lock(username, timeout=None):
            lock_acquired.append(username)
            yield MagicMock()

        mock_app_state.credential_store.get_credentials = AsyncMock(return_value=None)
        mock_app_state.user_manager.resource_exists = AsyncMock(return_value=True)
        mock_app_state.lock_manager.credential_lock = tracking_lock

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            await get_credentials(user, mock_request)

            assert lock_acquired == ["alice"]

    @pytest.mark.asyncio
    async def test_get_credentials_no_lock_on_cache_hit(self, mock_app_state):
        """Test that no lock is acquired when cache hits on fast path."""
        mock_request = MagicMock()
        lock_acquired = []

        @asynccontextmanager
        async def tracking_lock(username, timeout=None):
            lock_acquired.append(username)
            yield MagicMock()

        mock_app_state.credential_store.get_credentials = AsyncMock(
            return_value=("alice", "cached-secret-123")
        )
        mock_app_state.lock_manager.credential_lock = tracking_lock

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            await get_credentials(user, mock_request)

            assert lock_acquired == []

    @pytest.mark.asyncio
    async def test_rotate_credentials_always_acquires_lock(self, mock_app_state):
        """Test that rotate always acquires the lock."""
        mock_request = MagicMock()
        lock_acquired = []

        @asynccontextmanager
        async def tracking_lock(username, timeout=None):
            lock_acquired.append(username)
            yield MagicMock()

        mock_app_state.user_manager.resource_exists = AsyncMock(return_value=True)
        mock_app_state.lock_manager.credential_lock = tracking_lock

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            await rotate_credentials(user, mock_request)

            assert lock_acquired == ["alice"]
