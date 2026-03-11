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
from src.service.kb_auth import AdminPermission, KBaseUser


# === FIXTURES ===


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Ensure MC_PATH is set for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


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
