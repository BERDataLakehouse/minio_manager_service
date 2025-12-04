"""
Comprehensive tests for the routes.credentials module.

Tests cover:
- get_credentials endpoint
- User auto-creation for new users
- Credential rotation for existing users
- Authentication dependency integration
- Response model validation
- Error handling scenarios
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.routes.credentials import CredentialsResponse, get_credentials, router
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

    # Store app state
    app.state.minio_client = MagicMock()
    app.state.minio_config = MagicMock()
    app.state.policy_manager = MagicMock()
    app.state.user_manager = mock_app_state.user_manager
    app.state.group_manager = MagicMock()
    app.state.sharing_manager = MagicMock()

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
    """Tests for get_credentials endpoint."""

    def test_get_credentials_existing_user(self, client, mock_app_state):
        """Test getting credentials for an existing user."""
        mock_app_state.user_manager.resource_exists.return_value = True

        response = client.get("/credentials/")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["access_key"] == "testuser"
        assert data["secret_key"] == "test-secret-key-123"

    def test_get_credentials_new_user_auto_create(self, client, mock_app_state):
        """Test auto-creating a new user when they don't exist."""
        mock_app_state.user_manager.resource_exists.return_value = False

        response = client.get("/credentials/")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["access_key"] == "testuser"
        assert data["secret_key"] == "new-secret-key-123"

        # Verify create_user was called
        mock_app_state.user_manager.create_user.assert_called_once_with(
            username="testuser"
        )

    def test_get_credentials_rotates_existing_user_credentials(
        self, client, mock_app_state
    ):
        """Test that credentials are rotated for existing users."""
        mock_app_state.user_manager.resource_exists.return_value = True

        client.get("/credentials/")

        mock_app_state.user_manager.get_or_rotate_user_credentials.assert_called_once_with(
            "testuser"
        )


# === ASYNC FUNCTION TESTS ===


class TestGetCredentialsAsync:
    """Async tests for get_credentials function."""

    @pytest.mark.asyncio
    async def test_get_credentials_existing_user_async(self, mock_app_state):
        """Test get_credentials for existing user."""

        mock_request = MagicMock()
        mock_request.app.state = mock_app_state

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            mock_app_state.user_manager.resource_exists.return_value = True

            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            response = await get_credentials(user, mock_request)

            assert response.username == "alice"
            mock_app_state.user_manager.get_or_rotate_user_credentials.assert_called_once_with(
                "alice"
            )

    @pytest.mark.asyncio
    async def test_get_credentials_new_user_async(self, mock_app_state):
        """Test get_credentials auto-creates new user."""

        mock_request = MagicMock()
        mock_request.app.state = mock_app_state

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            mock_app_state.user_manager.resource_exists.return_value = False

            user = KBaseUser(user="newuser", admin_perm=AdminPermission.FULL)
            response = await get_credentials(user, mock_request)

            assert response.username == "newuser"
            mock_app_state.user_manager.create_user.assert_called_once_with(
                username="newuser"
            )


# === ERROR HANDLING TESTS ===


class TestGetCredentialsErrors:
    """Tests for error handling in get_credentials."""

    @pytest.mark.asyncio
    async def test_get_credentials_user_creation_error(self, mock_app_state):
        """Test handling of user creation errors."""

        mock_request = MagicMock()

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
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

    def test_credentials_workflow_new_user(self, client, mock_app_state):
        """Test complete workflow for new user."""
        mock_app_state.user_manager.resource_exists.return_value = False

        # First request - user is created
        response1 = client.get("/credentials/")
        assert response1.status_code == 200

        # Simulate user now exists
        mock_app_state.user_manager.resource_exists.return_value = True

        # Second request - credentials are rotated
        response2 = client.get("/credentials/")
        assert response2.status_code == 200

        # Verify both create and rotate were called
        mock_app_state.user_manager.create_user.assert_called_once()
        mock_app_state.user_manager.get_or_rotate_user_credentials.assert_called_once()

    def test_credentials_response_format(self, client, mock_app_state):
        """Test that response format matches expected schema."""
        response = client.get("/credentials/")
        data = response.json()

        assert "username" in data
        assert "access_key" in data
        assert "secret_key" in data
        assert len(data) == 3  # Only these three fields
