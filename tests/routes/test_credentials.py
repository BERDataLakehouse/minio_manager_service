"""
Tests for the routes.credentials module.

Routes are thin wrappers around CredentialService, so these tests
verify routing, response models, and correct delegation.
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
    """Create a mock application state with credential_service."""
    app_state = MagicMock(spec=AppState)

    # Mock credential service
    app_state.credential_service = AsyncMock()
    app_state.credential_service.get_or_create = AsyncMock(
        return_value=("testuser", "test-secret-key-123")
    )
    app_state.credential_service.rotate = AsyncMock(
        return_value=("testuser", "rotated-secret-key-456")
    )

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
        with pytest.raises(Exception):
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
                secret_key="short",
            )


# === GET CREDENTIALS ENDPOINT TESTS ===


class TestGetCredentialsEndpoint:
    """Tests for GET /credentials/ endpoint."""

    def test_get_credentials_delegates_to_service(self, client, mock_app_state):
        """Test that get_credentials delegates to credential_service."""
        response = client.get("/credentials/")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["access_key"] == "testuser"
        assert data["secret_key"] == "test-secret-key-123"

        mock_app_state.credential_service.get_or_create.assert_called_once_with(
            "testuser"
        )

    def test_get_credentials_idempotent(self, client, mock_app_state):
        """Test that multiple calls delegate to service consistently."""
        response1 = client.get("/credentials/")
        response2 = client.get("/credentials/")

        assert response1.json() == response2.json()
        assert mock_app_state.credential_service.get_or_create.call_count == 2

    def test_get_credentials_response_format(self, client, mock_app_state):
        """Test response has exactly the expected fields."""
        response = client.get("/credentials/")
        data = response.json()

        assert set(data.keys()) == {"username", "access_key", "secret_key"}

    @pytest.mark.asyncio
    async def test_get_credentials_async(self, mock_app_state):
        """Test get_credentials async function directly."""
        mock_request = MagicMock()

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            response = await get_credentials(user, mock_request)

            assert response.username == "alice"
            mock_app_state.credential_service.get_or_create.assert_called_once_with(
                "alice"
            )

    @pytest.mark.asyncio
    async def test_get_credentials_propagates_errors(self, mock_app_state):
        """Test that service errors propagate through the route."""
        mock_request = MagicMock()
        mock_app_state.credential_service.get_or_create.side_effect = Exception(
            "Service failure"
        )

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="testuser", admin_perm=AdminPermission.FULL)
            with pytest.raises(Exception, match="Service failure"):
                await get_credentials(user, mock_request)


# === ROTATE CREDENTIALS ENDPOINT TESTS ===


class TestRotateCredentialsEndpoint:
    """Tests for POST /credentials/rotate endpoint."""

    def test_rotate_credentials_delegates_to_service(self, client, mock_app_state):
        """Test that rotate delegates to credential_service."""
        response = client.post("/credentials/rotate")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["secret_key"] == "rotated-secret-key-456"

        mock_app_state.credential_service.rotate.assert_called_once_with("testuser")

    @pytest.mark.asyncio
    async def test_rotate_credentials_async(self, mock_app_state):
        """Test rotate_credentials async function directly."""
        mock_request = MagicMock()

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            response = await rotate_credentials(user, mock_request)

            assert response.username == "alice"
            mock_app_state.credential_service.rotate.assert_called_once_with("alice")

    @pytest.mark.asyncio
    async def test_rotate_credentials_propagates_errors(self, mock_app_state):
        """Test that service errors propagate through the route."""
        mock_request = MagicMock()
        mock_app_state.credential_service.rotate.side_effect = Exception(
            "Rotation failed"
        )

        with patch("src.routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="testuser", admin_perm=AdminPermission.FULL)
            with pytest.raises(Exception, match="Rotation failed"):
                await rotate_credentials(user, mock_request)
