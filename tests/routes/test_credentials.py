"""
Tests for the routes.credentials module.

Routes orchestrate two backend services and the polaris-state ensure
helper. The unified `CredentialsResponse` carries MinIO + Polaris fields
so JupyterHub gets everything in one round-trip.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from credentials.polaris_store import PolarisCredentialRecord
from routes.credentials import (
    CredentialsResponse,
    get_credentials,
    rotate_credentials,
    router,
)
from service.app_state import AppState
from service.dependencies import auth
from service.kb_auth import AdminPermission, KBaseUser


# === FIXTURES ===


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Ensure MC_PATH is set for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


@pytest.fixture
def mock_app_state():
    """Create a mock AppState exposing only the two per-backend services.

    The credentials routes are a two-line orchestration:
      - app_state.s3_credential_service.get_or_create / rotate (MinIO)
      - app_state.polaris_credential_service.get_or_create / rotate (Polaris)

    Each service self-bootstraps its own identity on cache miss, so the
    route doesn't need access to the underlying managers.
    """
    app_state = MagicMock(spec=AppState)

    app_state.s3_credential_service = AsyncMock()
    app_state.s3_credential_service.get_or_create = AsyncMock(
        return_value=("testuser", "minio-cached")
    )
    app_state.s3_credential_service.rotate = AsyncMock(
        return_value=("testuser", "minio-rotated")
    )

    app_state.polaris_credential_service = AsyncMock()
    app_state.polaris_credential_service.get_or_create = AsyncMock(
        return_value=PolarisCredentialRecord(
            client_id="polaris-cid",
            client_secret="polaris-cached",
            personal_catalog="user_testuser",
        )
    )
    app_state.polaris_credential_service.rotate = AsyncMock(
        return_value=PolarisCredentialRecord(
            client_id="polaris-cid",
            client_secret="polaris-rotated",
            personal_catalog="user_testuser",
        )
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
    with patch("routes.credentials.get_app_state", return_value=mock_app_state):
        yield TestClient(test_app)


# === CREDENTIALS RESPONSE MODEL TESTS ===


_VALID_KW = dict(
    username="testuser",
    s3_access_key="testuser",
    s3_secret_key="test-secret-key-123456",
    polaris_client_id="polaris-cid",
    polaris_client_secret="polaris-secret-456",
)


class TestCredentialsResponse:
    """Tests for CredentialsResponse model."""

    def test_credentials_response_valid(self):
        response = CredentialsResponse(**_VALID_KW)
        assert response.username == "testuser"
        assert response.s3_access_key == "testuser"
        assert response.s3_secret_key == "test-secret-key-123456"
        assert response.polaris_client_id == "polaris-cid"
        assert response.polaris_client_secret == "polaris-secret-456"

    def test_credentials_response_strips_whitespace(self):
        kw = _VALID_KW | {"username": "  testuser  ", "s3_access_key": "  testuser  "}
        response = CredentialsResponse(**kw)
        assert response.username == "testuser"
        assert response.s3_access_key == "testuser"

    def test_credentials_response_frozen(self):
        response = CredentialsResponse(**_VALID_KW)
        with pytest.raises(Exception):
            response.username = "changed"

    def test_credentials_response_username_min_length(self):
        with pytest.raises(ValueError):
            CredentialsResponse(**(_VALID_KW | {"username": ""}))

    def test_credentials_response_secret_key_min_length(self):
        with pytest.raises(ValueError):
            CredentialsResponse(**(_VALID_KW | {"s3_secret_key": "short"}))


# === GET CREDENTIALS ENDPOINT TESTS ===


class TestGetCredentialsEndpoint:
    """Tests for GET /credentials/ endpoint."""

    def test_get_credentials_returns_full_bundle(self, client, mock_app_state):
        """Response carries S3 + Polaris credential material in one body.

        Catalog metadata is intentionally excluded — clients fetch it from
        ``GET /polaris/effective-access/me``.
        """
        response = client.get("/credentials/")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        # S3 half
        assert data["s3_access_key"] == "testuser"
        assert data["s3_secret_key"] == "minio-cached"
        # Polaris half
        assert data["polaris_client_id"] == "polaris-cid"
        assert data["polaris_client_secret"] == "polaris-cached"
        # Catalog metadata excluded.
        assert "personal_catalog" not in data
        assert "tenant_catalogs" not in data

    def test_get_credentials_invokes_both_backends(self, client, mock_app_state):
        """The route calls the S3 service AND the Polaris service in get_or_create mode.

        Each per-backend service self-bootstraps its own identity on cache
        miss — the route is just a two-line orchestration.
        """
        client.get("/credentials/")

        mock_app_state.s3_credential_service.get_or_create.assert_called_once_with(
            "testuser"
        )
        mock_app_state.polaris_credential_service.get_or_create.assert_called_once_with(
            "testuser"
        )

    def test_get_credentials_response_format(self, client, mock_app_state):
        """Response body has exactly the expected fields."""
        response = client.get("/credentials/")
        data = response.json()

        assert set(data.keys()) == {
            "username",
            "s3_access_key",
            "s3_secret_key",
            "polaris_client_id",
            "polaris_client_secret",
        }

    @pytest.mark.asyncio
    async def test_get_credentials_async(self, mock_app_state):
        """Direct async call to the route function."""
        mock_request = MagicMock()

        with patch("routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            response = await get_credentials(user, mock_request)

            assert response.username == "alice"
            mock_app_state.s3_credential_service.get_or_create.assert_called_once_with(
                "alice"
            )

    @pytest.mark.asyncio
    async def test_get_credentials_propagates_errors(self, mock_app_state):
        """Service errors propagate through the route."""
        mock_request = MagicMock()
        mock_app_state.s3_credential_service.get_or_create.side_effect = Exception(
            "Service failure"
        )

        with patch("routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="testuser", admin_perm=AdminPermission.FULL)
            with pytest.raises(Exception, match="Service failure"):
                await get_credentials(user, mock_request)


# === ROTATE CREDENTIALS ENDPOINT TESTS ===


class TestRotateCredentialsEndpoint:
    """Tests for POST /credentials/rotate endpoint."""

    def test_rotate_credentials_rotates_both_backends(self, client, mock_app_state):
        """Both MinIO and Polaris are rotated, and the response shows both."""
        response = client.post("/credentials/rotate")

        assert response.status_code == 200
        data = response.json()
        assert data["s3_secret_key"] == "minio-rotated"
        assert data["polaris_client_secret"] == "polaris-rotated"

        mock_app_state.s3_credential_service.rotate.assert_called_once_with("testuser")
        mock_app_state.polaris_credential_service.rotate.assert_called_once_with(
            "testuser"
        )

    @pytest.mark.asyncio
    async def test_rotate_credentials_async(self, mock_app_state):
        """Direct async call to rotate_credentials."""
        mock_request = MagicMock()

        with patch("routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="alice", admin_perm=AdminPermission.FULL)
            response = await rotate_credentials(user, mock_request)

            assert response.username == "alice"
            mock_app_state.s3_credential_service.rotate.assert_called_once_with("alice")

    @pytest.mark.asyncio
    async def test_rotate_credentials_propagates_errors(self, mock_app_state):
        """Service errors propagate through the route."""
        mock_request = MagicMock()
        mock_app_state.s3_credential_service.rotate.side_effect = Exception(
            "Rotation failed"
        )

        with patch("routes.credentials.get_app_state", return_value=mock_app_state):
            user = KBaseUser(user="testuser", admin_perm=AdminPermission.FULL)
            with pytest.raises(Exception, match="Rotation failed"):
                await rotate_credentials(user, mock_request)
