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
    """Create a mock AppState with the per-backend services + Polaris managers.

    The credentials routes call:
      - app_state.s3_credential_service.get_or_create / rotate (MinIO)
      - ensure_user_polaris_state (uses polaris_user_manager,
        polaris_group_manager, group_manager)
      - app_state.polaris_credential_service.get_or_create / rotate (Polaris)
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

    # ensure_user_polaris_state queries these.
    app_state.polaris_user_manager = AsyncMock()
    app_state.polaris_group_manager = AsyncMock()
    app_state.group_manager = AsyncMock()
    app_state.group_manager.get_user_groups = AsyncMock(return_value=["globalusers"])

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
    access_key="testuser",
    secret_key="test-secret-key-123456",
    polaris_client_id="polaris-cid",
    polaris_client_secret="polaris-secret-456",
    personal_catalog="user_testuser",
    tenant_catalogs=["tenant_globalusers"],
)


class TestCredentialsResponse:
    """Tests for CredentialsResponse model."""

    def test_credentials_response_valid(self):
        response = CredentialsResponse(**_VALID_KW)
        assert response.username == "testuser"
        assert response.access_key == "testuser"
        assert response.secret_key == "test-secret-key-123456"
        assert response.polaris_client_id == "polaris-cid"
        assert response.polaris_client_secret == "polaris-secret-456"
        assert response.personal_catalog == "user_testuser"
        assert response.tenant_catalogs == ["tenant_globalusers"]

    def test_credentials_response_strips_whitespace(self):
        kw = _VALID_KW | {"username": "  testuser  ", "access_key": "  testuser  "}
        response = CredentialsResponse(**kw)
        assert response.username == "testuser"
        assert response.access_key == "testuser"

    def test_credentials_response_frozen(self):
        response = CredentialsResponse(**_VALID_KW)
        with pytest.raises(Exception):
            response.username = "changed"

    def test_credentials_response_username_min_length(self):
        with pytest.raises(ValueError):
            CredentialsResponse(**(_VALID_KW | {"username": ""}))

    def test_credentials_response_secret_key_min_length(self):
        with pytest.raises(ValueError):
            CredentialsResponse(**(_VALID_KW | {"secret_key": "short"}))


# === GET CREDENTIALS ENDPOINT TESTS ===


class TestGetCredentialsEndpoint:
    """Tests for GET /credentials/ endpoint."""

    def test_get_credentials_returns_full_bundle(self, client, mock_app_state):
        """Response carries MinIO + Polaris credential material in one body."""
        response = client.get("/credentials/")

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        # MinIO half
        assert data["access_key"] == "testuser"
        assert data["secret_key"] == "minio-cached"
        # Polaris half
        assert data["polaris_client_id"] == "polaris-cid"
        assert data["polaris_client_secret"] == "polaris-cached"
        assert data["personal_catalog"] == "user_testuser"
        assert data["tenant_catalogs"] == ["tenant_globalusers"]

    def test_get_credentials_invokes_both_backends(self, client, mock_app_state):
        """The route calls the S3 service AND the Polaris service in get_or_create mode."""
        client.get("/credentials/")

        mock_app_state.s3_credential_service.get_or_create.assert_called_once_with(
            "testuser"
        )
        # Polaris credential lookup uses the catalog name returned by ensure_user_polaris_state.
        mock_app_state.polaris_credential_service.get_or_create.assert_called_once_with(
            username="testuser", personal_catalog="user_testuser"
        )
        # ensure_user_polaris_state invoked the personal-asset provisioner.
        mock_app_state.polaris_user_manager.create_user.assert_called_once_with(
            "testuser"
        )

    def test_get_credentials_response_format(self, client, mock_app_state):
        """Response body has exactly the expected fields."""
        response = client.get("/credentials/")
        data = response.json()

        assert set(data.keys()) == {
            "username",
            "access_key",
            "secret_key",
            "polaris_client_id",
            "polaris_client_secret",
            "personal_catalog",
            "tenant_catalogs",
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
        assert data["secret_key"] == "minio-rotated"
        assert data["polaris_client_secret"] == "polaris-rotated"

        mock_app_state.s3_credential_service.rotate.assert_called_once_with("testuser")
        mock_app_state.polaris_credential_service.rotate.assert_called_once_with(
            username="testuser", personal_catalog="user_testuser"
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
