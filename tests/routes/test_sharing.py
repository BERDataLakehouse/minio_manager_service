"""
Comprehensive tests for the routes.sharing module.

Tests cover:
- share_data endpoint
- unshare_data endpoint
- make_path_public endpoint
- make_path_private endpoint
- get_path_access_info endpoint
- Request validation
- Response model validation
- Partial success (207 Multi-Status)
- Error handling
"""

import os
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.minio.managers.sharing_manager import (
    PathAccessInfo,
    SharingResult,
    UnsharingResult,
)
from src.routes.sharing import (
    PathAccessResponse,
    PathRequest,
    PublicAccessResponse,
    ShareRequest,
    ShareResponse,
    UnshareRequest,
    UnshareResponse,
    get_path_access_info,
    make_path_private,
    make_path_public,
    router,
    share_data,
    unshare_data,
)
from src.service.dependencies import auth
from src.service.exception_handlers import universal_error_handler
from src.service.exceptions import DataGovernanceError, PolicyValidationError
from src.service.kb_auth import AdminPermission, KBaseUser

# === FIXTURES ===


@pytest.fixture(autouse=True)
def mock_mc_path():
    """Ensure MC_PATH is set for all tests."""
    with patch.dict(os.environ, {"MC_PATH": "/usr/local/bin/mc"}):
        yield


@pytest.fixture
def mock_sharing_manager():
    """Create a mock sharing manager."""
    manager = AsyncMock()

    # Default successful share result
    manager.share_path = AsyncMock(
        return_value=SharingResult(
            path="s3a://bucket/data/",
            shared_with_users=["alice"],
            shared_with_groups=["team1"],
        )
    )

    # Default successful unshare result
    manager.unshare_path = AsyncMock(
        return_value=UnsharingResult(
            path="s3a://bucket/data/",
            unshared_from_users=["alice"],
            unshared_from_groups=["team1"],
        )
    )

    # Default make_public result
    manager.make_public = AsyncMock(
        return_value=SharingResult(
            path="s3a://bucket/data/",
            shared_with_groups=["all-users"],
        )
    )

    # Default make_private result
    manager.make_private = AsyncMock(
        return_value=UnsharingResult(
            path="s3a://bucket/data/",
            unshared_from_users=["alice"],
            unshared_from_groups=["team1"],
        )
    )

    # Default get_path_access_info result
    manager.get_path_access_info = AsyncMock(
        return_value=PathAccessInfo(
            users=["alice", "bob"],
            groups=["team1"],
            public=False,
        )
    )

    return manager


@pytest.fixture
def mock_app_state(mock_sharing_manager):
    """Create a mock application state."""
    app_state = MagicMock()
    app_state.sharing_manager = mock_sharing_manager
    return app_state


@pytest.fixture
def mock_auth_user():
    """Create a mock authenticated user."""
    return KBaseUser(user="owner", admin_perm=AdminPermission.FULL)


@pytest.fixture
def test_app(mock_app_state, mock_auth_user):
    """Create a test FastAPI application with mocked dependencies."""

    app = FastAPI()
    app.include_router(router)

    # Add exception handler (same as main app)
    app.add_exception_handler(Exception, universal_error_handler)

    # Store app state
    app.state.minio_client = MagicMock()
    app.state.minio_config = MagicMock()
    app.state.policy_manager = MagicMock()
    app.state.user_manager = MagicMock()
    app.state.group_manager = MagicMock()
    app.state.sharing_manager = mock_app_state.sharing_manager

    # Override auth dependency
    app.dependency_overrides[auth] = lambda: mock_auth_user

    return app


@pytest.fixture
def client(test_app, mock_app_state):
    """Create a test client with get_app_state patched."""
    with patch("src.routes.sharing.get_app_state", return_value=mock_app_state):
        yield TestClient(test_app, raise_server_exceptions=False)


# === REQUEST MODEL TESTS ===


class TestPathRequest:
    """Tests for PathRequest model."""

    def test_path_request_valid(self):
        """Test creating a valid PathRequest."""
        request = PathRequest(path="s3a://bucket/data/path/")
        assert request.path == "s3a://bucket/data/path/"

    def test_path_request_invalid_path(self):
        """Test PathRequest with invalid path."""
        with pytest.raises(PolicyValidationError):
            PathRequest(path="invalid-path")

    def test_path_request_strips_whitespace(self):
        """Test that PathRequest strips whitespace."""
        request = PathRequest(path="  s3a://bucket/data/path/  ")
        assert request.path == "s3a://bucket/data/path/"


class TestShareRequest:
    """Tests for ShareRequest model."""

    def test_share_request_valid(self):
        """Test creating a valid ShareRequest."""
        request = ShareRequest(
            path="s3a://bucket/data/path/",
            with_users=["alice", "bob"],
            with_groups=["team1"],
        )
        assert request.path == "s3a://bucket/data/path/"
        assert request.with_users == ["alice", "bob"]
        assert request.with_groups == ["team1"]

    def test_share_request_empty_lists(self):
        """Test ShareRequest with empty lists."""
        request = ShareRequest(path="s3a://bucket/data/path/")
        assert request.with_users == []
        assert request.with_groups == []

    def test_share_request_invalid_path(self):
        """Test ShareRequest with invalid path."""
        with pytest.raises(PolicyValidationError):
            ShareRequest(path="bad-path", with_users=["alice"])

    def test_share_request_extra_fields_forbidden(self):
        """Test that extra fields are forbidden."""
        with pytest.raises(ValueError):
            ShareRequest(
                path="s3a://bucket/data/path/",
                extra_field="not allowed",
            )


class TestUnshareRequest:
    """Tests for UnshareRequest model."""

    def test_unshare_request_valid(self):
        """Test creating a valid UnshareRequest."""
        request = UnshareRequest(
            path="s3a://bucket/data/path/",
            from_users=["alice"],
            from_groups=["team1"],
        )
        assert request.path == "s3a://bucket/data/path/"
        assert request.from_users == ["alice"]

    def test_unshare_request_empty_lists(self):
        """Test UnshareRequest with empty lists."""
        request = UnshareRequest(path="s3a://bucket/data/path/")
        assert request.from_users == []
        assert request.from_groups == []


# === RESPONSE MODEL TESTS ===


class TestShareResponse:
    """Tests for ShareResponse model."""

    def test_share_response_valid(self):
        """Test creating a valid ShareResponse."""
        response = ShareResponse(
            path="s3a://bucket/data/",
            shared_with_users=["alice"],
            shared_with_groups=["team1"],
            success_count=2,
            errors=[],
            shared_by="owner",
            shared_at=datetime.now(),
        )
        assert response.path == "s3a://bucket/data/"
        assert response.success_count == 2

    def test_share_response_with_errors(self):
        """Test ShareResponse with errors."""
        response = ShareResponse(
            path="s3a://bucket/data/",
            shared_with_users=["alice"],
            shared_with_groups=[],
            success_count=1,
            errors=["Error sharing with bob"],
            shared_by="owner",
            shared_at=datetime.now(),
        )
        assert len(response.errors) == 1


class TestUnshareResponse:
    """Tests for UnshareResponse model."""

    def test_unshare_response_valid(self):
        """Test creating a valid UnshareResponse."""
        response = UnshareResponse(
            path="s3a://bucket/data/",
            unshared_from_users=["alice"],
            unshared_from_groups=["team1"],
            success_count=2,
            errors=[],
            unshared_by="owner",
            unshared_at=datetime.now(),
        )
        assert response.success_count == 2


class TestPublicAccessResponse:
    """Tests for PublicAccessResponse model."""

    def test_public_access_response_public(self):
        """Test PublicAccessResponse for public path."""
        response = PublicAccessResponse(
            path="s3a://bucket/data/",
            is_public=True,
        )
        assert response.is_public is True

    def test_public_access_response_private(self):
        """Test PublicAccessResponse for private path."""
        response = PublicAccessResponse(
            path="s3a://bucket/data/",
            is_public=False,
        )
        assert response.is_public is False


class TestPathAccessResponse:
    """Tests for PathAccessResponse model."""

    def test_path_access_response_valid(self):
        """Test creating a valid PathAccessResponse."""
        response = PathAccessResponse(
            path="s3a://bucket/data/",
            users=["alice", "bob"],
            groups=["team1"],
            public=False,
        )
        assert response.users == ["alice", "bob"]
        assert response.groups == ["team1"]
        assert response.public is False


# === SHARE DATA ENDPOINT TESTS ===


class TestShareDataEndpoint:
    """Tests for share_data endpoint."""

    def test_share_data_success(self, client, mock_sharing_manager):
        """Test sharing data successfully."""
        response = client.post(
            "/sharing/share",
            json={
                "path": "s3a://bucket/data/project/",
                "with_users": ["alice"],
                "with_groups": ["team1"],
            },
        )

        assert response.status_code == 200
        data = response.json()
        # The response path comes from the request (after validation)
        assert data["path"] == "s3a://bucket/data/project/"
        assert "alice" in data["shared_with_users"]

    def test_share_data_partial_success(self, client, mock_sharing_manager):
        """Test sharing with partial success returns 207."""
        mock_sharing_manager.share_path.return_value = SharingResult(
            path="s3a://bucket/data/",
            shared_with_users=["alice"],
            errors=["Error sharing with bob: Not found"],
        )

        response = client.post(
            "/sharing/share",
            json={
                "path": "s3a://bucket/data/project/",
                "with_users": ["alice", "bob"],
            },
        )

        assert response.status_code == 207
        data = response.json()
        assert len(data["errors"]) > 0

    def test_share_data_empty_targets(self, client, mock_sharing_manager):
        """Test sharing with empty targets."""
        mock_sharing_manager.share_path.return_value = SharingResult(
            path="s3a://bucket/data/",
        )

        response = client.post(
            "/sharing/share",
            json={
                "path": "s3a://bucket/data/project/",
            },
        )

        assert response.status_code == 200

    def test_share_data_invalid_path(self, client):
        """Test sharing with invalid path."""
        response = client.post(
            "/sharing/share",
            json={
                "path": "invalid-path",
                "with_users": ["alice"],
            },
        )

        # PolicyValidationError is converted to 400 by exception handler
        assert response.status_code == 400


# === UNSHARE DATA ENDPOINT TESTS ===


class TestUnshareDataEndpoint:
    """Tests for unshare_data endpoint."""

    def test_unshare_data_success(self, client, mock_sharing_manager):
        """Test unsharing data successfully."""
        response = client.post(
            "/sharing/unshare",
            json={
                "path": "s3a://bucket/data/project/",
                "from_users": ["alice"],
                "from_groups": ["team1"],
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "alice" in data["unshared_from_users"]

    def test_unshare_data_partial_success(self, client, mock_sharing_manager):
        """Test unsharing with partial success returns 207."""
        mock_sharing_manager.unshare_path.return_value = UnsharingResult(
            path="s3a://bucket/data/",
            unshared_from_users=["alice"],
            errors=["Error unsharing from bob"],
        )

        response = client.post(
            "/sharing/unshare",
            json={
                "path": "s3a://bucket/data/project/",
                "from_users": ["alice", "bob"],
            },
        )

        assert response.status_code == 207

    def test_unshare_data_invalid_path(self, client):
        """Test unsharing with invalid path."""
        response = client.post(
            "/sharing/unshare",
            json={
                "path": "bad-path",
                "from_users": ["alice"],
            },
        )

        # PolicyValidationError is converted to 400 by exception handler
        assert response.status_code == 400


# === MAKE PUBLIC ENDPOINT TESTS ===


class TestMakePublicEndpoint:
    """Tests for make_path_public endpoint."""

    def test_make_public_success(self, client, mock_sharing_manager):
        """Test making path public successfully."""
        response = client.post(
            "/sharing/make-public",
            json={"path": "s3a://bucket/data/dataset/"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["is_public"] is True

    def test_make_public_error(self, client, mock_sharing_manager):
        """Test make_public with errors."""
        mock_sharing_manager.make_public.return_value = SharingResult(
            path="s3a://bucket/data/",
            errors=["Authorization failed"],
        )

        response = client.post(
            "/sharing/make-public",
            json={"path": "s3a://bucket/data/dataset/"},
        )

        assert response.status_code == 403  # DataGovernanceError maps to 403


# === MAKE PRIVATE ENDPOINT TESTS ===


class TestMakePrivateEndpoint:
    """Tests for make_path_private endpoint."""

    def test_make_private_success(self, client, mock_sharing_manager):
        """Test making path private successfully."""
        response = client.post(
            "/sharing/make-private",
            json={"path": "s3a://bucket/data/dataset/"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["is_public"] is False

    def test_make_private_error(self, client, mock_sharing_manager):
        """Test make_private with errors."""
        mock_sharing_manager.make_private.return_value = UnsharingResult(
            path="s3a://bucket/data/",
            errors=["Failed to remove access"],
        )

        response = client.post(
            "/sharing/make-private",
            json={"path": "s3a://bucket/data/dataset/"},
        )

        assert response.status_code == 403  # DataGovernanceError maps to 403


# === GET PATH ACCESS INFO ENDPOINT TESTS ===


class TestGetPathAccessInfoEndpoint:
    """Tests for get_path_access_info endpoint."""

    def test_get_access_info_success(self, client, mock_sharing_manager):
        """Test getting path access info successfully."""
        response = client.post(
            "/sharing/get_path_access_info",
            json={"path": "s3a://bucket/data/project/"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert "groups" in data
        assert "public" in data

    def test_get_access_info_public_path(self, client, mock_sharing_manager):
        """Test getting access info for public path."""
        mock_sharing_manager.get_path_access_info.return_value = PathAccessInfo(
            users=["alice"],
            groups=["all-users"],
            public=True,
        )

        response = client.post(
            "/sharing/get_path_access_info",
            json={"path": "s3a://bucket/data/public/"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["public"] is True

    def test_get_access_info_no_access(self, client, mock_sharing_manager):
        """Test getting access info when no one has access."""
        mock_sharing_manager.get_path_access_info.return_value = PathAccessInfo(
            users=[],
            groups=[],
            public=False,
        )

        response = client.post(
            "/sharing/get_path_access_info",
            json={"path": "s3a://bucket/data/private/"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["users"] == []
        assert data["groups"] == []


# === ASYNC FUNCTION TESTS ===


class TestSharingFunctionsAsync:
    """Async tests for sharing functions."""

    @pytest.mark.asyncio
    async def test_share_data_async(self, mock_sharing_manager):
        """Test share_data function directly."""

        mock_request = MagicMock()
        mock_response = MagicMock()
        mock_app_state = MagicMock()
        mock_app_state.sharing_manager = mock_sharing_manager

        with patch("src.routes.sharing.get_app_state", return_value=mock_app_state):
            share_request = ShareRequest(
                path="s3a://bucket/data/",
                with_users=["alice"],
            )
            user = KBaseUser(user="owner", admin_perm=AdminPermission.FULL)

            result = await share_data(share_request, user, mock_request, mock_response)

            assert result.path == "s3a://bucket/data/"

    @pytest.mark.asyncio
    async def test_unshare_data_async(self, mock_sharing_manager):
        """Test unshare_data function directly."""

        mock_request = MagicMock()
        mock_response = MagicMock()
        mock_app_state = MagicMock()
        mock_app_state.sharing_manager = mock_sharing_manager

        with patch("src.routes.sharing.get_app_state", return_value=mock_app_state):
            unshare_request = UnshareRequest(
                path="s3a://bucket/data/",
                from_users=["alice"],
            )
            user = KBaseUser(user="owner", admin_perm=AdminPermission.FULL)

            result = await unshare_data(
                unshare_request, user, mock_request, mock_response
            )

            assert result.path == "s3a://bucket/data/"

    @pytest.mark.asyncio
    async def test_make_public_async(self, mock_sharing_manager):
        """Test make_path_public function directly."""

        mock_request = MagicMock()
        mock_app_state = MagicMock()
        mock_app_state.sharing_manager = mock_sharing_manager

        with patch("src.routes.sharing.get_app_state", return_value=mock_app_state):
            path_request = PathRequest(path="s3a://bucket/data/")
            user = KBaseUser(user="owner", admin_perm=AdminPermission.FULL)

            result = await make_path_public(path_request, user, mock_request)

            assert result.is_public is True

    @pytest.mark.asyncio
    async def test_make_private_async(self, mock_sharing_manager):
        """Test make_path_private function directly."""

        mock_request = MagicMock()
        mock_app_state = MagicMock()
        mock_app_state.sharing_manager = mock_sharing_manager

        with patch("src.routes.sharing.get_app_state", return_value=mock_app_state):
            path_request = PathRequest(path="s3a://bucket/data/")
            user = KBaseUser(user="owner", admin_perm=AdminPermission.FULL)

            result = await make_path_private(path_request, user, mock_request)

            assert result.is_public is False

    @pytest.mark.asyncio
    async def test_get_path_access_info_async(self, mock_sharing_manager):
        """Test get_path_access_info function directly."""

        mock_request = MagicMock()
        mock_app_state = MagicMock()
        mock_app_state.sharing_manager = mock_sharing_manager

        with patch("src.routes.sharing.get_app_state", return_value=mock_app_state):
            path_request = PathRequest(path="s3a://bucket/data/")
            user = KBaseUser(user="owner", admin_perm=AdminPermission.FULL)

            result = await get_path_access_info(path_request, user, mock_request)

            assert result.path == "s3a://bucket/data/"
            assert "alice" in result.users


# === ERROR HANDLING TESTS ===


class TestSharingErrorHandling:
    """Tests for error handling in sharing routes."""

    @pytest.mark.asyncio
    async def test_share_data_governance_error(self, mock_sharing_manager):
        """Test DataGovernanceError is raised for make_public errors."""

        mock_sharing_manager.make_public.return_value = SharingResult(
            path="s3a://bucket/data/",
            errors=["User not authorized"],
        )

        mock_request = MagicMock()
        mock_app_state = MagicMock()
        mock_app_state.sharing_manager = mock_sharing_manager

        with patch("src.routes.sharing.get_app_state", return_value=mock_app_state):
            path_request = PathRequest(path="s3a://bucket/data/")
            user = KBaseUser(user="unauthorized", admin_perm=AdminPermission.FULL)

            with pytest.raises(DataGovernanceError):
                await make_path_public(path_request, user, mock_request)


# === INTEGRATION TESTS ===


class TestSharingIntegration:
    """Integration-like tests for sharing workflows."""

    def test_share_then_unshare_workflow(self, client, mock_sharing_manager):
        """Test sharing then unsharing workflow."""
        # Share
        share_response = client.post(
            "/sharing/share",
            json={
                "path": "s3a://bucket/data/project/",
                "with_users": ["alice"],
            },
        )
        assert share_response.status_code == 200

        # Unshare
        unshare_response = client.post(
            "/sharing/unshare",
            json={
                "path": "s3a://bucket/data/project/",
                "from_users": ["alice"],
            },
        )
        assert unshare_response.status_code == 200

    def test_make_public_then_private_workflow(self, client, mock_sharing_manager):
        """Test making public then private workflow."""
        # Make public
        public_response = client.post(
            "/sharing/make-public",
            json={"path": "s3a://bucket/data/dataset/"},
        )
        assert public_response.status_code == 200
        assert public_response.json()["is_public"] is True

        # Make private
        private_response = client.post(
            "/sharing/make-private",
            json={"path": "s3a://bucket/data/dataset/"},
        )
        assert private_response.status_code == 200
        assert private_response.json()["is_public"] is False

    def test_share_response_includes_metadata(self, client, mock_sharing_manager):
        """Test that share response includes proper metadata."""
        response = client.post(
            "/sharing/share",
            json={
                "path": "s3a://bucket/data/project/",
                "with_users": ["alice"],
            },
        )

        data = response.json()
        assert "shared_by" in data
        assert data["shared_by"] == "owner"
        assert "shared_at" in data

    def test_unshare_response_includes_metadata(self, client, mock_sharing_manager):
        """Test that unshare response includes proper metadata."""
        response = client.post(
            "/sharing/unshare",
            json={
                "path": "s3a://bucket/data/project/",
                "from_users": ["alice"],
            },
        )

        data = response.json()
        assert "unshared_by" in data
        assert data["unshared_by"] == "owner"
        assert "unshared_at" in data
