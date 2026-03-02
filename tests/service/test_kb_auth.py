"""Tests for the kb_auth module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.service.kb_auth import (
    AdminPermission,
    KBaseAuth,
    KBaseUser,
    _check_error,
)
from src.service.exceptions import InvalidTokenError, MissingRoleError


# === ADMIN PERMISSION TESTS ===


class TestAdminPermission:
    """Tests for AdminPermission enum."""

    def test_none_value(self):
        assert AdminPermission.NONE == 1

    def test_full_value(self):
        assert AdminPermission.FULL == 10

    def test_ordering(self):
        assert AdminPermission.NONE < AdminPermission.FULL


# === KBASE USER TESTS ===


class TestKBaseUser:
    """Tests for KBaseUser NamedTuple."""

    def test_create_user(self):
        user = KBaseUser(user="testuser", admin_perm=AdminPermission.NONE)
        assert user.user == "testuser"
        assert user.admin_perm == AdminPermission.NONE

    def test_create_admin_user(self):
        user = KBaseUser(user="admin", admin_perm=AdminPermission.FULL)
        assert user.admin_perm == AdminPermission.FULL


# === CHECK ERROR TESTS ===


class TestCheckError:
    """Tests for _check_error helper."""

    @pytest.mark.asyncio
    async def test_check_error_200_does_nothing(self):
        """Test successful response doesn't raise."""
        resp = MagicMock()
        resp.status = 200
        await _check_error(resp)  # Should not raise

    @pytest.mark.asyncio
    async def test_check_error_invalid_token(self):
        """Test 401 with appcode 10020 raises InvalidTokenError."""
        resp = MagicMock()
        resp.status = 401
        resp.json = AsyncMock(
            return_value={"error": {"appcode": 10020, "message": "Token is invalid"}}
        )
        with pytest.raises(InvalidTokenError):
            await _check_error(resp)

    @pytest.mark.asyncio
    async def test_check_error_other_json_error(self):
        """Test non-10020 JSON error raises IOError."""
        resp = MagicMock()
        resp.status = 403
        resp.json = AsyncMock(
            return_value={"error": {"appcode": 30000, "message": "Forbidden"}}
        )
        with pytest.raises(IOError, match="Error from KBase auth server: Forbidden"):
            await _check_error(resp)

    @pytest.mark.asyncio
    async def test_check_error_non_json_response(self):
        """Test non-JSON error response raises IOError."""
        resp = MagicMock()
        resp.status = 500
        resp.json = AsyncMock(side_effect=Exception("Not JSON"))
        resp.text = "Internal Server Error"
        with pytest.raises(IOError, match="Non-JSON response"):
            await _check_error(resp)


# === KBASE AUTH TESTS ===


class TestKBaseAuth:
    """Tests for KBaseAuth class."""

    @pytest.mark.asyncio
    async def test_create_success(self):
        """Test KBaseAuth.create with valid auth service."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
            return_value={"servicename": "Authentication Service"},
        ):
            auth = await KBaseAuth.create(
                "http://auth:5000/",
                required_roles=["BERDL_USER"],
                full_admin_roles=["KBASE_ADMIN"],
            )
            assert auth._url == "http://auth:5000/"
            assert auth._me_url == "http://auth:5000/api/V2/me"

    @pytest.mark.asyncio
    async def test_create_adds_trailing_slash(self):
        """Test create appends trailing slash if missing."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
            return_value={"servicename": "Authentication Service"},
        ):
            auth = await KBaseAuth.create("http://auth:5000")
            assert auth._url == "http://auth:5000/"

    @pytest.mark.asyncio
    async def test_create_wrong_service_raises(self):
        """Test create raises IOError if not Authentication Service."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
            return_value={"servicename": "Some Other Service"},
        ):
            with pytest.raises(IOError, match="does not appear to be"):
                await KBaseAuth.create("http://wrong:5000/")

    @pytest.mark.asyncio
    async def test_get_user_success(self):
        """Test get_user returns KBaseUser with correct roles."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
        ) as mock_get:
            # First call: create
            mock_get.return_value = {"servicename": "Authentication Service"}
            auth = await KBaseAuth.create(
                "http://auth:5000/",
                required_roles=["BERDL_USER"],
                full_admin_roles=["KBASE_ADMIN"],
            )

            # Second call: get_user
            mock_get.return_value = {
                "user": "testuser",
                "customroles": ["BERDL_USER"],
            }

            user = await auth.get_user("valid-token")
            assert user.user == "testuser"
            assert user.admin_perm == AdminPermission.NONE

    @pytest.mark.asyncio
    async def test_get_user_admin(self):
        """Test get_user returns FULL admin for users with admin roles."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {"servicename": "Authentication Service"}
            auth = await KBaseAuth.create(
                "http://auth:5000/",
                required_roles=["BERDL_USER"],
                full_admin_roles=["KBASE_ADMIN"],
            )

            mock_get.return_value = {
                "user": "admin",
                "customroles": ["BERDL_USER", "KBASE_ADMIN"],
            }

            user = await auth.get_user("admin-token")
            assert user.admin_perm == AdminPermission.FULL

    @pytest.mark.asyncio
    async def test_get_user_missing_role(self):
        """Test get_user raises MissingRoleError when required role is absent."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {"servicename": "Authentication Service"}
            auth = await KBaseAuth.create(
                "http://auth:5000/",
                required_roles=["BERDL_USER"],
            )

            mock_get.return_value = {
                "user": "testuser",
                "customroles": [],  # Missing BERDL_USER
            }

            with pytest.raises(MissingRoleError, match="missing required"):
                await auth.get_user("token-no-role")

    @pytest.mark.asyncio
    async def test_get_user_caching(self):
        """Test get_user caches results for the same token."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {"servicename": "Authentication Service"}
            auth = await KBaseAuth.create(
                "http://auth:5000/",
                full_admin_roles=["KBASE_ADMIN"],
            )

            mock_get.return_value = {
                "user": "testuser",
                "customroles": [],
            }

            user1 = await auth.get_user("cached-token")
            user2 = await auth.get_user("cached-token")

            assert user1 == user2
            # _get called once for create + once for first get_user = 2 total
            assert mock_get.call_count == 2

    @pytest.mark.asyncio
    async def test_get_user_falsy_token_raises(self):
        """Test get_user raises ValueError for empty token."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
            return_value={"servicename": "Authentication Service"},
        ):
            auth = await KBaseAuth.create("http://auth:5000/")

            with pytest.raises(ValueError, match="token is required"):
                await auth.get_user("")

    @pytest.mark.asyncio
    async def test_get_user_no_required_roles(self):
        """Test get_user succeeds when no required roles are configured."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = {"servicename": "Authentication Service"}
            auth = await KBaseAuth.create("http://auth:5000/")

            mock_get.return_value = {
                "user": "anyuser",
                "customroles": [],
            }

            user = await auth.get_user("some-token")
            assert user.user == "anyuser"


# === GET ADMIN ROLE TESTS ===


class TestGetAdminRole:
    """Tests for _get_admin_role method."""

    @pytest.mark.asyncio
    async def test_admin_role_with_matching_role(self):
        """Test returns FULL when user has an admin role."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
            return_value={"servicename": "Authentication Service"},
        ):
            auth = await KBaseAuth.create(
                "http://auth:5000/", full_admin_roles=["KBASE_ADMIN"]
            )

        result = auth._get_admin_role({"KBASE_ADMIN", "OTHER_ROLE"})
        assert result == AdminPermission.FULL

    @pytest.mark.asyncio
    async def test_admin_role_without_matching_role(self):
        """Test returns NONE when user doesn't have admin roles."""
        with patch(
            "src.service.kb_auth._get",
            new_callable=AsyncMock,
            return_value={"servicename": "Authentication Service"},
        ):
            auth = await KBaseAuth.create(
                "http://auth:5000/", full_admin_roles=["KBASE_ADMIN"]
            )

        result = auth._get_admin_role({"OTHER_ROLE"})
        assert result == AdminPermission.NONE
