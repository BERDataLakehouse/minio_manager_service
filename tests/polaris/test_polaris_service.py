"""Tests for the PolarisService module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp

from src.polaris.polaris_service import PolarisService


# === FIXTURES ===


@pytest.fixture
def polaris_service():
    """Create a PolarisService with test defaults."""
    return PolarisService(
        polaris_uri="http://polaris:8181",
        root_credential="root:s3cr3t",
        minio_endpoint="http://minio:9002",
    )


@pytest.fixture
def mock_session():
    """Create a mock aiohttp.ClientSession with configurable responses."""
    session = AsyncMock(spec=aiohttp.ClientSession)

    # Make session usable as async context manager
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    return session


def _make_response(status=200, json_data=None, content_type="application/json"):
    """Helper to create a mock aiohttp response."""
    resp = AsyncMock()
    resp.status = status
    resp.headers = {"Content-Type": content_type}
    resp.json = AsyncMock(return_value=json_data or {})
    resp.raise_for_status = MagicMock()
    # Make it usable as async context manager
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=None)
    return resp


# === INIT TESTS ===


class TestPolarisServiceInit:
    """Tests for PolarisService initialization."""

    def test_init_with_plain_uri(self):
        """Test init with a plain base URI."""
        svc = PolarisService("http://polaris:8181", "root:secret")
        assert svc.base_url == "http://polaris:8181/api/management/v1"
        assert svc.oauth_url == "http://polaris:8181/api/catalog/v1/oauth/tokens"
        assert svc.client_id == "root"
        assert svc.client_secret == "secret"
        assert svc.minio_endpoint is None

    def test_init_with_catalog_uri(self):
        """Test init with /api/catalog in the URI — should be rewritten."""
        svc = PolarisService("http://polaris:8181/api/catalog", "root:secret")
        assert svc.base_url == "http://polaris:8181/api/management/v1"
        assert svc.oauth_url == "http://polaris:8181/api/catalog/v1/oauth/tokens"

    def test_init_with_trailing_slash(self):
        """Test init strips trailing slashes."""
        svc = PolarisService("http://polaris:8181/", "root:secret")
        assert svc.base_url == "http://polaris:8181/api/management/v1"

    def test_init_with_minio_endpoint(self):
        """Test init stores MinIO endpoint."""
        svc = PolarisService("http://polaris:8181", "root:secret", "http://minio:9002")
        assert svc.minio_endpoint == "http://minio:9002"

    def test_init_credential_without_colon(self):
        """Test init with credential that has no colon."""
        svc = PolarisService("http://polaris:8181", "rootonly")
        assert svc.client_id == "rootonly"
        assert svc.client_secret == ""

    def test_init_credential_with_colon_in_secret(self):
        """Test init with credential containing colon in secret."""
        svc = PolarisService("http://polaris:8181", "root:sec:ret")
        assert svc.client_id == "root"
        assert svc.client_secret == "sec:ret"


# === SESSION LIFECYCLE TESTS ===


class TestSessionLifecycle:
    """Tests for shared aiohttp session management."""

    @pytest.mark.asyncio
    async def test_get_session_creates_new_session(self, polaris_service):
        """Test _get_session creates a new session when none exists."""
        assert polaris_service._session is None
        session = await polaris_service._get_session()
        assert session is not None
        assert not session.closed
        # Cleanup
        await polaris_service.close()

    @pytest.mark.asyncio
    async def test_get_session_reuses_existing_session(self, polaris_service):
        """Test _get_session returns the same session on subsequent calls."""
        session1 = await polaris_service._get_session()
        session2 = await polaris_service._get_session()
        assert session1 is session2
        await polaris_service.close()

    @pytest.mark.asyncio
    async def test_get_session_recreates_after_close(self, polaris_service):
        """Test _get_session creates a new session after close()."""
        session1 = await polaris_service._get_session()
        await polaris_service.close()
        session2 = await polaris_service._get_session()
        assert session1 is not session2
        await polaris_service.close()

    @pytest.mark.asyncio
    async def test_close_without_session(self, polaris_service):
        """Test close() is safe when no session exists."""
        assert polaris_service._session is None
        await polaris_service.close()  # Should not raise

    @pytest.mark.asyncio
    async def test_close_sets_session_to_none(self, polaris_service):
        """Test close() cleans up the session reference."""
        await polaris_service._get_session()
        await polaris_service.close()
        assert polaris_service._session is None


# === TOKEN TESTS ===


class TestGetToken:
    """Tests for OAuth token retrieval."""

    @pytest.mark.asyncio
    async def test_get_token_fetches_new_token(self, polaris_service, mock_session):
        """Test token is fetched from Polaris OAuth endpoint."""
        token_resp = _make_response(json_data={"access_token": "test-token-123"})
        mock_session.post = MagicMock(return_value=token_resp)

        token = await polaris_service._get_token(mock_session)

        assert token == "test-token-123"
        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args
        assert call_args[0][0] == polaris_service.oauth_url

    @pytest.mark.asyncio
    async def test_get_token_returns_cached_token(self, polaris_service, mock_session):
        """Test cached token is returned without making a new request."""
        polaris_service._token = "cached-token"

        token = await polaris_service._get_token(mock_session)

        assert token == "cached-token"
        mock_session.post.assert_not_called()


# === REQUEST TESTS ===


class TestRequest:
    """Tests for the authenticated _request method."""

    @pytest.mark.asyncio
    async def test_request_get_json(self, polaris_service):
        """Test GET request returns JSON response."""
        resp = _make_response(json_data={"name": "test_catalog"})

        session = AsyncMock()
        token_resp = _make_response(json_data={"access_token": "token"})
        session.post = MagicMock(return_value=token_resp)
        session.request = MagicMock(return_value=resp)
        session.closed = False

        polaris_service._session = session

        result = await polaris_service._request("GET", "/catalogs/test")
        assert result == {"name": "test_catalog"}

    @pytest.mark.asyncio
    async def test_request_204_returns_empty(self, polaris_service):
        """Test 204 No Content returns empty dict."""
        resp = _make_response(status=204)

        session = AsyncMock()
        token_resp = _make_response(json_data={"access_token": "token"})
        session.post = MagicMock(return_value=token_resp)
        session.request = MagicMock(return_value=resp)
        session.closed = False

        polaris_service._session = session

        result = await polaris_service._request("PUT", "/some/endpoint")
        assert result == {}

    @pytest.mark.asyncio
    async def test_request_201_no_json_returns_empty(self, polaris_service):
        """Test 201 with non-JSON content type returns empty dict."""
        resp = _make_response(status=201, content_type="text/plain")

        session = AsyncMock()
        token_resp = _make_response(json_data={"access_token": "token"})
        session.post = MagicMock(return_value=token_resp)
        session.request = MagicMock(return_value=resp)
        session.closed = False

        polaris_service._session = session

        result = await polaris_service._request("POST", "/principals")
        assert result == {}

    @pytest.mark.asyncio
    async def test_request_401_clears_token_cache(self, polaris_service):
        """Test 401 response clears the cached token."""
        polaris_service._token = "stale-token"

        error = aiohttp.ClientResponseError(
            request_info=MagicMock(),
            history=(),
            status=401,
            message="Unauthorized",
        )
        resp = AsyncMock()
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        resp.status = 401
        resp.raise_for_status = MagicMock(side_effect=error)
        resp.headers = {"Content-Type": "application/json"}

        session = AsyncMock()
        session.request = MagicMock(return_value=resp)
        session.closed = False

        polaris_service._session = session

        with pytest.raises(aiohttp.ClientResponseError):
            await polaris_service._request("GET", "/catalogs")

        assert polaris_service._token is None


# === CATALOG TESTS ===


class TestCreateCatalog:
    """Tests for catalog creation."""

    @pytest.mark.asyncio
    async def test_create_catalog_with_endpoint(self, polaris_service):
        """Test catalog creation includes storageConfigInfo when endpoint provided."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {"catalog": {"name": "user_tgu2"}}

            result = await polaris_service.create_catalog(
                name="user_tgu2",
                storage_location="s3://cdm-lake/users-sql-warehouse/tgu2/iceberg/",
            )

            mock_req.assert_called_once()
            call_payload = mock_req.call_args[1]["json"]
            catalog = call_payload["catalog"]
            assert catalog["name"] == "user_tgu2"
            assert catalog["type"] == "INTERNAL"
            assert (
                catalog["properties"]["default-base-location"]
                == "s3://cdm-lake/users-sql-warehouse/tgu2/iceberg/"
            )
            storage = catalog["storageConfigInfo"]
            assert storage["storageType"] == "S3"
            assert storage["allowedLocations"] == [
                "s3://cdm-lake/users-sql-warehouse/tgu2/iceberg/"
            ]
            assert storage["endpoint"] == "http://minio:9002"
            assert storage["endpointInternal"] == "http://minio:9002"
            assert storage["pathStyleAccess"] is True
            assert storage["stsUnavailable"] is True
            assert storage["region"] == "us-east-1"
            assert result == {"catalog": {"name": "user_tgu2"}}

    @pytest.mark.asyncio
    async def test_create_catalog_with_explicit_endpoint(self, polaris_service):
        """Test explicit s3_endpoint overrides minio_endpoint."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {}

            await polaris_service.create_catalog(
                name="test",
                storage_location="s3://bucket/path/",
                s3_endpoint="http://custom:9000",
            )

            call_payload = mock_req.call_args[1]["json"]
            storage_config = call_payload["catalog"]["storageConfigInfo"]
            assert storage_config["endpoint"] == "http://custom:9000"
            assert storage_config["endpointInternal"] == "http://custom:9000"

    @pytest.mark.asyncio
    async def test_create_catalog_without_endpoint(self):
        """Test catalog creation without any endpoint omits endpoint fields."""
        svc = PolarisService("http://polaris:8181", "root:secret")

        with patch.object(svc, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await svc.create_catalog(name="test", storage_location="s3://bucket/path/")

            call_payload = mock_req.call_args[1]["json"]
            storage_config = call_payload["catalog"]["storageConfigInfo"]
            assert "endpoint" not in storage_config
            assert storage_config["storageType"] == "S3"
            assert storage_config["allowedLocations"] == ["s3://bucket/path/"]

    @pytest.mark.asyncio
    async def test_create_catalog_conflict_returns_existing(self, polaris_service):
        """Test 409 conflict falls back to get_catalog."""
        conflict_error = aiohttp.ClientResponseError(
            request_info=MagicMock(), history=(), status=409, message="Conflict"
        )

        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = [conflict_error, {"name": "existing_catalog"}]

            # First call raises 409, second call (get_catalog) returns existing
            result = await polaris_service.create_catalog(
                "existing_catalog", "s3://bucket/path/"
            )

            assert result == {"name": "existing_catalog"}
            assert mock_req.call_count == 2

    @pytest.mark.asyncio
    async def test_create_catalog_non_conflict_error_raises(self, polaris_service):
        """Test non-409 errors are re-raised."""
        server_error = aiohttp.ClientResponseError(
            request_info=MagicMock(), history=(), status=500, message="Server Error"
        )

        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = server_error

            with pytest.raises(aiohttp.ClientResponseError) as exc_info:
                await polaris_service.create_catalog("test", "s3://bucket/path/")
            assert exc_info.value.status == 500


# === PRINCIPAL TESTS ===


class TestCreatePrincipal:
    """Tests for principal management."""

    @pytest.mark.asyncio
    async def test_create_principal_success(self, polaris_service):
        """Test creating a new principal."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {"principal": {"name": "testuser"}}

            result = await polaris_service.create_principal("testuser")

            mock_req.assert_called_once_with(
                "POST",
                "/principals",
                json={
                    "principal": {"name": "testuser", "type": "USER", "properties": {}}
                },
            )
            assert result == {"principal": {"name": "testuser"}}

    @pytest.mark.asyncio
    async def test_create_principal_conflict_returns_existing(self, polaris_service):
        """Test 409 conflict falls back to get_principal."""
        conflict = aiohttp.ClientResponseError(
            request_info=MagicMock(), history=(), status=409, message="Conflict"
        )

        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = [conflict, {"principal": {"name": "existing"}}]

            result = await polaris_service.create_principal("existing")
            assert result == {"principal": {"name": "existing"}}

    @pytest.mark.asyncio
    async def test_get_principal(self, polaris_service):
        """Test getting a specific principal."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {"principal": {"name": "testuser"}}

            result = await polaris_service.get_principal("testuser")

            mock_req.assert_called_once_with("GET", "/principals/testuser")
            assert result["principal"]["name"] == "testuser"


# === CREDENTIAL TESTS ===


class TestCredentials:
    """Tests for credential rotation/reset."""

    @pytest.mark.asyncio
    async def test_reset_principal_credentials(self, polaris_service):
        """Test resetting credentials via POST /principals/{name}/reset."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {
                "credentials": {"clientId": "cid", "clientSecret": "csec"}
            }

            result = await polaris_service.reset_principal_credentials("testuser")

            mock_req.assert_called_once_with(
                "POST", "/principals/testuser/reset", json={}
            )
            assert result["credentials"]["clientId"] == "cid"
            assert result["credentials"]["clientSecret"] == "csec"

    @pytest.mark.asyncio
    async def test_rotate_is_alias_for_reset(self, polaris_service):
        """Test rotate_principal_credentials is an alias for reset."""
        assert (
            polaris_service.rotate_principal_credentials
            == polaris_service.reset_principal_credentials
        )


# === CATALOG ROLE TESTS ===


class TestCatalogRoles:
    """Tests for catalog role operations."""

    @pytest.mark.asyncio
    async def test_create_catalog_role(self, polaris_service):
        """Test creating a catalog role."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {}

            await polaris_service.create_catalog_role("user_tgu2", "catalog_admin")

            mock_req.assert_called_once_with(
                "POST",
                "/catalogs/user_tgu2/catalog-roles",
                json={"catalogRole": {"name": "catalog_admin", "properties": {}}},
            )

    @pytest.mark.asyncio
    async def test_create_catalog_role_conflict(self, polaris_service):
        """Test 409 conflict falls back to GET existing role."""
        conflict = aiohttp.ClientResponseError(
            request_info=MagicMock(), history=(), status=409, message="Conflict"
        )

        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = [
                conflict,
                {"catalogRole": {"name": "catalog_admin"}},
            ]

            result = await polaris_service.create_catalog_role(
                "user_tgu2", "catalog_admin"
            )
            assert result == {"catalogRole": {"name": "catalog_admin"}}

    @pytest.mark.asyncio
    async def test_grant_catalog_privilege(self, polaris_service):
        """Test granting a privilege on a catalog to a role."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {}

            await polaris_service.grant_catalog_privilege(
                "user_tgu2", "catalog_admin", "CATALOG_MANAGE_CONTENT"
            )

            mock_req.assert_called_once_with(
                "PUT",
                "/catalogs/user_tgu2/catalog-roles/catalog_admin/grants",
                json={
                    "grant": {"type": "catalog", "privilege": "CATALOG_MANAGE_CONTENT"}
                },
            )

    @pytest.mark.asyncio
    async def test_grant_catalog_privilege_conflict_returns_empty(
        self, polaris_service
    ):
        """Test 409 conflict returns empty dict (already granted)."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(), history=(), status=409, message="Conflict"
            )

            result = await polaris_service.grant_catalog_privilege(
                "cat", "role", "SOME_PRIV"
            )
            assert result == {}

    @pytest.mark.asyncio
    async def test_grant_catalog_privilege_non_conflict_raises(self, polaris_service):
        """Test non-conflict 500 errors are re-raised."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=500,
                message="Unexpected server failure",
            )

            with pytest.raises(aiohttp.ClientResponseError) as exc_info:
                await polaris_service.grant_catalog_privilege(
                    "cat", "role", "SOME_PRIV"
                )
            assert exc_info.value.status == 500

    @pytest.mark.asyncio
    async def test_grant_catalog_privilege_duplicate_key_returns_empty(
        self, polaris_service
    ):
        """Test 500 with 'already exists' (Polaris duplicate key bug) returns empty dict."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=500,
                message="duplicate key value violates unique constraint already exists",
            )

            result = await polaris_service.grant_catalog_privilege(
                "cat", "role", "SOME_PRIV"
            )
            assert result == {}


# === PRINCIPAL ROLE TESTS ===


class TestPrincipalRoles:
    """Tests for principal role operations."""

    @pytest.mark.asyncio
    async def test_create_principal_role(self, polaris_service):
        """Test creating a principal role."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {}

            await polaris_service.create_principal_role("tgu2_role")

            mock_req.assert_called_once_with(
                "POST",
                "/principal-roles",
                json={"principalRole": {"name": "tgu2_role", "properties": {}}},
            )

    @pytest.mark.asyncio
    async def test_create_principal_role_conflict(self, polaris_service):
        """Test 409 conflict falls back to GET existing role."""
        conflict = aiohttp.ClientResponseError(
            request_info=MagicMock(), history=(), status=409, message="Conflict"
        )

        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = [
                conflict,
                {"principalRole": {"name": "tgu2_role"}},
            ]

            result = await polaris_service.create_principal_role("tgu2_role")
            assert result == {"principalRole": {"name": "tgu2_role"}}

    @pytest.mark.asyncio
    async def test_grant_catalog_role_to_principal_role(self, polaris_service):
        """Test assigning a catalog role to a principal role."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            # First call (GET) returns no existing roles, second call (PUT) succeeds
            mock_req.side_effect = [{"roles": []}, {}]

            await polaris_service.grant_catalog_role_to_principal_role(
                catalog="user_tgu2",
                catalog_role="catalog_admin",
                principal_role="tgu2_role",
            )

            assert mock_req.call_count == 2
            mock_req.assert_any_call(
                "GET",
                "/principal-roles/tgu2_role/catalog-roles/user_tgu2",
            )
            mock_req.assert_any_call(
                "PUT",
                "/principal-roles/tgu2_role/catalog-roles/user_tgu2",
                json={"catalogRole": {"name": "catalog_admin"}},
            )

    @pytest.mark.asyncio
    async def test_grant_catalog_role_to_principal_role_already_granted(
        self, polaris_service
    ):
        """Test that granting an already-assigned catalog role is a no-op."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {"roles": [{"name": "catalog_admin"}]}

            await polaris_service.grant_catalog_role_to_principal_role(
                catalog="user_tgu2",
                catalog_role="catalog_admin",
                principal_role="tgu2_role",
            )

            # Only the GET check, no PUT
            mock_req.assert_called_once_with(
                "GET",
                "/principal-roles/tgu2_role/catalog-roles/user_tgu2",
            )

    @pytest.mark.asyncio
    async def test_grant_principal_role_to_principal(self, polaris_service):
        """Test assigning a principal role to a user."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            # First call (GET) returns no existing roles, second call (PUT) succeeds
            mock_req.side_effect = [{"roles": []}, {}]

            await polaris_service.grant_principal_role_to_principal(
                principal="tgu2", principal_role="tgu2_role"
            )

            assert mock_req.call_count == 2
            mock_req.assert_any_call(
                "GET",
                "/principals/tgu2/principal-roles",
            )
            mock_req.assert_any_call(
                "PUT",
                "/principals/tgu2/principal-roles",
                json={"principalRole": {"name": "tgu2_role"}},
            )

    @pytest.mark.asyncio
    async def test_grant_principal_role_to_principal_already_granted(
        self, polaris_service
    ):
        """Test that granting an already-assigned principal role is a no-op."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {"roles": [{"name": "tgu2_role"}]}

            await polaris_service.grant_principal_role_to_principal(
                principal="tgu2", principal_role="tgu2_role"
            )

            # Only the GET check, no PUT
            mock_req.assert_called_once_with(
                "GET",
                "/principals/tgu2/principal-roles",
            )

    @pytest.mark.asyncio
    async def test_revoke_principal_role_from_principal(self, polaris_service):
        """Test revoking a principal role from a user."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            # First call (GET) returns the role as assigned, second call (DELETE) succeeds
            mock_req.side_effect = [{"roles": [{"name": "tgu2_role"}]}, {}]

            await polaris_service.revoke_principal_role_from_principal(
                principal="tgu2", principal_role="tgu2_role"
            )

            assert mock_req.call_count == 2
            mock_req.assert_any_call("GET", "/principals/tgu2/principal-roles")
            mock_req.assert_any_call(
                "DELETE", "/principals/tgu2/principal-roles/tgu2_role"
            )

    @pytest.mark.asyncio
    async def test_revoke_principal_role_not_assigned(self, polaris_service):
        """Test revoking a role that isn't assigned is a no-op."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {"roles": []}

            await polaris_service.revoke_principal_role_from_principal(
                principal="tgu2", principal_role="tgu2_role"
            )

            # Only the GET check, no DELETE
            mock_req.assert_called_once_with("GET", "/principals/tgu2/principal-roles")

    @pytest.mark.asyncio
    async def test_revoke_principal_role_principal_not_found(self, polaris_service):
        """Test revoking from a non-existent principal is a no-op."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = aiohttp.ClientResponseError(
                MagicMock(), (), status=404, message="Not Found"
            )

            await polaris_service.revoke_principal_role_from_principal(
                principal="nonexistent", principal_role="tgu2_role"
            )

            # Only the GET check, no DELETE
            mock_req.assert_called_once_with(
                "GET", "/principals/nonexistent/principal-roles"
            )


# === LIST/GET TESTS ===


class TestListAndGet:
    """Tests for list/get operations."""

    @pytest.mark.asyncio
    async def test_get_catalog(self, polaris_service):
        """Test getting a specific catalog."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {"name": "user_tgu2"}

            result = await polaris_service.get_catalog("user_tgu2")

            mock_req.assert_called_once_with("GET", "/catalogs/user_tgu2")
            assert result["name"] == "user_tgu2"

    @pytest.mark.asyncio
    async def test_list_catalogs(self, polaris_service):
        """Test listing all catalogs."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {
                "catalogs": [{"name": "user_tgu2"}, {"name": "tenant_globalusers"}]
            }

            result = await polaris_service.list_catalogs()

            assert len(result) == 2
            assert result[0]["name"] == "user_tgu2"

    @pytest.mark.asyncio
    async def test_list_catalogs_empty(self, polaris_service):
        """Test listing catalogs when none exist."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.return_value = {}

            result = await polaris_service.list_catalogs()
            assert result == []


# === DELETION TESTS ===


class TestDeletions:
    """Tests for resource deletion operations."""

    @pytest.mark.asyncio
    async def test_delete_principal_success(self, polaris_service):
        """Test deleting a principal succeeds via DELETE request."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            await polaris_service.delete_principal("testuser")
            mock_req.assert_called_once_with("DELETE", "/principals/testuser")

    @pytest.mark.asyncio
    async def test_delete_principal_not_found(self, polaris_service):
        """Test deleting a principal ignores 404 cleanly."""
        not_found = aiohttp.ClientResponseError(
            request_info=MagicMock(), history=(), status=404, message="Not Found"
        )
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            mock_req.side_effect = not_found
            # Should not raise
            await polaris_service.delete_principal("ghost_user")

    @pytest.mark.asyncio
    async def test_delete_catalog_success(self, polaris_service):
        """Test deleting a catalog succeeds via DELETE request."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            await polaris_service.delete_catalog("tenant_foo")
            mock_req.assert_called_once_with("DELETE", "/catalogs/tenant_foo")

    @pytest.mark.asyncio
    async def test_delete_principal_role_success(self, polaris_service):
        """Test deleting a principal role succeeds via DELETE request."""
        with patch.object(
            polaris_service, "_request", new_callable=AsyncMock
        ) as mock_req:
            await polaris_service.delete_principal_role("foo_member")
            mock_req.assert_called_once_with("DELETE", "/principal-roles/foo_member")

    @pytest.mark.asyncio
    async def test_drop_tenant_catalog(self, polaris_service):
        """Test drop_tenant_catalog drops the catalog and both bound member roles sequentially."""
        with (
            patch.object(
                polaris_service, "delete_catalog", new_callable=AsyncMock
            ) as mock_del_cat,
            patch.object(
                polaris_service, "delete_principal_role", new_callable=AsyncMock
            ) as mock_del_role,
        ):
            await polaris_service.drop_tenant_catalog("globalusers")

            mock_del_cat.assert_called_once_with("tenant_globalusers")
            assert mock_del_role.call_count == 2
            mock_del_role.assert_any_call("globalusers_member")
            mock_del_role.assert_any_call("globalusersro_member")


# === ENSURE TENANT CATALOG TESTS ===


class TestEnsureTenantCatalog:
    """Tests for the ensure_tenant_catalog orchestration method."""

    @pytest.mark.asyncio
    async def test_ensure_tenant_catalog_creates_all_resources(self, polaris_service):
        """Test that ensure_tenant_catalog creates catalog, roles, grants, and principal roles."""
        with (
            patch.object(
                polaris_service, "create_catalog", new_callable=AsyncMock
            ) as mock_create_cat,
            patch.object(
                polaris_service, "create_catalog_role", new_callable=AsyncMock
            ) as mock_create_cat_role,
            patch.object(
                polaris_service, "grant_catalog_privilege", new_callable=AsyncMock
            ) as mock_grant_priv,
            patch.object(
                polaris_service, "create_principal_role", new_callable=AsyncMock
            ) as mock_create_pr_role,
            patch.object(
                polaris_service,
                "grant_catalog_role_to_principal_role",
                new_callable=AsyncMock,
            ) as mock_grant_cr_to_pr,
        ):
            await polaris_service.ensure_tenant_catalog(
                "globalusers",
                "s3a://cdm-lake/tenants-sql-warehouse/globalusers/iceberg/",
            )

            # Catalog created
            mock_create_cat.assert_called_once_with(
                "tenant_globalusers",
                "s3a://cdm-lake/tenants-sql-warehouse/globalusers/iceberg/",
            )

            # Writer + reader catalog roles created
            assert mock_create_cat_role.call_count == 2
            mock_create_cat_role.assert_any_call(
                "tenant_globalusers", "globalusers_writer"
            )
            mock_create_cat_role.assert_any_call(
                "tenant_globalusers", "globalusers_reader"
            )

            # Writer gets CATALOG_MANAGE_CONTENT, reader gets 3 read privileges
            assert mock_grant_priv.call_count == 4
            mock_grant_priv.assert_any_call(
                "tenant_globalusers", "globalusers_writer", "CATALOG_MANAGE_CONTENT"
            )
            mock_grant_priv.assert_any_call(
                "tenant_globalusers", "globalusers_reader", "TABLE_READ_DATA"
            )
            mock_grant_priv.assert_any_call(
                "tenant_globalusers", "globalusers_reader", "TABLE_LIST"
            )
            mock_grant_priv.assert_any_call(
                "tenant_globalusers", "globalusers_reader", "NAMESPACE_LIST"
            )

            # Writer + reader principal roles created
            assert mock_create_pr_role.call_count == 2
            mock_create_pr_role.assert_any_call("globalusers_member")
            mock_create_pr_role.assert_any_call("globalusersro_member")

            # Catalog roles wired to principal roles
            assert mock_grant_cr_to_pr.call_count == 2
            mock_grant_cr_to_pr.assert_any_call(
                "tenant_globalusers", "globalusers_writer", "globalusers_member"
            )
            mock_grant_cr_to_pr.assert_any_call(
                "tenant_globalusers", "globalusers_reader", "globalusersro_member"
            )

    @pytest.mark.asyncio
    async def test_ensure_tenant_catalog_naming_conventions(self, polaris_service):
        """Test that ensure_tenant_catalog uses correct naming conventions."""
        with (
            patch.object(
                polaris_service, "create_catalog", new_callable=AsyncMock
            ) as mock_create_cat,
            patch.object(
                polaris_service, "create_catalog_role", new_callable=AsyncMock
            ),
            patch.object(
                polaris_service, "grant_catalog_privilege", new_callable=AsyncMock
            ),
            patch.object(
                polaris_service, "create_principal_role", new_callable=AsyncMock
            ) as mock_create_pr_role,
            patch.object(
                polaris_service,
                "grant_catalog_role_to_principal_role",
                new_callable=AsyncMock,
            ),
        ):
            await polaris_service.ensure_tenant_catalog(
                "myteam", "s3a://bucket/tenants/myteam/iceberg/"
            )

            # Catalog name is tenant_{group}
            mock_create_cat.assert_called_once_with(
                "tenant_myteam", "s3a://bucket/tenants/myteam/iceberg/"
            )

            # Principal roles: {group}_member and {group}ro_member
            mock_create_pr_role.assert_any_call("myteam_member")
            mock_create_pr_role.assert_any_call("myteamro_member")

    @pytest.mark.asyncio
    async def test_ensure_tenant_catalog_reader_privilege_errors_propagate(
        self, polaris_service
    ):
        """Test that reader privilege grant errors are surfaced."""
        with (
            patch.object(polaris_service, "create_catalog", new_callable=AsyncMock),
            patch.object(
                polaris_service, "create_catalog_role", new_callable=AsyncMock
            ),
            patch.object(
                polaris_service, "grant_catalog_privilege", new_callable=AsyncMock
            ) as mock_grant,
            patch.object(
                polaris_service, "create_principal_role", new_callable=AsyncMock
            ),
            patch.object(
                polaris_service,
                "grant_catalog_role_to_principal_role",
                new_callable=AsyncMock,
            ),
        ):
            # Writer grant succeeds, all reader grants raise
            mock_grant.side_effect = [
                {},  # writer CATALOG_MANAGE_CONTENT succeeds
                Exception("unsupported privilege"),  # TABLE_READ_DATA
                Exception("unsupported privilege"),  # TABLE_LIST
                Exception("unsupported privilege"),  # NAMESPACE_LIST
            ]

            with pytest.raises(Exception, match="unsupported privilege"):
                await polaris_service.ensure_tenant_catalog(
                    "testgroup", "s3a://bucket/path/"
                )

            # Stops at first failing reader privilege grant
            assert mock_grant.call_count == 2
