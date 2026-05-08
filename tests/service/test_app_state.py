"""Tests for the app_state module."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI

from service.app_state import (
    AppState,
    RequestState,
    _get_app_state_from_app,
    build_app,
    destroy_app_state,
    get_app_state,
    get_request_user,
    set_request_user,
)
from service.kb_auth import AdminPermission, KBaseUser


# === APP STATE NAMEDTUPLE TESTS ===


class TestAppStateNamedTuple:
    """Tests for the AppState NamedTuple."""

    def test_app_state_fields(self):
        """Test AppState has all expected fields."""
        state = AppState(
            auth=MagicMock(),
            user_manager=MagicMock(),
            group_manager=MagicMock(),
            policy_manager=MagicMock(),
            sharing_manager=MagicMock(),
            polaris_user_manager=MagicMock(),
            polaris_group_manager=MagicMock(),
            polaris_credential_service=MagicMock(),
            s3_credential_service=MagicMock(),
            tenant_manager=MagicMock(),
            users_sql_warehouse_base="s3a://test-bucket/users-sql",
            tenant_sql_warehouse_base="s3a://test-bucket/tenant-sql",
        )
        assert state.auth is not None
        assert state.polaris_user_manager is not None
        assert state.polaris_group_manager is not None
        assert state.polaris_credential_service is not None
        assert state.s3_credential_service is not None
        assert state.tenant_manager is not None

    def test_app_state_does_not_expose_raw_polaris_service(self):
        """The low-level PolarisService is teardown-only.

        Routes interact with Polaris exclusively through the manager layer
        (``polaris_user_manager`` / ``polaris_group_manager``) and the
        ``polaris_credential_service``. Exposing the raw client on AppState
        would invite direct calls that bypass the manager-layer
        orchestration; keep it on ``app.state._polaris_service`` for
        ``destroy_app_state`` only.
        """
        assert "polaris_service" not in AppState._fields


# === REQUEST STATE TESTS ===


class TestRequestState:
    """Tests for RequestState and request user helpers."""

    def test_request_state_with_user(self):
        """Test RequestState holds a user."""
        user = KBaseUser(user="testuser", admin_perm=AdminPermission.NONE)
        state = RequestState(user=user)
        assert state.user.user == "testuser"

    def test_request_state_with_none(self):
        """Test RequestState with no user."""
        state = RequestState(user=None)
        assert state.user is None

    def test_set_and_get_request_user(self):
        """Test set_request_user and get_request_user round-trip."""
        request = MagicMock()
        request.state = MagicMock()
        user = KBaseUser(user="testuser", admin_perm=AdminPermission.NONE)

        set_request_user(request, user)

        # get_request_user reads from request.state._request_state
        result = get_request_user(request)
        assert result.user == "testuser"

    def test_get_request_user_no_state(self):
        """Test get_request_user returns None when no state set."""
        request = MagicMock()
        request.state = MagicMock(spec=[])  # No _request_state attribute

        result = get_request_user(request)
        assert result is None

    def test_get_request_user_falsy_state(self):
        """Test get_request_user returns None when state is falsy."""
        request = MagicMock()
        request.state._request_state = None

        result = get_request_user(request)
        assert result is None


# === GET APP STATE TESTS ===


class TestGetAppState:
    """Tests for get_app_state and _get_app_state_from_app."""

    def test_get_app_state_from_request(self):
        """Test get_app_state extracts state from request."""
        mock_state = MagicMock()
        request = MagicMock()
        request.app.state._minio_manager_state = mock_state

        result = get_app_state(request)
        assert result is mock_state

    def test_get_app_state_from_app_not_initialized(self):
        """Test raises ValueError when state not initialized."""
        app = FastAPI()

        with pytest.raises(ValueError, match="App state has not been initialized"):
            _get_app_state_from_app(app)

    def test_get_app_state_from_app_falsy(self):
        """Test raises ValueError when state is falsy."""
        app = FastAPI()
        app.state._minio_manager_state = None

        with pytest.raises(ValueError, match="App state has not been initialized"):
            _get_app_state_from_app(app)


# === BUILD APP TESTS ===


class TestBuildApp:
    """Tests for build_app initialization."""

    @pytest.mark.asyncio
    async def test_build_app_initializes_all_services(self):
        """Test build_app initializes all services correctly."""
        app = FastAPI()

        env = {
            "KBASE_AUTH_URL": "http://auth:5000/",
            "KBASE_ADMIN_ROLES": "ADMIN",
            "KBASE_REQUIRED_ROLES": "USER",
            "MINIO_ENDPOINT": "http://minio:9002",
            "MINIO_ROOT_USER": "minio",
            "MINIO_ROOT_PASSWORD": "minio123",
            "MC_PATH": "/usr/local/bin/mc",
            "POLARIS_CATALOG_URI": "http://polaris:8181",
            "POLARIS_CREDENTIAL": "root:s3cr3t",
            "MMS_DB_HOST": "localhost",
            "MMS_DB_PORT": "5432",
            "MMS_DB_NAME": "mms",
            "MMS_DB_USER": "mms",
            "MMS_DB_PASSWORD": "mmspassword",
            "MMS_DB_ENCRYPTION_KEY": "test-key",
        }

        mock_pool = MagicMock()
        mock_db_pool = MagicMock()
        mock_db_pool.pool = mock_pool

        with (
            patch.dict(os.environ, env, clear=False),
            patch("service.app_state.run_migrations") as mock_migrate,
            patch(
                "service.app_state.KBaseAuth.create", new_callable=AsyncMock
            ) as mock_auth,
            patch(
                "service.app_state.S3Client.create", new_callable=AsyncMock
            ) as mock_mc,
            patch("service.app_state.DistributedLockManager") as mock_lock_cls,
            patch("service.app_state.PolarisService") as mock_polaris_cls,
            patch(
                "service.app_state.DatabasePool.create", new_callable=AsyncMock
            ) as mock_db_create,
        ):
            mock_auth.return_value = MagicMock()
            mock_mc.return_value = MagicMock()
            mock_lock = MagicMock()
            mock_lock.health_check = AsyncMock(return_value=True)
            mock_lock_cls.return_value = mock_lock
            mock_polaris_cls.return_value = MagicMock()
            mock_db_create.return_value = mock_db_pool

            await build_app(app)

            mock_migrate.assert_called_once()
            state = app.state._minio_manager_state
            assert state.polaris_user_manager is not None
            assert state.polaris_group_manager is not None
            assert state.polaris_credential_service is not None
            assert state.s3_credential_service is not None
            # The raw PolarisService is parked on app.state for shutdown
            # but intentionally not exposed via AppState.
            assert app.state._polaris_service is not None
            # Verify Polaris was called with correct args
            call_args = mock_polaris_cls.call_args[0]
            assert call_args[0] == "http://polaris:8181"
            assert call_args[1] == "root:s3cr3t"
            assert call_args[2].rstrip("/") == "http://minio:9002"
            # Verify DB pool was initialized
            assert app.state._db_pool is mock_db_pool
            assert state.tenant_manager is not None
            mock_db_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_build_app_redis_failure_raises(self):
        """Test build_app raises RuntimeError when Redis is unavailable."""
        app = FastAPI()

        env = {
            "KBASE_AUTH_URL": "http://auth:5000/",
            "MINIO_ENDPOINT": "http://minio:9002",
            "MINIO_ROOT_USER": "minio",
            "MINIO_ROOT_PASSWORD": "minio123",
            "MC_PATH": "/usr/local/bin/mc",
            "POLARIS_CATALOG_URI": "http://polaris:8181",
            "POLARIS_CREDENTIAL": "root:s3cr3t",
            "MMS_DB_HOST": "localhost",
            "MMS_DB_NAME": "mms",
            "MMS_DB_USER": "mms",
            "MMS_DB_PASSWORD": "mmspassword",
            "MMS_DB_ENCRYPTION_KEY": "test-key",
        }

        mock_db_pool = MagicMock()
        mock_db_pool.pool = MagicMock()

        with (
            patch.dict(os.environ, env, clear=False),
            patch("service.app_state.run_migrations"),
            patch(
                "service.app_state.DatabasePool.create", new_callable=AsyncMock
            ) as mock_db_create,
            patch(
                "service.app_state.KBaseAuth.create", new_callable=AsyncMock
            ) as mock_auth,
            patch(
                "service.app_state.S3Client.create", new_callable=AsyncMock
            ) as mock_mc,
            patch("service.app_state.DistributedLockManager") as mock_lock_cls,
            patch("service.app_state.PolarisService"),
        ):
            mock_db_create.return_value = mock_db_pool
            mock_auth.return_value = MagicMock()
            mock_mc.return_value = MagicMock()
            mock_lock = MagicMock()
            mock_lock.health_check = AsyncMock(return_value=False)
            mock_lock_cls.return_value = mock_lock

            with pytest.raises(RuntimeError, match="Failed to connect to Redis"):
                await build_app(app)


# === DESTROY APP STATE TESTS ===


class TestDestroyAppState:
    """Tests for destroy_app_state cleanup."""

    @pytest.mark.asyncio
    async def test_destroy_app_state_closes_resources(self):
        """Test resources are closed during shutdown."""
        app = FastAPI()
        mock_lock = MagicMock()
        mock_lock.close = AsyncMock()
        mock_s3_client = MagicMock()
        mock_s3_client.close_session = AsyncMock()
        mock_polaris = MagicMock()
        mock_polaris.close = AsyncMock()
        mock_db_pool = MagicMock()
        mock_db_pool.close = AsyncMock()

        app.state._lock_manager = mock_lock
        app.state._s3_client = mock_s3_client
        app.state._db_pool = mock_db_pool
        app.state._polaris_service = mock_polaris
        app.state._minio_manager_state = AppState(
            auth=MagicMock(),
            user_manager=MagicMock(),
            group_manager=MagicMock(),
            policy_manager=MagicMock(),
            sharing_manager=MagicMock(),
            polaris_user_manager=MagicMock(),
            polaris_group_manager=MagicMock(),
            polaris_credential_service=MagicMock(),
            s3_credential_service=MagicMock(),
            tenant_manager=MagicMock(),
            users_sql_warehouse_base="s3a://test-bucket/users-sql",
            tenant_sql_warehouse_base="s3a://test-bucket/tenant-sql",
        )

        await destroy_app_state(app)

        mock_lock.close.assert_called_once()
        mock_s3_client.close_session.assert_called_once()
        mock_polaris.close.assert_called_once()
        mock_db_pool.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_destroy_app_state_handles_missing_state(self):
        """Test destroy works when no state exists."""
        app = FastAPI()
        # No _minio_manager_state set
        await destroy_app_state(app)  # Should not raise

    @pytest.mark.asyncio
    async def test_destroy_app_state_handles_close_errors(self):
        """Test destroy logs warnings but doesn't raise on close errors."""
        app = FastAPI()
        mock_lock = MagicMock()
        mock_lock.close = AsyncMock(side_effect=Exception("Redis error"))
        mock_s3_client = MagicMock()
        mock_s3_client.close_session = AsyncMock(side_effect=Exception("S3 error"))
        mock_polaris = MagicMock()
        mock_polaris.close = AsyncMock(side_effect=Exception("Polaris error"))
        mock_db_pool = MagicMock()
        mock_db_pool.close = AsyncMock(side_effect=Exception("DB error"))

        app.state._lock_manager = mock_lock
        app.state._s3_client = mock_s3_client
        app.state._db_pool = mock_db_pool
        app.state._polaris_service = mock_polaris
        app.state._minio_manager_state = AppState(
            auth=MagicMock(),
            user_manager=MagicMock(),
            group_manager=MagicMock(),
            policy_manager=MagicMock(),
            sharing_manager=MagicMock(),
            polaris_user_manager=MagicMock(),
            polaris_group_manager=MagicMock(),
            polaris_credential_service=MagicMock(),
            s3_credential_service=MagicMock(),
            tenant_manager=MagicMock(),
            users_sql_warehouse_base="s3a://test-bucket/users-sql",
            tenant_sql_warehouse_base="s3a://test-bucket/tenant-sql",
        )

        # Should not raise
        await destroy_app_state(app)
