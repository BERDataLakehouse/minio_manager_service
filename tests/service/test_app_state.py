"""Tests for the app_state module."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI

from service import app_state
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


def test_app_state_imports():
    """Test that app_state module can be imported."""
    assert app_state is not None


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
            credential_service=MagicMock(),
            tenant_manager=MagicMock(),
        )
        assert state.auth is not None
        assert state.credential_service is not None
        assert state.tenant_manager is not None


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
    async def test_build_app_initializes_database_pool(self):
        """Test build_app initializes shared database pool correctly."""
        app = FastAPI()

        env = {
            "KBASE_AUTH_URL": "http://auth:5000/",
            "KBASE_ADMIN_ROLES": "ADMIN",
            "KBASE_REQUIRED_ROLES": "USER",
            "MINIO_ENDPOINT": "http://minio:9002",
            "MINIO_ROOT_USER": "minio",
            "MINIO_ROOT_PASSWORD": "minio123",
            "MC_PATH": "/usr/local/bin/mc",
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
            patch(
                "service.app_state.DatabasePool.create", new_callable=AsyncMock
            ) as mock_db_create,
        ):
            mock_auth.return_value = MagicMock()
            mock_mc.return_value = MagicMock()
            mock_lock = MagicMock()
            mock_lock.health_check = AsyncMock(return_value=True)
            mock_lock_cls.return_value = mock_lock
            mock_db_create.return_value = mock_db_pool

            await build_app(app)

            mock_migrate.assert_called_once()
            state = app.state._minio_manager_state
            assert state.credential_service is not None
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
        mock_db_pool = MagicMock()
        mock_db_pool.close = AsyncMock()

        app.state._lock_manager = mock_lock
        app.state._s3_client = mock_s3_client
        app.state._db_pool = mock_db_pool

        await destroy_app_state(app)

        mock_lock.close.assert_called_once()
        mock_s3_client.close_session.assert_called_once()
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
        mock_db_pool = MagicMock()
        mock_db_pool.close = AsyncMock(side_effect=Exception("DB error"))

        app.state._lock_manager = mock_lock
        app.state._s3_client = mock_s3_client
        app.state._db_pool = mock_db_pool

        # Should not raise
        await destroy_app_state(app)
