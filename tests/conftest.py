"""
Shared test fixtures for the minio_manager_service test suite.

Provides reusable mocks for external dependencies:
- MinIO/S3: Mock aiobotocore MinIOClient and S3 operations
- Redis: Mock distributed locking
- Subprocess: Mock MinIO CLI command execution
- KBase Auth: Mock aiohttp.ClientSession for auth API calls
- FastAPI: Mock app with dependency overrides
"""

from contextlib import asynccontextmanager
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.main import create_application
from src.minio.core.minio_client import MinIOClient
from src.minio.managers.group_manager import GroupManager
from src.minio.managers.policy_manager import PolicyManager
from src.minio.managers.user_manager import UserManager
from src.minio.models.minio_config import MinIOConfig
from src.minio.models.policy import (
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyStatement,
    PolicyType,
)
from src.minio.models.user import UserModel
from src.minio.models.group import GroupModel
from src.service.dependencies import auth
from src.service.exceptions import PolicyOperationError
from src.service.kb_auth import AdminPermission, KBaseUser


# =============================================================================
# Settings and Configuration Fixtures
# =============================================================================


@pytest.fixture
def mock_minio_config() -> MinIOConfig:
    """
    Create a mock MinIOConfig for testing.

    Returns:
        MinIOConfig with test-appropriate defaults.
    """
    return MinIOConfig(
        endpoint="http://localhost:9002",
        access_key="test_access_key",
        secret_key="test_secret_key",
        secure=False,
        default_bucket="test-bucket",
        users_sql_warehouse_prefix="users-sql-warehouse",
        users_general_warehouse_prefix="users-general-warehouse",
        tenant_general_warehouse_prefix="tenant-general-warehouse",
        tenant_sql_warehouse_prefix="tenant-sql-warehouse",
    )


# =============================================================================
# MinIO Client Fixtures
# =============================================================================


@pytest.fixture
def mock_s3_client():
    """
    Create a mock aiobotocore S3 client.

    The mock supports:
    - Bucket operations: create_bucket, delete_bucket, list_buckets
    - Object operations: put_object, get_object, delete_object
    - list_objects_v2 with pagination support
    """
    client = MagicMock()

    # Mock bucket operations
    client.create_bucket = AsyncMock()
    client.delete_bucket = AsyncMock()
    client.list_buckets = AsyncMock(return_value={"Buckets": []})

    # Mock object operations
    client.put_object = AsyncMock()
    client.get_object = AsyncMock(
        return_value={"Body": AsyncMock(read=AsyncMock(return_value=b"test data"))}
    )
    client.delete_object = AsyncMock()

    # Mock list_objects_v2 with pagination
    client.list_objects_v2 = AsyncMock(
        return_value={"Contents": [], "IsTruncated": False}
    )

    # Mock paginator
    paginator = MagicMock()
    paginator.paginate = MagicMock(return_value=AsyncMock())
    client.get_paginator = MagicMock(return_value=paginator)

    return client


@pytest.fixture
def mock_aiobotocore_session(mock_s3_client):
    """
    Mock aiobotocore.session.get_session() to return a mock session.

    This patches the global session factory so MinIOClient initialization
    uses our mock S3 client.
    """
    mock_session = MagicMock()

    @asynccontextmanager
    async def mock_create_client(*args, **kwargs):
        yield mock_s3_client

    mock_session.create_client = mock_create_client

    with patch("aiobotocore.session.get_session", return_value=mock_session):
        yield mock_session


@pytest.fixture
def mock_minio_client(mock_minio_config, mock_aiobotocore_session):
    """
    Create a real MinIOClient instance with mocked aiobotocore backend.

    This provides a MinIOClient that behaves correctly as an async context
    manager but uses mocked S3 operations underneath.
    """
    return MinIOClient(mock_minio_config)


# =============================================================================
# Redis and Distributed Lock Fixtures
# =============================================================================


@pytest.fixture
def mock_redis_client():
    """
    Create a mock Redis async client.

    Supports:
    - lock() method returning mock lock object
    - Lock acquire/release operations
    """
    client = MagicMock()

    # Mock lock object
    mock_lock = MagicMock()
    mock_lock.acquire = AsyncMock(return_value=True)
    mock_lock.release = AsyncMock()

    client.lock = MagicMock(return_value=mock_lock)
    client.close = AsyncMock()

    return client


@pytest.fixture
def mock_distributed_lock_manager(mock_redis_client):
    """
    Create a mock DistributedLockManager with mocked Redis client.

    Usage in tests:
        async with lock_manager.policy_update_lock("policy_name"):
            # Critical section code
            pass
    """

    @asynccontextmanager
    async def mock_policy_update_lock(policy_name: str, timeout: int = None):
        """Mock async context manager for policy locks."""
        lock = mock_redis_client.lock(
            f"policy_lock:{policy_name}", timeout=timeout or 30
        )
        acquired = await lock.acquire(blocking=False)
        if not acquired:
            raise PolicyOperationError(
                f"Policy '{policy_name}' is currently locked. Try again later."
            )
        try:
            yield lock
        finally:
            await lock.release()

    manager = MagicMock()
    manager.policy_update_lock = mock_policy_update_lock
    manager.close = AsyncMock()
    manager.redis = mock_redis_client

    return manager


# =============================================================================
# Subprocess Execution Fixtures
# =============================================================================


@pytest.fixture
def mock_subprocess():
    """
    Mock asyncio.create_subprocess_exec for MinIO CLI command execution.

    Returns a factory function to configure subprocess behavior:
        mock_subprocess(stdout=b"output", stderr=b"", returncode=0)

    Usage in tests:
        with mock_subprocess(stdout=b'{"status":"success"}'):
            result = await executor.execute_command(["mc", "admin", "user", "add"])
    """

    def _configure_subprocess(
        stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0
    ):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(stdout, stderr))
        mock_proc.returncode = returncode

        patcher = patch("asyncio.create_subprocess_exec", return_value=mock_proc)
        patcher.start()
        return mock_proc, patcher

    return _configure_subprocess


# =============================================================================
# Data Model Fixtures
# =============================================================================


@pytest.fixture
def sample_user_data():
    """Factory for creating sample UserModel instances."""

    def _create_user(
        username: str = "testuser",
        access_key: str = "test_access_key",
        secret_key: str = "test_secret_key",
        policies: List[str] = None,
        groups: List[str] = None,
        accessible_paths: List[str] = None,
    ) -> UserModel:
        return UserModel(
            username=username,
            access_key=access_key,
            secret_key=secret_key,
            policies=policies or [],
            groups=groups or [],
            accessible_paths=accessible_paths or [],
        )

    return _create_user


@pytest.fixture
def sample_policy_data():
    """Factory for creating sample PolicyModel and PolicyDocument instances."""

    def _create_policy(
        name: str = "test-policy",
        policy_type: PolicyType = PolicyType.USER_HOME,
        document: PolicyDocument = None,
    ) -> PolicyModel:
        if document is None:
            document = PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    PolicyStatement(
                        Effect=PolicyEffect.ALLOW,
                        Action=["s3:GetObject", "s3:PutObject"],
                        Resource=["arn:aws:s3:::test-bucket/test-path/*"],
                    )
                ],
            )

        return PolicyModel(name=name, type=policy_type, document=document)

    return _create_policy


@pytest.fixture
def sample_policy_document():
    """Factory for creating PolicyDocument instances."""

    def _create_document(
        resources: List[str] = None, actions: List[str] = None
    ) -> PolicyDocument:
        if resources is None:
            resources = ["arn:aws:s3:::test-bucket/test-path/*"]
        if actions is None:
            actions = ["s3:GetObject", "s3:PutObject"]

        return PolicyDocument(
            Version="2012-10-17",
            Statement=[
                PolicyStatement(
                    Effect=PolicyEffect.ALLOW, Action=actions, Resource=resources
                )
            ],
        )

    return _create_document


@pytest.fixture
def sample_group_data():
    """Factory for creating sample GroupModel instances."""

    def _create_group(
        name: str = "testgroup",
        members: List[str] = None,
        policies: List[str] = None,
    ) -> GroupModel:
        return GroupModel(name=name, members=members or [], policies=policies or [])

    return _create_group


# =============================================================================
# Manager Fixtures
# =============================================================================


@pytest.fixture
def mock_policy_manager(mock_minio_client, mock_minio_config):
    """Create a PolicyManager with mocked dependencies."""

    return PolicyManager(mock_minio_client, mock_minio_config)


@pytest.fixture
def mock_user_manager(mock_minio_client, mock_minio_config):
    """Create a UserManager with mocked dependencies."""

    return UserManager(mock_minio_client, mock_minio_config)


@pytest.fixture
def mock_group_manager(mock_minio_client, mock_minio_config):
    """Create a GroupManager with mocked dependencies."""

    return GroupManager(mock_minio_client, mock_minio_config)


# =============================================================================
# KBase Auth Fixtures
# =============================================================================


@pytest.fixture
def mock_kbase_user():
    """Factory for creating mock KBaseUser instances."""

    def _create_user(
        username: str = "testuser", admin_perm: AdminPermission = AdminPermission.NONE
    ) -> KBaseUser:
        return KBaseUser(user=username, admin_perm=admin_perm)

    return _create_user


@pytest.fixture
def mock_aiohttp_session():
    """
    Create a mock aiohttp ClientSession for testing KBase auth.

    Usage:
        session = mock_aiohttp_session({"http://auth/api/V2/token": {"user": "testuser"}})
    """

    def _create_session(responses: Dict[str, Any] = None):
        if responses is None:
            responses = {}

        session = MagicMock()

        async def mock_get(url, headers=None):
            response = MagicMock()
            response.status = 200

            async def mock_json():
                return responses.get(url, {"user": "testuser"})

            response.json = mock_json
            return response

        # Create async context manager
        context_manager = MagicMock()
        context_manager.__aenter__ = AsyncMock(
            side_effect=lambda: mock_get(context_manager._url, context_manager._headers)
        )
        context_manager.__aexit__ = AsyncMock(return_value=None)

        def get_side_effect(url, headers=None):
            context_manager._url = url
            context_manager._headers = headers
            return context_manager

        session.get.side_effect = get_side_effect
        session.close = AsyncMock()
        session.closed = False

        return session

    return _create_session


# =============================================================================
# FastAPI Testing Fixtures
# =============================================================================


@pytest.fixture
def client():
    """
    Basic test client without mocked dependencies.

    Note: This requires actual services to be available.
    Use mock_app fixture for unit tests with mocks.
    """
    app = create_application()
    return TestClient(app)


@pytest.fixture
def mock_app(mock_kbase_user):
    """
    Create a FastAPI app with mocked dependencies for route testing.

    Returns tuple: (app, mock_managers)
    where mock_managers contains mocked UserManager, PolicyManager, etc.
    """
    app = create_application()

    # Create mock user
    user = mock_kbase_user()

    # Mock auth dependency

    def mock_auth():
        return user

    app.dependency_overrides[auth] = mock_auth

    # Mock manager dependencies would be added here as needed
    mock_managers = MagicMock()

    return app, mock_managers


@pytest.fixture
def test_client(mock_app):
    """
    Create a TestClient with mocked dependencies.

    Usage:
        def test_endpoint(test_client):
            response = test_client.get("/health")
            assert response.status_code == 200
    """
    app, _ = mock_app
    return TestClient(app)
