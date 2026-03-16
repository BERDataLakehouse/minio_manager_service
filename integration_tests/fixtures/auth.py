"""
Authentication fixtures for integration tests.

Provides HTTP clients and authentication headers for API testing.
All fixtures are designed for parallel-safe execution.
"""

import os
import pytest
import httpx


@pytest.fixture(scope="session")
def test_config():
    """
    Test configuration from environment variables.

    Session-scoped as values don't change between tests.
    """
    return {
        "base_url": os.getenv("API_BASE_URL", "http://localhost:8010"),
        "admin_token": os.getenv("ADMIN_KBASE_TOKEN"),  # tgu2
        "user_token": os.getenv("KBASE_TOKEN"),  # tgu3
        "minio_endpoint": os.getenv("MINIO_ENDPOINT", "http://localhost:9012"),
        "minio_root_user": os.getenv("MINIO_ROOT_USER", "minio"),
        "minio_root_password": os.getenv("MINIO_ROOT_PASSWORD", "minio123"),
        "redis_url": os.getenv("REDIS_URL", "redis://localhost:6389"),
        "test_timeout": int(os.getenv("TEST_TIMEOUT", "60")),
        # PostgreSQL credential store config
        "db_host": os.getenv("MMS_DB_HOST", "localhost"),
        "db_port": int(os.getenv("MMS_DB_PORT", "5442")),
        "db_name": os.getenv("MMS_DB_NAME", "mms"),
        "db_user": os.getenv("MMS_DB_USER", "mms"),
        "db_password": os.getenv("MMS_DB_PASSWORD", "mmspassword"),
        "db_encryption_key": os.getenv("MMS_DB_ENCRYPTION_KEY", "change-me-in-prod"),
    }


@pytest.fixture(scope="function")
def api_client(test_config):
    """
    Fresh HTTP client for each test.

    Function-scoped to prevent connection pooling issues between parallel tests.
    """
    client = httpx.Client(
        base_url=test_config["base_url"],
        timeout=test_config["test_timeout"],
    )
    yield client
    client.close()


@pytest.fixture(scope="session")
def admin_username():
    """
    The admin username for sharing tests.

    This is the user that admin_headers authenticates as.
    Sharing tests must use paths in this user's workspace.
    """
    return "tgu2"


@pytest.fixture(scope="session")
def admin_headers(test_config):
    """
    Admin authentication headers (tgu2).

    Session-scoped as headers are read-only and thread-safe.

    Skip test if ADMIN_KBASE_TOKEN not provided.
    """
    if not test_config["admin_token"]:
        pytest.skip("ADMIN_KBASE_TOKEN not provided")

    return {
        "Authorization": f"Bearer {test_config['admin_token']}",
        "Content-Type": "application/json",
    }


@pytest.fixture(scope="session")
def user_headers(test_config):
    """
    Regular user authentication headers (tgu3).

    Session-scoped as headers are read-only and thread-safe.

    Skip test if KBASE_TOKEN not provided.
    """
    if not test_config["user_token"]:
        pytest.skip("KBASE_TOKEN not provided")

    return {
        "Authorization": f"Bearer {test_config['user_token']}",
        "Content-Type": "application/json",
    }


@pytest.fixture(scope="function")
def admin_client(test_config, admin_headers):
    """
    HTTP client pre-configured with admin headers.

    Convenience fixture for admin-only tests.
    """
    client = httpx.Client(
        base_url=test_config["base_url"],
        timeout=test_config["test_timeout"],
        headers=admin_headers,
    )
    yield client
    client.close()


@pytest.fixture(scope="function")
def user_client(test_config, user_headers):
    """
    HTTP client pre-configured with regular user headers.

    Convenience fixture for user-facing endpoint tests.
    """
    client = httpx.Client(
        base_url=test_config["base_url"],
        timeout=test_config["test_timeout"],
        headers=user_headers,
    )
    yield client
    client.close()
