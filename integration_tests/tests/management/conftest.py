"""
Management test fixtures.

Provides fixtures specific to management tests that need MinIO file operations.
"""

import pytest
from utils.minio_client import MinIOFileHelper


@pytest.fixture(scope="function")
def minio_files(test_config):
    """
    MinIO file helper with automatic cleanup.

    Tracks all created files and deletes them after the test.

    Provides methods:
        - create_file(bucket, key, content) -> bool
        - read_as_user(bucket, key, access_key, secret_key) -> str
        - user_can_read(bucket, key, access_key, secret_key) -> bool
        - user_can_write(bucket, key, access_key, secret_key) -> bool
        - cleanup() - called automatically after test
    """
    helper = MinIOFileHelper(
        endpoint=test_config.get("minio_endpoint", "http://localhost:9002")
    )
    yield helper
    helper.cleanup()
