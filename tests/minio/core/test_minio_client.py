"""
Comprehensive tests for the minio.core.minio_client module.

MinIOClient provides async wrapper around aiobotocore for S3/MinIO operations.
Tests use mocked aiobotocore client from conftest.py fixtures.
"""

import aiobotocore.session
import pytest
from botocore.exceptions import ClientError
from unittest.mock import AsyncMock, MagicMock, patch

from src.minio.core.minio_client import MinIOClient, MAX_LIST_OBJECTS_COUNT
from src.service.exceptions import BucketOperationError, ConnectionError


# =============================================================================
# Helper Classes for Testing
# =============================================================================


class AsyncIteratorMock:
    """Mock async iterator for paginator testing."""

    def __init__(self, items):
        self.items = items.copy()

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.items:
            raise StopAsyncIteration
        return self.items.pop(0)


# =============================================================================
# TestMinIOClientInitialization - Client setup and lifecycle
# =============================================================================


class TestMinIOClientInitialization:
    """Tests for MinIOClient initialization and session management."""

    def test_init_with_config(self, mock_minio_config):
        """Test basic initialization with config."""
        client = MinIOClient(mock_minio_config)
        assert client.config == mock_minio_config
        assert client._session is None

    @pytest.mark.asyncio
    async def test_create_initializes_session(
        self, mock_minio_config, mock_aiobotocore_session
    ):
        """Test class method create() initializes session."""
        client = await MinIOClient.create(mock_minio_config)
        assert client._session is not None
        assert client.config == mock_minio_config

    @pytest.mark.asyncio
    async def test_initialize_session(
        self, mock_minio_config, mock_aiobotocore_session
    ):
        """Test manual session initialization."""
        client = MinIOClient(mock_minio_config)
        assert client._session is None

        await client.initialize_session()
        assert client._session is not None

    @pytest.mark.asyncio
    async def test_initialize_session_error_handling(self, mock_minio_config):
        """Test that session initialization errors are properly wrapped."""
        client = MinIOClient(mock_minio_config)

        # Mock get_session to raise an error
        with patch.object(
            aiobotocore.session,
            "get_session",
            side_effect=RuntimeError("Session failed"),
        ):
            with pytest.raises(ConnectionError, match="Failed to initialize session"):
                await client.initialize_session()

    @pytest.mark.asyncio
    async def test_close_session(self, mock_minio_config, mock_aiobotocore_session):
        """Test session cleanup."""
        client = MinIOClient(mock_minio_config)
        await client.initialize_session()
        assert client._session is not None

        await client.close_session()
        assert client._session is None

    @pytest.mark.asyncio
    async def test_async_context_manager(
        self, mock_minio_config, mock_aiobotocore_session
    ):
        """Test using MinIOClient as async context manager."""
        client = MinIOClient(mock_minio_config)
        assert client._session is None

        async with client as ctx_client:
            assert ctx_client is client
            assert client._session is not None

        # Session should be closed after exiting context
        assert client._session is None


# =============================================================================
# TestConnectionTesting - Connection verification
# =============================================================================


class TestConnectionTesting:
    """Tests for connection testing functionality."""

    @pytest.mark.asyncio
    async def test_test_connection_success(self, mock_minio_client, mock_s3_client):
        """Test successful connection test."""
        mock_s3_client.list_buckets = AsyncMock(
            return_value={"Buckets": [{"Name": "bucket1"}, {"Name": "bucket2"}]}
        )

        async with mock_minio_client:
            result = await mock_minio_client.test_connection()

        assert result is True

    @pytest.mark.asyncio
    async def test_test_connection_failure(self, mock_minio_client, mock_s3_client):
        """Test connection test with failure."""
        mock_s3_client.list_buckets = AsyncMock(
            side_effect=Exception("Connection refused")
        )

        async with mock_minio_client:
            result = await mock_minio_client.test_connection()

        assert result is False

    @pytest.mark.asyncio
    async def test_test_connection_empty_buckets(
        self, mock_minio_client, mock_s3_client
    ):
        """Test connection test with no buckets."""
        mock_s3_client.list_buckets = AsyncMock(return_value={"Buckets": []})

        async with mock_minio_client:
            result = await mock_minio_client.test_connection()

        assert result is True


# =============================================================================
# TestBucketOperations - Bucket CRUD operations
# =============================================================================


class TestBucketOperations:
    """Tests for bucket creation, deletion, listing, and existence checks."""

    @pytest.mark.asyncio
    async def test_create_bucket(self, mock_minio_client, mock_s3_client):
        """Test bucket creation."""
        mock_s3_client.create_bucket = AsyncMock()

        async with mock_minio_client:
            await mock_minio_client.create_bucket("test-bucket")

        mock_s3_client.create_bucket.assert_called_once_with(Bucket="test-bucket")

    @pytest.mark.asyncio
    async def test_create_bucket_error(self, mock_minio_client, mock_s3_client):
        """Test bucket creation with error."""
        mock_s3_client.create_bucket = AsyncMock(
            side_effect=Exception("Bucket already exists")
        )

        async with mock_minio_client:
            with pytest.raises(BucketOperationError, match="Bucket creation failed"):
                await mock_minio_client.create_bucket("test-bucket")

    @pytest.mark.asyncio
    async def test_bucket_exists_true(self, mock_minio_client, mock_s3_client):
        """Test bucket existence check when bucket exists."""
        mock_s3_client.head_bucket = AsyncMock()

        async with mock_minio_client:
            result = await mock_minio_client.bucket_exists("test-bucket")

        assert result is True
        mock_s3_client.head_bucket.assert_called_once_with(Bucket="test-bucket")

    @pytest.mark.asyncio
    async def test_bucket_exists_false(self, mock_minio_client, mock_s3_client):
        """Test bucket existence check when bucket does not exist."""
        error_response = {"Error": {"Code": "404"}}
        mock_s3_client.head_bucket = AsyncMock(
            side_effect=ClientError(error_response, "HeadBucket")
        )

        async with mock_minio_client:
            result = await mock_minio_client.bucket_exists("nonexistent-bucket")

        assert result is False

    @pytest.mark.asyncio
    async def test_bucket_exists_error(self, mock_minio_client, mock_s3_client):
        """Test bucket existence check with non-404 error."""
        error_response = {"Error": {"Code": "403"}}
        mock_s3_client.head_bucket = AsyncMock(
            side_effect=ClientError(error_response, "HeadBucket")
        )

        async with mock_minio_client:
            with pytest.raises(BucketOperationError, match="Bucket check failed"):
                await mock_minio_client.bucket_exists("forbidden-bucket")

    @pytest.mark.asyncio
    async def test_bucket_exists_unexpected_error(
        self, mock_minio_client, mock_s3_client
    ):
        """Test bucket existence check with unexpected exception."""
        mock_s3_client.head_bucket = AsyncMock(
            side_effect=RuntimeError("Network error")
        )

        async with mock_minio_client:
            with pytest.raises(BucketOperationError, match="Bucket check failed"):
                await mock_minio_client.bucket_exists("test-bucket")

    @pytest.mark.asyncio
    async def test_list_buckets(self, mock_minio_client, mock_s3_client):
        """Test listing buckets."""
        mock_s3_client.list_buckets = AsyncMock(
            return_value={
                "Buckets": [
                    {"Name": "bucket1"},
                    {"Name": "bucket2"},
                    {"Name": "bucket3"},
                ]
            }
        )

        async with mock_minio_client:
            buckets = await mock_minio_client.list_buckets()

        assert buckets == ["bucket1", "bucket2", "bucket3"]

    @pytest.mark.asyncio
    async def test_list_buckets_empty(self, mock_minio_client, mock_s3_client):
        """Test listing buckets when none exist."""
        mock_s3_client.list_buckets = AsyncMock(return_value={"Buckets": []})

        async with mock_minio_client:
            buckets = await mock_minio_client.list_buckets()

        assert buckets == []

    @pytest.mark.asyncio
    async def test_list_buckets_error(self, mock_minio_client, mock_s3_client):
        """Test listing buckets with error."""
        mock_s3_client.list_buckets = AsyncMock(side_effect=Exception("Access denied"))

        async with mock_minio_client:
            with pytest.raises(BucketOperationError, match="Bucket listing failed"):
                await mock_minio_client.list_buckets()

    @pytest.mark.asyncio
    async def test_delete_bucket_empty(self, mock_minio_client, mock_s3_client):
        """Test deleting an empty bucket."""
        # Mock paginator for empty bucket
        mock_paginator = MagicMock()
        async_iterator = AsyncIteratorMock([{}])  # Empty page, no Contents
        mock_paginator.paginate = MagicMock(return_value=async_iterator)
        mock_s3_client.get_paginator = MagicMock(return_value=mock_paginator)
        mock_s3_client.delete_bucket = AsyncMock()

        async with mock_minio_client:
            await mock_minio_client.delete_bucket("test-bucket")

        mock_s3_client.delete_bucket.assert_called_once_with(Bucket="test-bucket")

    @pytest.mark.asyncio
    async def test_delete_bucket_with_objects(self, mock_minio_client, mock_s3_client):
        """Test deleting a bucket with objects."""
        # Mock paginator with objects
        mock_paginator = MagicMock()
        async_iterator = AsyncIteratorMock(
            [
                {"Contents": [{"Key": "obj1"}, {"Key": "obj2"}]},
                {"Contents": [{"Key": "obj3"}]},
            ]
        )
        mock_paginator.paginate = MagicMock(return_value=async_iterator)
        mock_s3_client.get_paginator = MagicMock(return_value=mock_paginator)
        mock_s3_client.delete_objects = AsyncMock()
        mock_s3_client.delete_bucket = AsyncMock()

        async with mock_minio_client:
            await mock_minio_client.delete_bucket("test-bucket")

        # Should delete objects in two batches
        assert mock_s3_client.delete_objects.call_count == 2
        mock_s3_client.delete_bucket.assert_called_once_with(Bucket="test-bucket")

    @pytest.mark.asyncio
    async def test_delete_bucket_error(self, mock_minio_client, mock_s3_client):
        """Test bucket deletion with error."""
        mock_paginator = MagicMock()
        async_iterator = AsyncIteratorMock([{}])
        mock_paginator.paginate = MagicMock(return_value=async_iterator)
        mock_s3_client.get_paginator = MagicMock(return_value=mock_paginator)
        mock_s3_client.delete_bucket = AsyncMock(side_effect=Exception("Cannot delete"))

        async with mock_minio_client:
            with pytest.raises(BucketOperationError, match="Bucket deletion failed"):
                await mock_minio_client.delete_bucket("test-bucket")


# =============================================================================
# TestObjectOperations - Object CRUD operations
# =============================================================================


class TestObjectOperations:
    """Tests for object put, get, delete, and list operations."""

    @pytest.mark.asyncio
    async def test_put_object(self, mock_minio_client, mock_s3_client):
        """Test putting an object."""
        mock_s3_client.put_object = AsyncMock()

        async with mock_minio_client:
            await mock_minio_client.put_object(
                "test-bucket", "path/to/object", b"test data"
            )

        mock_s3_client.put_object.assert_called_once_with(
            Bucket="test-bucket", Key="path/to/object", Body=b"test data"
        )

    @pytest.mark.asyncio
    async def test_put_object_error(self, mock_minio_client, mock_s3_client):
        """Test putting an object with error."""
        mock_s3_client.put_object = AsyncMock(side_effect=Exception("Upload failed"))

        async with mock_minio_client:
            with pytest.raises(BucketOperationError, match="Object put failed"):
                await mock_minio_client.put_object(
                    "test-bucket", "path/to/object", b"test data"
                )

    @pytest.mark.asyncio
    async def test_get_object(self, mock_minio_client, mock_s3_client):
        """Test getting an object."""
        mock_body = MagicMock()
        mock_body.read = AsyncMock(return_value=b"object content")
        mock_s3_client.get_object = AsyncMock(return_value={"Body": mock_body})

        async with mock_minio_client:
            content = await mock_minio_client.get_object(
                "test-bucket", "path/to/object"
            )

        assert content == b"object content"
        mock_s3_client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key="path/to/object"
        )

    @pytest.mark.asyncio
    async def test_get_object_error(self, mock_minio_client, mock_s3_client):
        """Test getting an object with error."""
        mock_s3_client.get_object = AsyncMock(side_effect=Exception("Object not found"))

        async with mock_minio_client:
            with pytest.raises(BucketOperationError, match="Object get failed"):
                await mock_minio_client.get_object("test-bucket", "nonexistent")

    @pytest.mark.asyncio
    async def test_delete_object(self, mock_minio_client, mock_s3_client):
        """Test deleting an object."""
        mock_s3_client.delete_object = AsyncMock()

        async with mock_minio_client:
            await mock_minio_client.delete_object("test-bucket", "path/to/object")

        mock_s3_client.delete_object.assert_called_once_with(
            Bucket="test-bucket", Key="path/to/object"
        )

    @pytest.mark.asyncio
    async def test_delete_object_error(self, mock_minio_client, mock_s3_client):
        """Test deleting an object with error."""
        mock_s3_client.delete_object = AsyncMock(side_effect=Exception("Delete failed"))

        async with mock_minio_client:
            with pytest.raises(BucketOperationError, match="Object deletion failed"):
                await mock_minio_client.delete_object("test-bucket", "path/to/object")

    @pytest.mark.asyncio
    async def test_list_objects_basic(self, mock_minio_client, mock_s3_client):
        """Test listing objects with default parameters."""
        mock_paginator = MagicMock()
        async_iterator = AsyncIteratorMock(
            [
                {"Contents": [{"Key": "obj1"}, {"Key": "obj2"}]},
                {"Contents": [{"Key": "obj3"}]},
            ]
        )
        mock_paginator.paginate = MagicMock(return_value=async_iterator)
        mock_s3_client.get_paginator = MagicMock(return_value=mock_paginator)

        async with mock_minio_client:
            objects = await mock_minio_client.list_objects("test-bucket")

        assert objects == ["obj1", "obj2", "obj3"]
        mock_paginator.paginate.assert_called_once_with(Bucket="test-bucket", Prefix="")

    @pytest.mark.asyncio
    async def test_list_objects_with_prefix(self, mock_minio_client, mock_s3_client):
        """Test listing objects with prefix filter."""
        mock_paginator = MagicMock()
        async_iterator = AsyncIteratorMock(
            [{"Contents": [{"Key": "users/file1"}, {"Key": "users/file2"}]}]
        )
        mock_paginator.paginate = MagicMock(return_value=async_iterator)
        mock_s3_client.get_paginator = MagicMock(return_value=mock_paginator)

        async with mock_minio_client:
            objects = await mock_minio_client.list_objects(
                "test-bucket", prefix="users/"
            )

        assert objects == ["users/file1", "users/file2"]
        mock_paginator.paginate.assert_called_once_with(
            Bucket="test-bucket", Prefix="users/"
        )

    @pytest.mark.asyncio
    async def test_list_objects_empty(self, mock_minio_client, mock_s3_client):
        """Test listing objects in empty bucket."""
        mock_paginator = MagicMock()
        async_iterator = AsyncIteratorMock([{}])  # No Contents key
        mock_paginator.paginate = MagicMock(return_value=async_iterator)
        mock_s3_client.get_paginator = MagicMock(return_value=mock_paginator)

        async with mock_minio_client:
            objects = await mock_minio_client.list_objects("test-bucket")

        assert objects == []

    @pytest.mark.asyncio
    async def test_list_objects_respects_limit(self, mock_minio_client, mock_s3_client):
        """Test that list_objects respects MAX_LIST_OBJECTS_COUNT."""
        # Create pages that would exceed the limit
        page1_objects = [{"Key": f"obj{i}"} for i in range(8000)]
        page2_objects = [{"Key": f"obj{i}"} for i in range(8000, 15000)]

        mock_paginator = MagicMock()
        async_iterator = AsyncIteratorMock(
            [{"Contents": page1_objects}, {"Contents": page2_objects}]
        )
        mock_paginator.paginate = MagicMock(return_value=async_iterator)
        mock_s3_client.get_paginator = MagicMock(return_value=mock_paginator)

        async with mock_minio_client:
            objects = await mock_minio_client.list_objects("test-bucket")

        # Should stop at MAX_LIST_OBJECTS_COUNT (10000)
        assert len(objects) == MAX_LIST_OBJECTS_COUNT
        assert objects[0] == "obj0"
        assert objects[-1] == f"obj{MAX_LIST_OBJECTS_COUNT - 1}"

    @pytest.mark.asyncio
    async def test_list_objects_list_all_ignores_limit(
        self, mock_minio_client, mock_s3_client
    ):
        """Test that list_all=True bypasses the limit."""
        # Create pages that exceed the limit
        page1_objects = [{"Key": f"obj{i}"} for i in range(8000)]
        page2_objects = [{"Key": f"obj{i}"} for i in range(8000, 15000)]

        mock_paginator = MagicMock()
        async_iterator = AsyncIteratorMock(
            [{"Contents": page1_objects}, {"Contents": page2_objects}]
        )
        mock_paginator.paginate = MagicMock(return_value=async_iterator)
        mock_s3_client.get_paginator = MagicMock(return_value=mock_paginator)

        async with mock_minio_client:
            objects = await mock_minio_client.list_objects("test-bucket", list_all=True)

        # Should get all 15000 objects
        assert len(objects) == 15000
        assert objects[0] == "obj0"
        assert objects[-1] == "obj14999"

    @pytest.mark.asyncio
    async def test_list_objects_error(self, mock_minio_client, mock_s3_client):
        """Test listing objects with error."""
        mock_s3_client.get_paginator = MagicMock(
            side_effect=Exception("Pagination failed")
        )

        async with mock_minio_client:
            with pytest.raises(BucketOperationError, match="Object listing failed"):
                await mock_minio_client.list_objects("test-bucket")
