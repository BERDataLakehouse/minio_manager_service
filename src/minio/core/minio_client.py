import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, List

import aiobotocore.session
from botocore.exceptions import ClientError

from ...service.exceptions import BucketOperationError, ConnectionError
from ..models.minio_config import MinIOConfig

logger = logging.getLogger(__name__)

MAX_LIST_OBJECTS_COUNT = 10 * 1000  # 10k objects


class MinIOClient:
    """MinIO Client Wrapper."""

    def __init__(self, config: MinIOConfig):
        """
        Initializes the MinIOClient with server configuration.

        Args:
            config: A MinIOConfig object with connection details.
        """
        self.config = config
        self._session = None

    @classmethod
    async def create(cls, config: MinIOConfig) -> "MinIOClient":
        """
        Create and initialize a MinIOClient instance.

        Args:
            config: A MinIOConfig object with connection details.
        """
        instance = cls(config)
        await instance.initialize_session()
        return instance

    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close_session()

    async def initialize_session(self):
        """Initialize the aiobotocore session."""
        try:
            self._session = aiobotocore.session.get_session()
            logger.info("Initialized async MinIO client session")
        except Exception as e:
            logger.error(f"Failed to initialize MinIO session: {e}")
            raise ConnectionError(f"Failed to initialize session: {e}") from e

    async def close_session(self):
        """Close the session and cleanup resources."""
        if self._session:
            # aiobotocore sessions don't need explicit closing
            self._session = None
            logger.info("Closed MinIO client session")

    @asynccontextmanager
    async def _get_client(self) -> AsyncIterator[Any]:
        """Get an async S3 client with proper configuration."""
        if not self._session:
            await self.initialize_session()

        async with self._session.create_client(  # type: ignore
            "s3",
            endpoint_url=str(self.config.endpoint),
            aws_access_key_id=self.config.access_key,
            aws_secret_access_key=self.config.secret_key,
            use_ssl=self.config.secure,
        ) as client:
            yield client

    async def test_connection(self) -> bool:
        """
        Verifies the connection to the MinIO server by listing buckets.

        Returns:
            True if the connection is successful, False otherwise.
        """
        try:
            async with self._get_client() as client:
                response = await client.list_buckets()
                bucket_count = len(response.get("Buckets", []))
                logger.info(
                    f"Connection test successful. Found {bucket_count} buckets."
                )
                return True
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    async def create_bucket(self, bucket_name: str) -> None:
        """
        Creates a new bucket on the MinIO server.

        Args:
            bucket_name: The name of the bucket to create.

        Raises:
            BucketOperationError: If the bucket creation fails for any reason.
        """
        try:
            async with self._get_client() as client:
                await client.create_bucket(Bucket=bucket_name)
                logger.info(f"Created bucket: {bucket_name}")
        except Exception as e:
            logger.error(f"Unexpected error creating bucket {bucket_name}: {e}")
            raise BucketOperationError(f"Bucket creation failed: {e}") from e

    async def bucket_exists(self, bucket_name: str) -> bool:
        """
        Checks if a bucket exists by sending a HEAD request.

        NOTE: This method is designed to be used by minIO admin only where we have access to all buckets.

        Args:
            bucket_name: The name of the bucket to check.

        Returns:
            True if the bucket exists, False otherwise.

        Raises:
            BucketOperationError: If the check fails for reasons other than a 404 error.
        """
        try:
            async with self._get_client() as client:
                await client.head_bucket(Bucket=bucket_name)
                return True
        except ClientError as e:
            # Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
            if e.response["Error"]["Code"] == "404":
                return False
            else:
                logger.error(f"Error checking bucket {bucket_name}: {e}")
                raise BucketOperationError(f"Bucket check failed: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error checking bucket {bucket_name}: {e}")
            raise BucketOperationError(f"Bucket check failed: {e}") from e

    async def list_buckets(self) -> List[str]:
        """
        Retrieves a list of all bucket names from the MinIO server.

        Returns:
            A list of strings, where each string is a bucket name.

        Raises:
            BucketOperationError: If listing buckets fails.
        """
        try:
            async with self._get_client() as client:
                response = await client.list_buckets()
                buckets = [bucket["Name"] for bucket in response.get("Buckets", [])]
                logger.info(f"Listed {len(buckets)} buckets")
                return buckets
        except Exception as e:
            logger.error(f"Failed to list buckets: {e}")
            raise BucketOperationError(f"Bucket listing failed: {e}") from e

    async def delete_bucket(self, bucket_name: str) -> None:
        """
        Deletes a bucket and all objects within it.

        This operation first lists and deletes all objects in the bucket before
        deleting the bucket itself.

        Args:
            bucket_name: The name of the bucket to delete.

        Raises:
            BucketOperationError: If the bucket deletion fails.
        """
        try:
            async with self._get_client() as client:
                # Always delete all objects first
                paginator = client.get_paginator("list_objects_v2")
                async for page in paginator.paginate(Bucket=bucket_name):
                    if "Contents" in page:
                        objects = [{"Key": obj["Key"]} for obj in page["Contents"]]
                        await client.delete_objects(
                            Bucket=bucket_name, Delete={"Objects": objects}
                        )

                await client.delete_bucket(Bucket=bucket_name)
                logger.info(f"Deleted bucket: {bucket_name}")
        except Exception as e:
            logger.error(f"Failed to delete bucket {bucket_name}: {e}")
            raise BucketOperationError(f"Bucket deletion failed: {e}") from e

    async def put_object(self, bucket_name: str, key: str, body: bytes) -> None:
        """
        Uploads an object to a specified bucket.

        NOTE: This method is not designed to be used for uploading large objects.

        Args:
            bucket_name: The name of the target bucket.
            key: The object key (i.e., its name/path within the bucket).
            body: The content of the object as bytes.

        Raises:
            BucketOperationError: If the upload operation fails.
        """
        try:
            async with self._get_client() as client:
                await client.put_object(Bucket=bucket_name, Key=key, Body=body)
                logger.info(f"Put object {key} in bucket {bucket_name}")
        except Exception as e:
            logger.error(f"Failed to put object {key} in bucket {bucket_name}: {e}")
            raise BucketOperationError(f"Object put failed: {e}") from e

    async def get_object(self, bucket_name: str, key: str) -> bytes:
        """
        Retrieves an object from a bucket.
        NOTE: This method is not designed to be used for retrieving large objects.

        Args:
            bucket_name: The name of the bucket containing the object.
            key: The key of the object to retrieve.

        Returns:
            The content of the object as bytes.

        Raises:
            BucketOperationError: If the object retrieval fails.
        """
        try:
            async with self._get_client() as client:
                response = await client.get_object(Bucket=bucket_name, Key=key)
                body = await response["Body"].read()
                logger.info(f"Got object {key} from bucket {bucket_name}")
                return body
        except Exception as e:
            logger.error(f"Failed to get object {key} from bucket {bucket_name}: {e}")
            raise BucketOperationError(f"Object get failed: {e}") from e

    async def delete_object(self, bucket_name: str, key: str) -> None:
        """
        Deletes a single object from a bucket.

        Args:
            bucket_name: The name of the bucket containing the object.
            key: The key of the object to delete.

        Raises:
            BucketOperationError: If the object deletion fails.
        """
        try:
            async with self._get_client() as client:
                await client.delete_object(Bucket=bucket_name, Key=key)
                logger.info(f"Deleted object {key} from bucket {bucket_name}")
        except Exception as e:
            logger.error(
                f"Failed to delete object {key} from bucket {bucket_name}: {e}"
            )
            raise BucketOperationError(f"Object deletion failed: {e}") from e

    async def list_objects(
        self, bucket_name: str, prefix: str = "", list_all: bool = False
    ) -> List[str]:
        """
        Lists objects in a bucket, optionally filtered by a prefix.

        Args:
            bucket_name: The name of the bucket to list objects from.
            prefix: An optional prefix to filter the object keys.
            list_all: If True, lists all objects without limit. If False, stops at MAX_LIST_OBJECTS_COUNT.

        Returns:
            A list of object keys (strings). Limited to MAX_LIST_OBJECTS_COUNT items unless list_all=True.

        Raises:
            BucketOperationError: If the object listing operation fails.
        """
        try:
            async with self._get_client() as client:
                paginator = client.get_paginator("list_objects_v2")
                objects = []

                async for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
                    if "Contents" in page:
                        page_objects = [obj["Key"] for obj in page["Contents"]]

                        # Check if adding this page would exceed the limit (unless list_all=True)
                        if (
                            not list_all
                            and len(objects) + len(page_objects)
                            > MAX_LIST_OBJECTS_COUNT
                        ):
                            # Add only what we can without exceeding the limit
                            remaining_slots = MAX_LIST_OBJECTS_COUNT - len(objects)
                            objects.extend(page_objects[:remaining_slots])
                            logger.warning(
                                f"Object listing stopped at {MAX_LIST_OBJECTS_COUNT} objects limit "
                                f"for bucket {bucket_name} with prefix '{prefix}'"
                            )
                            break

                        objects.extend(page_objects)

                logger.info(
                    f"Listed {len(objects)} objects in bucket {bucket_name} with prefix '{prefix}'"
                )
                return objects
        except Exception as e:
            logger.error(f"Failed to list objects in bucket {bucket_name}: {e}")
            raise BucketOperationError(f"Object listing failed: {e}") from e
