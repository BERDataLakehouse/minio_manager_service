"""
MinIO client utilities for functional access testing.

Provides helpers to perform direct file operations against MinIO
using user credentials to verify that sharing actually works.
"""

import os
from typing import Optional

import boto3
from botocore.exceptions import ClientError


# Default configuration
DEFAULT_MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://localhost:9012")
DEFAULT_BUCKET = "cdm-lake"


def get_s3_client(
    access_key: str,
    secret_key: str,
    endpoint: str = DEFAULT_MINIO_ENDPOINT,
) -> boto3.client:
    """
    Create an S3 client configured for MinIO.

    Args:
        access_key: MinIO access key
        secret_key: MinIO secret key
        endpoint: MinIO endpoint URL

    Returns:
        boto3.client: Configured S3 client
    """
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
    )


def upload_test_file(
    bucket: str,
    key: str,
    content: str = "test data",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    endpoint: str = DEFAULT_MINIO_ENDPOINT,
) -> bool:
    """
    Upload a test file to MinIO.

    Uses root credentials if no access_key/secret_key provided.

    Args:
        bucket: Bucket name
        key: Object key (path)
        content: File content
        access_key: Optional access key (defaults to root)
        secret_key: Optional secret key (defaults to root)
        endpoint: MinIO endpoint

    Returns:
        bool: True if upload succeeded
    """
    if access_key is None:
        access_key = os.getenv("MINIO_ROOT_USER", "minio")
    if secret_key is None:
        secret_key = os.getenv("MINIO_ROOT_PASSWORD", "minio123")

    try:
        client = get_s3_client(access_key, secret_key, endpoint)
        client.put_object(Bucket=bucket, Key=key, Body=content.encode())
        return True
    except ClientError as e:
        print(f"Upload failed: {e}")
        return False


def read_file(
    bucket: str,
    key: str,
    access_key: str,
    secret_key: str,
    endpoint: str = DEFAULT_MINIO_ENDPOINT,
) -> Optional[str]:
    """
    Read a file from MinIO using provided credentials.

    Args:
        bucket: Bucket name
        key: Object key (path)
        access_key: MinIO access key
        secret_key: MinIO secret key
        endpoint: MinIO endpoint

    Returns:
        str: File content if readable, None if access denied
    """
    try:
        client = get_s3_client(access_key, secret_key, endpoint)
        response = client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read().decode()
    except ClientError:
        return None


def can_read_file(
    bucket: str,
    key: str,
    access_key: str,
    secret_key: str,
    endpoint: str = DEFAULT_MINIO_ENDPOINT,
) -> bool:
    """
    Check if credentials can read a specific file.

    Args:
        bucket: Bucket name
        key: Object key (path)
        access_key: MinIO access key
        secret_key: MinIO secret key
        endpoint: MinIO endpoint

    Returns:
        bool: True if file is readable with these credentials
    """
    return read_file(bucket, key, access_key, secret_key, endpoint) is not None


def can_write_file(
    bucket: str,
    key: str,
    access_key: str,
    secret_key: str,
    endpoint: str = DEFAULT_MINIO_ENDPOINT,
) -> bool:
    """
    Check if credentials can write to a specific path.

    Creates a small test file and immediately deletes it.

    Args:
        bucket: Bucket name
        key: Object key (path) - will write to {key}/.write_test
        access_key: MinIO access key
        secret_key: MinIO secret key
        endpoint: MinIO endpoint

    Returns:
        bool: True if write succeeded
    """
    test_key = f"{key.rstrip('/')}/.write_test"
    try:
        client = get_s3_client(access_key, secret_key, endpoint)
        client.put_object(Bucket=bucket, Key=test_key, Body=b"write_test")
        # Clean up test file
        client.delete_object(Bucket=bucket, Key=test_key)
        return True
    except ClientError:
        return False


def delete_file(
    bucket: str,
    key: str,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    endpoint: str = DEFAULT_MINIO_ENDPOINT,
) -> bool:
    """
    Delete a file from MinIO.

    Uses root credentials if no access_key/secret_key provided.

    Args:
        bucket: Bucket name
        key: Object key (path)
        access_key: Optional access key (defaults to root)
        secret_key: Optional secret key (defaults to root)
        endpoint: MinIO endpoint

    Returns:
        bool: True if delete succeeded
    """
    if access_key is None:
        access_key = os.getenv("MINIO_ROOT_USER", "minio")
    if secret_key is None:
        secret_key = os.getenv("MINIO_ROOT_PASSWORD", "minio123")

    try:
        client = get_s3_client(access_key, secret_key, endpoint)
        client.delete_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        print(f"Delete failed: {e}")
        return False


class MinIOFileHelper:
    """
    Helper class for file operations in tests.

    Tracks created files for automatic cleanup.
    """

    def __init__(self, endpoint: str = DEFAULT_MINIO_ENDPOINT):
        self.endpoint = endpoint
        self.created_files: list[tuple[str, str]] = []  # (bucket, key) pairs

    def create_file(
        self,
        bucket: str,
        key: str,
        content: str = "test data",
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> bool:
        """Create a file and track it for cleanup."""
        success = upload_test_file(
            bucket, key, content, access_key, secret_key, self.endpoint
        )
        if success:
            self.created_files.append((bucket, key))
        return success

    def read_as_user(
        self, bucket: str, key: str, access_key: str, secret_key: str
    ) -> Optional[str]:
        """Read a file as a specific user."""
        return read_file(bucket, key, access_key, secret_key, self.endpoint)

    def user_can_read(
        self, bucket: str, key: str, access_key: str, secret_key: str
    ) -> bool:
        """Check if user can read a file."""
        return can_read_file(bucket, key, access_key, secret_key, self.endpoint)

    def user_can_write(
        self, bucket: str, key: str, access_key: str, secret_key: str
    ) -> bool:
        """Check if user can write to a path."""
        return can_write_file(bucket, key, access_key, secret_key, self.endpoint)

    def cleanup(self) -> None:
        """Delete all tracked files."""
        for bucket, key in self.created_files:
            delete_file(bucket, key, endpoint=self.endpoint)
        self.created_files.clear()
