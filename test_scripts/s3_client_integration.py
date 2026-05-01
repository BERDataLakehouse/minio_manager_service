"""
Integration smoke-test for S3Client against a live S3-compatible endpoint.
Run with: PYTHONPATH=src uv run python test_scripts/s3_client_integration.py
"""

# TODO: Add tests for the remaining S3Client methods as needed:
#   bucket_exists, list_buckets, delete_bucket, put_object, get_object,
#   delete_object, list_objects

import asyncio
import sys
import traceback

from s3.core.s3_client import S3Client
from s3.models.s3_config import S3Config

ENDPOINT = "http://localhost:9050"
ACCESS_KEY = "test_access_key"
SECRET_KEY = "test_access_secret"
# MinIO (useful for testing exists_ok behaviour — Ceph silently succeeds on duplicate buckets,
# at least those owned by the user):
# ENDPOINT = "http://localhost:9012"
# ACCESS_KEY = "minio"
# SECRET_KEY = "minio123"
TEST_BUCKET = "inttest-s3client-bucket"

passed = []
failed = []


def ok(name):
    print(f"  PASS  {name}")
    passed.append(name)


def fail(name, exc):
    print(f"  FAIL  {name}: {exc}")
    failed.append(name)
    traceback.print_exc()


async def run(client: S3Client):
    # ── create_bucket ─────────────────────────────────────────────────────────
    try:
        await client.create_bucket(TEST_BUCKET)
        ok("create_bucket")
    except Exception as e:
        fail("create_bucket", e)

    try:
        await client.create_bucket(TEST_BUCKET, exists_ok=True)
        ok("create_bucket exists_ok=True silently succeeds")
    except Exception as e:
        fail("create_bucket exists_ok=True silently succeeds", e)

    # Note: MinIO raises BucketAlreadyOwnedByYou on duplicate creation; Ceph
    # RadosGW silently succeeds (at least when the bucket is owned by the same
    # user), so exists_ok=False is only meaningful here against MinIO.
    try:
        await client.create_bucket(TEST_BUCKET, exists_ok=False)
        fail("create_bucket exists_ok=False raises on duplicate", "no exception raised")
    except Exception:
        ok("create_bucket exists_ok=False raises on duplicate")

    # ── Cleanup ───────────────────────────────────────────────────────────────
    try:
        await client.delete_bucket(TEST_BUCKET)
        ok("cleanup: delete_bucket")
    except Exception as e:
        fail("cleanup: delete_bucket", e)


async def main():
    print(f"\nS3 client integration test — {ENDPOINT}\n")

    config = S3Config(
        endpoint=ENDPOINT,
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        secure=False,
        default_bucket=TEST_BUCKET,
    )

    # Clean up any leftover state from a previous interrupted run
    try:
        client = await S3Client.create(config)
        if await client.bucket_exists(TEST_BUCKET):
            await client.delete_bucket(TEST_BUCKET)
        await client.close_session()
    except Exception:
        pass

    try:
        client = await S3Client.create(config)
        await run(client)
        await client.close_session()
    except Exception as e:
        print(f"\nFATAL: could not open client: {e}")
        traceback.print_exc()
        sys.exit(1)

    print(f"\n{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("Failed tests:")
        for name in failed:
            print(f"  - {name}")
        sys.exit(1)


asyncio.run(main())
