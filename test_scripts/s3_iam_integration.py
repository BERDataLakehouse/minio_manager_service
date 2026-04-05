"""
Integration smoke-test for S3IAMClient against a live S3-compatible IAM endpoint.
Run with: PYTHONPATH=. uv run python test_scripts/s3_iam_integration.py
"""

import asyncio
import sys
import traceback
from contextlib import asynccontextmanager

import aiobotocore.session
from botocore.exceptions import ClientError

from src.s3.core.s3_iam_client import S3IAMClient

ENDPOINT = "http://localhost:9050"
ACCESS_KEY = "test_access_key"
SECRET_KEY = "test_access_secret"
PATH_PREFIX = "/mms-test/"
USERNAME = "inttest-alice"
ROTATION_USERNAME = "inttest-keyrotation"
GROUP = "inttest-researchers"
POLICY_NAME_USER = "home"
POLICY_NAME_GROUP = "group"
# Set above the Ceph server key limit (4) so that rotate_access_key is forced to
# handle a LimitExceeded response from the server during the rotation test.
ROTATION_MAX_KEYS = 5
SAMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::test-bucket/*"],
        }
    ],
}

# Second user/group used to verify that inline policy names are scoped per entity
SCOPING_USER = "inttest-bob"
SCOPING_GROUP = "inttest-admins"
POLICY_A = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::bucket-a/*"],
        }
    ],
}
POLICY_B = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::bucket-b/*"],
        }
    ],
}

# Policy enforcement test — a fresh user with credentials scoped to one path
ENFORCEMENT_USER = "inttest-enforced"
ENFORCEMENT_BUCKET = "inttest-bucket"
ENFORCEMENT_ALLOWED_PREFIX = "allowed-path"
ENFORCEMENT_DENIED_PREFIX = "denied-path"
ENFORCEMENT_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetBucketLocation"],
            "Resource": [f"arn:aws:s3:::{ENFORCEMENT_BUCKET}"],
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": [
                f"arn:aws:s3:::{ENFORCEMENT_BUCKET}/{ENFORCEMENT_ALLOWED_PREFIX}/*"
            ],
        },
    ],
}

passed = []
failed = []


def ok(name):
    print(f"  PASS  {name}")
    passed.append(name)


def fail(name, exc):
    print(f"  FAIL  {name}: {exc}")
    failed.append(name)
    traceback.print_exc()


@asynccontextmanager
async def s3_client_for(endpoint: str, access_key: str, secret_key: str):
    """Raw aiobotocore S3 client for the given credentials."""
    session = aiobotocore.session.get_session()
    async with session.create_client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        use_ssl=False,
    ) as s3:
        yield s3


async def run(client: S3IAMClient):
    # ── Startup validation ────────────────────────────────────────────────────
    # Already validated by create() — if we got here, connectivity is good.
    ok("create() validates connectivity and credentials")

    # ── Users ─────────────────────────────────────────────────────────────────
    try:
        await client.create_user(USERNAME)
        ok("create_user")
    except Exception as e:
        fail("create_user", e)

    try:
        await client.create_user(USERNAME, exists_ok=True)
        ok("create_user exists_ok=True silently succeeds")
    except Exception as e:
        fail("create_user exists_ok=True silently succeeds", e)

    try:
        await client.create_user(USERNAME, exists_ok=False)
        fail("create_user exists_ok=False raises on duplicate", "no exception raised")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            ok("create_user exists_ok=False raises on duplicate")
        else:
            fail("create_user exists_ok=False raises on duplicate", e)
    except Exception as e:
        fail("create_user exists_ok=False raises on duplicate", e)

    try:
        exists = await client.user_exists(USERNAME)
        assert exists, "user_exists should be True"
        ok("user_exists True")
    except Exception as e:
        fail("user_exists True", e)

    try:
        exists = await client.user_exists("inttest-nobody")
        assert not exists, "user_exists should be False for unknown user"
        ok("user_exists False")
    except Exception as e:
        fail("user_exists False", e)

    try:
        users = await client.list_users()
        assert USERNAME in users, f"{USERNAME} not in {users}"
        ok("list_users")
    except Exception as e:
        fail("list_users", e)

    # ── User policies ─────────────────────────────────────────────────────────
    try:
        result = await client.get_user_policy(
            USERNAME, POLICY_NAME_USER, except_if_absent=False
        )
        assert result is None, f"expected None, got {result}"
        ok("get_user_policy except_if_absent=False returns None when absent")
    except Exception as e:
        fail("get_user_policy except_if_absent=False returns None when absent", e)

    try:
        await client.get_user_policy(USERNAME, POLICY_NAME_USER, except_if_absent=True)
        fail(
            "get_user_policy except_if_absent=True raises when absent",
            "no exception raised",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            ok("get_user_policy except_if_absent=True raises when absent")
        else:
            fail("get_user_policy except_if_absent=True raises when absent", e)
    except Exception as e:
        fail("get_user_policy except_if_absent=True raises when absent", e)

    try:
        await client.set_user_policy(USERNAME, POLICY_NAME_USER, SAMPLE_POLICY)
        ok("set_user_policy")
    except Exception as e:
        fail("set_user_policy", e)

    try:
        doc = await client.get_user_policy(USERNAME, POLICY_NAME_USER)
        assert doc == SAMPLE_POLICY, f"policy mismatch: {doc}"
        ok("get_user_policy roundtrip")
    except Exception as e:
        fail("get_user_policy roundtrip", e)

    # ── Access key rotation ───────────────────────────────────────────────────
    try:
        key_id, secret = await client.rotate_access_key(USERNAME)
        assert key_id and secret
        ok("rotate_access_key (first key)")
    except Exception as e:
        fail("rotate_access_key (first key)", e)

    try:
        key_id2, _ = await client.rotate_access_key(USERNAME)
        assert key_id2 != key_id, "expected a different key ID"
        ok("rotate_access_key (rotation produces new key)")
    except Exception as e:
        fail("rotate_access_key (rotation produces new key)", e)

    # ── Groups ────────────────────────────────────────────────────────────────
    try:
        await client.create_group(GROUP)
        ok("create_group")
    except Exception as e:
        fail("create_group", e)

    try:
        await client.create_group(GROUP, exists_ok=True)
        ok("create_group exists_ok=True silently succeeds")
    except Exception as e:
        fail("create_group exists_ok=True silently succeeds", e)

    try:
        await client.create_group(GROUP, exists_ok=False)
        fail("create_group exists_ok=False raises on duplicate", "no exception raised")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            ok("create_group exists_ok=False raises on duplicate")
        else:
            fail("create_group exists_ok=False raises on duplicate", e)
    except Exception as e:
        fail("create_group exists_ok=False raises on duplicate", e)

    try:
        exists = await client.group_exists(GROUP)
        assert exists
        ok("group_exists True")
    except Exception as e:
        fail("group_exists True", e)

    try:
        exists = await client.group_exists("inttest-nobody")
        assert not exists
        ok("group_exists False")
    except Exception as e:
        fail("group_exists False", e)

    try:
        groups = await client.list_groups()
        assert GROUP in groups, f"{GROUP} not in {groups}"
        ok("list_groups")
    except Exception as e:
        fail("list_groups", e)

    # ── Group membership ──────────────────────────────────────────────────────
    try:
        await client.add_user_to_group(USERNAME, GROUP)
        ok("add_user_to_group")
    except Exception as e:
        fail("add_user_to_group", e)

    try:
        members = await client.list_users_in_group(GROUP)
        assert USERNAME in members, f"{USERNAME} not in {members}"
        ok("list_users_in_group")
    except Exception as e:
        fail("list_users_in_group", e)

    try:
        user_groups = await client.list_groups_for_user(USERNAME)
        assert GROUP in user_groups, f"{GROUP} not in {user_groups}"
        ok("list_groups_for_user")
    except Exception as e:
        fail("list_groups_for_user", e)

    # ── Group policies ────────────────────────────────────────────────────────
    try:
        result = await client.get_group_policy(
            GROUP, POLICY_NAME_GROUP, except_if_absent=False
        )
        assert result is None
        ok("get_group_policy except_if_absent=False returns None when absent")
    except Exception as e:
        fail("get_group_policy except_if_absent=False returns None when absent", e)

    try:
        await client.get_group_policy(GROUP, POLICY_NAME_GROUP, except_if_absent=True)
        fail(
            "get_group_policy except_if_absent=True raises when absent",
            "no exception raised",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            ok("get_group_policy except_if_absent=True raises when absent")
        else:
            fail("get_group_policy except_if_absent=True raises when absent", e)
    except Exception as e:
        fail("get_group_policy except_if_absent=True raises when absent", e)

    try:
        await client.set_group_policy(GROUP, POLICY_NAME_GROUP, SAMPLE_POLICY)
        ok("set_group_policy")
    except Exception as e:
        fail("set_group_policy", e)

    try:
        doc = await client.get_group_policy(GROUP, POLICY_NAME_GROUP)
        assert doc == SAMPLE_POLICY, f"policy mismatch: {doc}"
        ok("get_group_policy roundtrip")
    except Exception as e:
        fail("get_group_policy roundtrip", e)

    # ── Policy name scoping ───────────────────────────────────────────────────
    # Verify that an inline policy name (e.g. "home") is scoped to its owner —
    # setting it on user/group A must not affect the same-named policy on B.
    try:
        await client.create_user(SCOPING_USER)
        await client.create_group(SCOPING_GROUP)

        # Two policies on the first user/group, same two names on the second
        await client.set_user_policy(USERNAME, "home", POLICY_A)
        await client.set_user_policy(USERNAME, "system", POLICY_A)
        await client.set_user_policy(SCOPING_USER, "home", POLICY_B)
        await client.set_user_policy(SCOPING_USER, "system", POLICY_B)

        assert await client.get_user_policy(USERNAME, "home") == POLICY_A
        assert await client.get_user_policy(USERNAME, "system") == POLICY_A
        assert await client.get_user_policy(SCOPING_USER, "home") == POLICY_B
        assert await client.get_user_policy(SCOPING_USER, "system") == POLICY_B
        ok("policy scoping: same policy names on different users are independent")
    except Exception as e:
        fail("policy scoping: same policy names on different users are independent", e)

    try:
        await client.set_group_policy(GROUP, "group", POLICY_A)
        await client.set_group_policy(GROUP, "extra", POLICY_A)
        await client.set_group_policy(SCOPING_GROUP, "group", POLICY_B)
        await client.set_group_policy(SCOPING_GROUP, "extra", POLICY_B)

        assert await client.get_group_policy(GROUP, "group") == POLICY_A
        assert await client.get_group_policy(GROUP, "extra") == POLICY_A
        assert await client.get_group_policy(SCOPING_GROUP, "group") == POLICY_B
        assert await client.get_group_policy(SCOPING_GROUP, "extra") == POLICY_B
        ok("policy scoping: same policy names on different groups are independent")
    except Exception as e:
        fail("policy scoping: same policy names on different groups are independent", e)

    try:
        await client.delete_user(SCOPING_USER)
        await client.delete_group(SCOPING_GROUP)
        ok("policy scoping: cleanup")
    except Exception as e:
        fail("policy scoping: cleanup", e)

    # ── Policy enforcement (S3 data plane) ───────────────────────────────────
    # Create a bucket as admin, give a fresh IAM user scoped credentials, then
    # verify the policy actually gates S3 operations on the data plane.
    try:
        async with s3_client_for(ENDPOINT, ACCESS_KEY, SECRET_KEY) as admin_s3:
            await admin_s3.create_bucket(Bucket=ENFORCEMENT_BUCKET)
            # Seed an object in the denied path so GET failures are due to
            # access control, not a missing key.
            await admin_s3.put_object(
                Bucket=ENFORCEMENT_BUCKET,
                Key=f"{ENFORCEMENT_DENIED_PREFIX}/seed.txt",
                Body=b"admin-seeded",
            )
        ok("policy enforcement: admin creates bucket and seeds denied-path object")
    except Exception as e:
        fail("policy enforcement: admin creates bucket and seeds denied-path object", e)

    key_id, secret = None, None
    try:
        await client.create_user(ENFORCEMENT_USER)
        key_id, secret = await client.rotate_access_key(ENFORCEMENT_USER)
        await client.set_user_policy(
            ENFORCEMENT_USER, POLICY_NAME_USER, ENFORCEMENT_POLICY
        )
        ok("policy enforcement: IAM user, key, and scoped policy created")
    except Exception as e:
        fail("policy enforcement: IAM user, key, and scoped policy created", e)

    if key_id and secret:
        try:
            async with s3_client_for(ENDPOINT, key_id, secret) as user_s3:
                await user_s3.put_object(
                    Bucket=ENFORCEMENT_BUCKET,
                    Key=f"{ENFORCEMENT_ALLOWED_PREFIX}/test.txt",
                    Body=b"hello",
                )
            ok("policy enforcement: PUT to allowed path succeeds")
        except Exception as e:
            fail("policy enforcement: PUT to allowed path succeeds", e)

        try:
            async with s3_client_for(ENDPOINT, key_id, secret) as user_s3:
                response = await user_s3.get_object(
                    Bucket=ENFORCEMENT_BUCKET,
                    Key=f"{ENFORCEMENT_ALLOWED_PREFIX}/test.txt",
                )
                body = await response["Body"].read()
                assert body == b"hello", f"unexpected body: {body!r}"
            ok("policy enforcement: GET from allowed path succeeds")
        except Exception as e:
            fail("policy enforcement: GET from allowed path succeeds", e)

        try:
            async with s3_client_for(ENDPOINT, key_id, secret) as user_s3:
                await user_s3.put_object(
                    Bucket=ENFORCEMENT_BUCKET,
                    Key=f"{ENFORCEMENT_DENIED_PREFIX}/test.txt",
                    Body=b"should be denied",
                )
            fail(
                "policy enforcement: PUT to denied path is rejected",
                "no exception raised",
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AccessDenied", "403"):
                ok("policy enforcement: PUT to denied path is rejected")
            else:
                fail("policy enforcement: PUT to denied path is rejected", e)
        except Exception as e:
            fail("policy enforcement: PUT to denied path is rejected", e)

        try:
            async with s3_client_for(ENDPOINT, key_id, secret) as user_s3:
                await user_s3.get_object(
                    Bucket=ENFORCEMENT_BUCKET,
                    Key=f"{ENFORCEMENT_DENIED_PREFIX}/seed.txt",
                )
            fail(
                "policy enforcement: GET from denied path is rejected",
                "no exception raised",
            )
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AccessDenied", "403"):
                ok("policy enforcement: GET from denied path is rejected")
            else:
                fail("policy enforcement: GET from denied path is rejected", e)
        except Exception as e:
            fail("policy enforcement: GET from denied path is rejected", e)

    try:
        await client.delete_user(ENFORCEMENT_USER)
        async with s3_client_for(ENDPOINT, ACCESS_KEY, SECRET_KEY) as admin_s3:
            for key in [
                f"{ENFORCEMENT_ALLOWED_PREFIX}/test.txt",
                f"{ENFORCEMENT_DENIED_PREFIX}/seed.txt",
            ]:
                try:
                    await admin_s3.delete_object(Bucket=ENFORCEMENT_BUCKET, Key=key)
                except Exception:
                    pass
            await admin_s3.delete_bucket(Bucket=ENFORCEMENT_BUCKET)
        ok("policy enforcement: cleanup")
    except Exception as e:
        fail("policy enforcement: cleanup", e)

    # ── Cleanup / deletion ────────────────────────────────────────────────────
    try:
        await client.remove_user_from_group(USERNAME, GROUP)
        members = await client.list_users_in_group(GROUP)
        assert USERNAME not in members
        ok("remove_user_from_group")
    except Exception as e:
        fail("remove_user_from_group", e)

    try:
        await client.delete_group(GROUP)
        exists = await client.group_exists(GROUP)
        assert not exists
        ok("delete_group")
    except Exception as e:
        fail("delete_group", e)

    try:
        await client.delete_user(USERNAME)
        exists = await client.user_exists(USERNAME)
        assert not exists
        ok("delete_user")
    except Exception as e:
        fail("delete_user", e)

    # ── Key rotation at server limit ─────────────────────────────────────────
    # Use max_keys > Ceph's server key limit so every rotation once the limit is
    # reached exercises the LimitExceeded → delete-oldest → retry path.
    async with S3IAMClient(
        ENDPOINT,
        ACCESS_KEY,
        SECRET_KEY,
        path_prefix=PATH_PREFIX,
        max_keys=ROTATION_MAX_KEYS,
    ) as rot_client:
        await rot_client.create_user(ROTATION_USERNAME)
        try:
            prev_key_id = None
            for _ in range(ROTATION_MAX_KEYS + 1):
                key_id, _ = await rot_client.rotate_access_key(ROTATION_USERNAME)
                assert key_id != prev_key_id, "each rotation must produce a new key ID"
                prev_key_id = key_id
            ok(
                f"rotate_access_key handles server LimitExceeded"
                f" ({ROTATION_MAX_KEYS + 1} rotations, max_keys={ROTATION_MAX_KEYS})"
            )
        except Exception as e:
            fail("rotate_access_key handles server LimitExceeded", e)
        finally:
            await rot_client.delete_user(ROTATION_USERNAME)

    # ── Bad credentials ───────────────────────────────────────────────────────
    try:
        async with S3IAMClient(ENDPOINT, ACCESS_KEY, "wrong_secret"):
            fail("create() rejects bad credentials", "no exception raised")
    except Exception:
        ok("create() rejects bad credentials")


async def main():
    print(f"\nS3 IAM integration test — {ENDPOINT}\n")

    # Clean up any leftover state from a previous interrupted run
    try:
        async with S3IAMClient(
            ENDPOINT, ACCESS_KEY, SECRET_KEY, path_prefix=PATH_PREFIX
        ) as client:
            if await client.user_exists(USERNAME):
                await client.delete_user(USERNAME)
            if await client.user_exists(ROTATION_USERNAME):
                await client.delete_user(ROTATION_USERNAME)
            if await client.user_exists(SCOPING_USER):
                await client.delete_user(SCOPING_USER)
            if await client.user_exists(ENFORCEMENT_USER):
                await client.delete_user(ENFORCEMENT_USER)
            if await client.group_exists(GROUP):
                await client.delete_group(GROUP)
            if await client.group_exists(SCOPING_GROUP):
                await client.delete_group(SCOPING_GROUP)
        async with s3_client_for(ENDPOINT, ACCESS_KEY, SECRET_KEY) as admin_s3:
            try:
                for key in [
                    f"{ENFORCEMENT_ALLOWED_PREFIX}/test.txt",
                    f"{ENFORCEMENT_DENIED_PREFIX}/seed.txt",
                ]:
                    await admin_s3.delete_object(Bucket=ENFORCEMENT_BUCKET, Key=key)
                await admin_s3.delete_bucket(Bucket=ENFORCEMENT_BUCKET)
            except Exception:
                pass
    except Exception:
        pass

    try:
        async with S3IAMClient(
            ENDPOINT, ACCESS_KEY, SECRET_KEY, path_prefix=PATH_PREFIX
        ) as client:
            await run(client)
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
