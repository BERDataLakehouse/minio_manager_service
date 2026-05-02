"""
Integration smoke-test for UserManager against a live S3 endpoint.
Run with: PYTHONPATH=src uv run python test_scripts/user_manager_integration.py
"""

import asyncio
import os
import sys
import traceback

from s3.core.distributed_lock import DistributedLockManager
from s3.core.s3_client import S3Client
from s3.core.s3_iam_client import S3IAMClient
from s3.managers.group_manager import GroupManager
from s3.managers.policy_manager import PolicyManager
from s3.managers.user_manager import GLOBAL_USER_GROUP, UserManager
from s3.models.s3_config import S3Config
from service.exceptions import UserOperationError

ENDPOINT = "http://localhost:9050"
ACCESS_KEY = "test_access_key"
SECRET_KEY = "test_access_secret"

PATH_PREFIX = "/mms-test/"
REDIS_URL = "redis://localhost:6389"

BUCKET = "cdm-lake-test"
USERNAME = "inttest-um-alice"
USERNAME2 = "inttest-um-bob"

passed = []
failed = []


def ok(name):
    print(f"  PASS  {name}")
    passed.append(name)


def fail(name, exc):
    print(f"  FAIL  {name}: {exc}")
    failed.append(name)
    traceback.print_exc()


def make_config() -> S3Config:
    return S3Config(
        endpoint=ENDPOINT,
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        secure=False,
        default_bucket=BUCKET,
    )


async def run(
    iam_client: S3IAMClient, um: UserManager, s3_client: S3Client, pm: PolicyManager
):
    # ── create_user ───────────────────────────────────────────────────────────
    try:
        user = await um.create_user(USERNAME)
        assert user.username == USERNAME
        assert user.access_key, "access_key must be non-empty"
        assert user.secret_key, "secret_key must be non-empty"
        assert any(f"/{USERNAME}/" in p for p in user.home_paths), (
            f"home_paths must contain a path for {USERNAME}: {user.home_paths}"
        )
        ok("create_user returns credentials and home_paths")
    except Exception as e:
        fail("create_user returns credentials and home_paths", e)

    try:
        general_objects = await s3_client.list_objects(
            BUCKET, f"users-general-warehouse/{USERNAME}/", list_all=True
        )
        object_set = set(general_objects)
        expected_keys = [
            f"users-general-warehouse/{USERNAME}/.s3keep",
            f"users-general-warehouse/{USERNAME}/data/.s3keep",
            f"users-general-warehouse/{USERNAME}/notebooks/.s3keep",
            f"users-general-warehouse/{USERNAME}/shared/.s3keep",
            f"users-general-warehouse/{USERNAME}/README.txt",
        ]
        for key in expected_keys:
            assert key in object_set, f"missing S3 key: {key}"

        sql_objects = await s3_client.list_objects(
            BUCKET, f"users-sql-warehouse/{USERNAME}/", list_all=True
        )
        assert f"users-sql-warehouse/{USERNAME}/.s3keep" in set(sql_objects), (
            f"missing sql-warehouse .s3keep; got: {sql_objects}"
        )

        readme = await s3_client.get_object(
            BUCKET, f"users-general-warehouse/{USERNAME}/README.txt"
        )
        assert USERNAME.encode() in readme, (
            f"README.txt missing username; got: {readme[:200]}"
        )
        ok("create_user creates S3 home workspace with correct keys")
    except Exception as e:
        fail("create_user creates S3 home workspace with correct keys", e)

    try:
        home_policy = await pm.get_user_home_policy(USERNAME)
        home_paths = home_policy.get_accessible_paths()
        assert any(f"users-general-warehouse/{USERNAME}/" in p for p in home_paths), (
            f"home policy missing general-warehouse path: {home_paths}"
        )
        assert any(f"users-sql-warehouse/{USERNAME}/" in p for p in home_paths), (
            f"home policy missing sql-warehouse path: {home_paths}"
        )
        ok("create_user creates home policy with correct paths")
    except Exception as e:
        fail("create_user creates home policy with correct paths", e)

    try:
        system_policy = await pm.get_user_system_policy(USERNAME)
        system_paths = system_policy.get_accessible_paths()
        assert any(f"spark-job-logs/{USERNAME}/" in p for p in system_paths), (
            f"system policy missing spark-job-logs path: {system_paths}"
        )
        assert any("cts/logs/" in p for p in system_paths), (
            f"system policy missing cts/logs path: {system_paths}"
        )
        assert any("cts/io/" in p for p in system_paths), (
            f"system policy missing cts/io path: {system_paths}"
        )
        ok("create_user creates system policy with correct paths")
    except Exception as e:
        fail("create_user creates system policy with correct paths", e)

    try:
        user_again = await um.create_user(USERNAME)
        assert user_again.username == USERNAME, (
            "idempotent create_user must return the user"
        )
        ok("create_user is idempotent")
    except Exception as e:
        fail("create_user is idempotent", e)

    try:
        groups = await iam_client.list_groups_for_user(USERNAME)
        assert GLOBAL_USER_GROUP in groups, (
            f"user must be in {GLOBAL_USER_GROUP}, got: {groups}"
        )
        ok("create_user adds user to global group")
    except Exception as e:
        fail("create_user adds user to global group", e)

    # ── get_user ──────────────────────────────────────────────────────────────
    try:
        fetched = await um.get_user(USERNAME)
        assert fetched.username == USERNAME
        assert fetched.access_key, "get_user must return a non-empty access_key"
        assert fetched.secret_key == "<redacted>", "get_user must redact secret_key"

        assert (
            f"s3a://{BUCKET}/users-general-warehouse/{USERNAME}/" in fetched.home_paths
        ), f"home_paths missing general-warehouse: {fetched.home_paths}"
        assert (
            f"s3a://{BUCKET}/users-sql-warehouse/{USERNAME}/" in fetched.home_paths
        ), f"home_paths missing sql-warehouse: {fetched.home_paths}"

        # USERNAME creates globalusers (it doesn't exist yet after cleanup), so it
        # is also added to globalusersro as the group creator.
        assert GLOBAL_USER_GROUP in fetched.groups, (
            f"groups must contain {GLOBAL_USER_GROUP}: {fetched.groups}"
        )
        assert f"{GLOBAL_USER_GROUP}ro" in fetched.groups, (
            f"groups must contain {GLOBAL_USER_GROUP}ro (creator of globalusers): {fetched.groups}"
        )

        assert len(fetched.user_policies) == 2, (
            f"expected 2 user policies (home + system), got {len(fetched.user_policies)}"
        )
        assert len(fetched.group_policies) == 2, (
            f"expected 2 group policies (globalusers + globalusersro), got {len(fetched.group_policies)}"
        )
        assert fetched.total_policies == 4, (
            "expected total_policies == 4 (home + system + globalusers + globalusersro), "
            + f"got {fetched.total_policies}"
        )

        assert any(f"/{USERNAME}/" in p for p in fetched.accessible_paths), (
            f"accessible_paths must contain a user path: {fetched.accessible_paths}"
        )
        assert fetched.accessible_paths == sorted(fetched.accessible_paths), (
            "accessible_paths must be sorted"
        )
        ok("get_user returns correct user info")
    except Exception as e:
        fail("get_user returns correct user info", e)

    try:
        try:
            await um.get_user("inttest-um-nobody")
            fail("get_user raises for missing user", "no exception raised")
        except UserOperationError as e:
            if "inttest-um-nobody" in str(e):
                ok("get_user raises for missing user")
            else:
                fail("get_user raises for missing user", e)
    except Exception as e:
        fail("get_user raises for missing user", e)

    # ── user_exists ───────────────────────────────────────────────────────────
    try:
        assert await um.user_exists(USERNAME) is True
        assert await um.user_exists("inttest-um-nobody") is False
        ok("user_exists returns correct boolean")
    except Exception as e:
        fail("user_exists returns correct boolean", e)

    # ── list_users ────────────────────────────────────────────────────────────
    try:
        await um.create_user(USERNAME2)
        users = await um.list_users()
        assert USERNAME in users, f"{USERNAME} not in {users}"
        assert USERNAME2 in users, f"{USERNAME2} not in {users}"
        ok("list_users returns both users")
    except Exception as e:
        fail("list_users returns both users", e)

    try:
        groups = await iam_client.list_groups_for_user(USERNAME2)
        assert GLOBAL_USER_GROUP in groups, (
            f"{USERNAME2} must be in {GLOBAL_USER_GROUP} (group already existed), got: {groups}"
        )
        ok("create_user adds second user to existing global group")
    except Exception as e:
        fail("create_user adds second user to existing global group", e)

    # ── get_or_rotate_user_credentials ────────────────────────────────────────
    try:
        try:
            await um.get_or_rotate_user_credentials("inttest-um-nobody")
            fail("get_or_rotate raises for missing user", "no exception raised")
        except UserOperationError as e:
            if "inttest-um-nobody" in str(e):
                ok("get_or_rotate raises for missing user")
            else:
                fail("get_or_rotate raises for missing user", e)
    except Exception as e:
        fail("get_or_rotate raises for missing user", e)

    try:
        old_key = (await um.get_user(USERNAME)).access_key
        new_key_id, new_secret = await um.get_or_rotate_user_credentials(USERNAME)
        assert new_key_id, "rotated key_id must be non-empty"
        assert new_secret, "rotated secret must be non-empty"
        # Old key should be gone, new key should be active
        active_keys = await iam_client.list_access_key_ids(USERNAME)
        assert new_key_id in active_keys, f"new key {new_key_id} not in {active_keys}"
        assert old_key not in active_keys, (
            f"old key {old_key} still active after rotation"
        )
        ok("get_or_rotate_user_credentials rotates key")
    except Exception as e:
        fail("get_or_rotate_user_credentials rotates key", e)

    # ── get_user_policies ─────────────────────────────────────────────────────
    try:
        policies = await um.get_user_policies(USERNAME)

        home_paths = policies["user_home_policy"].get_accessible_paths()
        assert any(f"users-general-warehouse/{USERNAME}/" in p for p in home_paths), (
            f"home policy missing general-warehouse path: {home_paths}"
        )
        assert any(f"users-sql-warehouse/{USERNAME}/" in p for p in home_paths), (
            f"home policy missing sql-warehouse path: {home_paths}"
        )

        system_paths = policies["user_system_policy"].get_accessible_paths()
        assert any(f"spark-job-logs/{USERNAME}/" in p for p in system_paths), (
            f"system policy missing spark-job-logs path: {system_paths}"
        )
        assert any("cts/logs/" in p for p in system_paths), (
            f"system policy missing cts/logs path: {system_paths}"
        )
        assert any("cts/io/" in p for p in system_paths), (
            f"system policy missing cts/io path: {system_paths}"
        )

        group_policies = policies["group_policies"]
        assert len(group_policies) == 2, (
            f"expected 2 group policies (globalusers + globalusersro), got {len(group_policies)}"
        )
        all_group_paths = [
            p for gp in group_policies for p in gp.get_accessible_paths()
        ]
        assert any(
            f"tenant-general-warehouse/{GLOBAL_USER_GROUP}/" in p
            for p in all_group_paths
        ), (
            f"group policies missing globalusers general-warehouse path: {all_group_paths}"
        )
        assert any(
            f"tenant-sql-warehouse/{GLOBAL_USER_GROUP}/" in p for p in all_group_paths
        ), f"group policies missing globalusers sql-warehouse path: {all_group_paths}"

        ok(
            "get_user_policies returns correctly scoped home, system, and group policies"
        )
    except Exception as e:
        fail(
            "get_user_policies returns correctly scoped home, system, and group policies",
            e,
        )

    # ── get_user_accessible_paths ─────────────────────────────────────────────
    try:
        paths = await um.get_user_accessible_paths(USERNAME)
        assert paths == sorted(paths), "accessible_paths must be sorted"

        # Home paths
        assert any(f"users-general-warehouse/{USERNAME}/" in p for p in paths), (
            f"paths missing general-warehouse home: {paths}"
        )
        assert any(f"users-sql-warehouse/{USERNAME}/" in p for p in paths), (
            f"paths missing sql-warehouse home: {paths}"
        )

        # System paths
        assert any(f"spark-job-logs/{USERNAME}/" in p for p in paths), (
            f"paths missing spark-job-logs: {paths}"
        )
        assert any("cts/logs/" in p for p in paths), f"paths missing cts/logs: {paths}"
        assert any("cts/io/" in p for p in paths), f"paths missing cts/io: {paths}"

        # Group paths (globalusers)
        assert any(
            f"tenant-general-warehouse/{GLOBAL_USER_GROUP}/" in p for p in paths
        ), f"paths missing globalusers general-warehouse: {paths}"
        assert any(f"tenant-sql-warehouse/{GLOBAL_USER_GROUP}/" in p for p in paths), (
            f"paths missing globalusers sql-warehouse: {paths}"
        )

        ok(
            "get_user_accessible_paths returns sorted paths covering home, system, and group"
        )
    except Exception as e:
        fail(
            "get_user_accessible_paths returns sorted paths covering home, system, and group",
            e,
        )

    # ── can_user_share_path ───────────────────────────────────────────────────
    try:
        general_home = f"s3a://{BUCKET}/users-general-warehouse/{USERNAME}/data/"
        sql_home = f"s3a://{BUCKET}/users-sql-warehouse/{USERNAME}/mydb/"
        outside = f"s3a://{BUCKET}/tenant-general-warehouse/researchers/"
        other_user = f"s3a://{BUCKET}/users-general-warehouse/{USERNAME2}/data/"

        assert await um.can_user_share_path(general_home, USERNAME) is True
        assert await um.can_user_share_path(sql_home, USERNAME) is True
        assert await um.can_user_share_path(outside, USERNAME) is False
        assert await um.can_user_share_path(other_user, USERNAME) is False
        ok("can_user_share_path correctly validates home path ownership")
    except Exception as e:
        fail("can_user_share_path correctly validates home path ownership", e)

    # ── delete_user ───────────────────────────────────────────────────────────
    try:
        await um.delete_user(USERNAME2)
        assert not await um.user_exists(USERNAME2), "user must not exist after deletion"
        remaining = await um.list_users()
        assert USERNAME2 not in remaining, (
            f"{USERNAME2} still in user list after deletion"
        )
        ok("delete_user removes user from IAM")
    except Exception as e:
        fail("delete_user removes user from IAM", e)

    try:
        general_objects = await s3_client.list_objects(
            BUCKET, f"users-general-warehouse/{USERNAME2}/", list_all=True
        )
        assert general_objects == [], (
            f"general-warehouse keys not deleted for {USERNAME2}: {general_objects}"
        )
        sql_objects = await s3_client.list_objects(
            BUCKET, f"users-sql-warehouse/{USERNAME2}/", list_all=True
        )
        assert sql_objects == [], (
            f"sql-warehouse keys not deleted for {USERNAME2}: {sql_objects}"
        )
        spark_objects = await s3_client.list_objects(
            "cdm-spark-job-logs", f"spark-job-logs/{USERNAME2}/", list_all=True
        )
        assert spark_objects == [], (
            f"spark-job-logs keys not deleted for {USERNAME2}: {spark_objects}"
        )
        ok("delete_user removes S3 home and system workspace keys")
    except Exception as e:
        fail("delete_user removes S3 home and system workspace keys", e)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    try:
        await iam_client.delete_user(USERNAME)
        for group in [GLOBAL_USER_GROUP, f"{GLOBAL_USER_GROUP}ro"]:
            if await iam_client.group_exists(group):
                await iam_client.delete_group(group)
        ok("cleanup")
    except Exception as e:
        fail("cleanup", e)


async def main():
    print(f"\nUserManager integration test — {ENDPOINT}\n")

    os.environ["REDIS_URL"] = REDIS_URL

    config = make_config()

    # Clean up any leftover state from a previous interrupted run
    try:
        async with S3IAMClient(
            ENDPOINT, ACCESS_KEY, SECRET_KEY, path_prefix=PATH_PREFIX
        ) as client:
            for username in [USERNAME, USERNAME2]:
                if await client.user_exists(username):
                    await client.delete_user(username)
            for group in [GLOBAL_USER_GROUP, f"{GLOBAL_USER_GROUP}ro"]:
                if await client.group_exists(group):
                    await client.delete_group(group)
    except Exception:
        pass

    try:
        async with S3IAMClient(
            ENDPOINT, ACCESS_KEY, SECRET_KEY, path_prefix=PATH_PREFIX
        ) as iam_client:
            s3_client = await S3Client.create(config)
            lock_manager = DistributedLockManager()
            pm = PolicyManager(iam_client, config, lock_manager)
            gm = GroupManager(
                iam_client=iam_client,
                s3_client=s3_client,
                policy_manager=pm,
                config=config,
            )
            um = UserManager(
                iam_client=iam_client,
                s3_client=s3_client,
                policy_manager=pm,
                group_manager=gm,
                config=config,
            )

            await run(iam_client, um, s3_client, pm)

            await lock_manager.redis.aclose()
            await s3_client.close_session()

    except Exception as e:
        print(f"\nFATAL: {e}")
        traceback.print_exc()
        sys.exit(1)

    print(f"\n{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("Failed tests:")
        for name in failed:
            print(f"  - {name}")
        sys.exit(1)


asyncio.run(main())
