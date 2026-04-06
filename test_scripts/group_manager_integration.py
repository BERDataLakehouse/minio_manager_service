"""
Integration smoke-test for GroupManager against a live S3 endpoint.
Run with: PYTHONPATH=src uv run python test_scripts/group_manager_integration.py
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
from s3.models.s3_config import S3Config

ENDPOINT = "http://localhost:9050"
ACCESS_KEY = "test_access_key"
SECRET_KEY = "test_access_secret"

PATH_PREFIX = "/mms-test/"
REDIS_URL = "redis://localhost:6389"

BUCKET = "cdm-lake-test"
CREATOR = "inttest-gm-alice"
MEMBER = "inttest-gm-bob"
GROUP = "inttestgmresearchers"

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
    iam_client: S3IAMClient, gm: GroupManager, pm: PolicyManager, s3_client: S3Client
):
    ro_group = f"{GROUP}ro"

    # ── create_group ──────────────────────────────────────────────────────────
    try:
        from service.exceptions import GroupOperationError

        try:
            await gm.create_group(GROUP, "inttest-gm-nobody")
            fail("create_group raises for missing creator", "no exception raised")
        except GroupOperationError as e:
            if "inttest-gm-nobody" in str(e):
                ok("create_group raises for missing creator")
            else:
                fail("create_group raises for missing creator", e)
    except Exception as e:
        fail("create_group raises for missing creator", e)

    try:
        main, ro = await gm.create_group(GROUP, CREATOR)
        assert main.group_name == GROUP
        assert main.members == [CREATOR]
        assert ro.group_name == ro_group
        assert ro.members == [CREATOR]
        ok("create_group returns correct GroupModels")
    except Exception as e:
        fail("create_group returns correct GroupModels", e)

    try:
        main2, _ = await gm.create_group(GROUP, CREATOR)
        assert main2.group_name == GROUP
        ok("create_group is idempotent")
    except Exception as e:
        fail("create_group is idempotent", e)

    try:
        assert await iam_client.group_exists(GROUP)
        assert await iam_client.group_exists(ro_group)
        ok("create_group creates both IAM groups")
    except Exception as e:
        fail("create_group creates both IAM groups", e)

    try:
        main_policy = await pm.get_group_policy(GROUP)
        main_paths = main_policy.get_accessible_paths()
        assert any(f"tenant-general-warehouse/{GROUP}/" in p for p in main_paths), (
            f"main policy missing general-warehouse path: {main_paths}"
        )
        assert any(f"tenant-sql-warehouse/{GROUP}/" in p for p in main_paths), (
            f"main policy missing sql-warehouse path: {main_paths}"
        )

        ro_policy = await pm.get_group_policy(ro_group)
        ro_paths = ro_policy.get_accessible_paths()
        # RO policy paths point at the main group's workspace
        assert any(f"tenant-general-warehouse/{GROUP}/" in p for p in ro_paths), (
            f"RO policy missing general-warehouse path: {ro_paths}"
        )
        assert any(f"tenant-sql-warehouse/{GROUP}/" in p for p in ro_paths), (
            f"RO policy missing sql-warehouse path: {ro_paths}"
        )
        ok("create_group creates correctly scoped policies for main and RO groups")
    except Exception as e:
        fail("create_group creates correctly scoped policies for main and RO groups", e)

    try:
        objects = await s3_client.list_objects(
            BUCKET, f"tenant-general-warehouse/{GROUP}/", list_all=True
        )
        object_set = set(objects)
        expected_keys = [
            f"tenant-general-warehouse/{GROUP}/.s3keep",
            f"tenant-general-warehouse/{GROUP}/shared/.s3keep",
            f"tenant-general-warehouse/{GROUP}/datasets/.s3keep",
            f"tenant-general-warehouse/{GROUP}/projects/.s3keep",
            f"tenant-general-warehouse/{GROUP}/README.txt",
        ]
        for key in expected_keys:
            assert key in object_set, f"missing S3 key: {key}"

        sql_objects = await s3_client.list_objects(
            BUCKET, f"tenant-sql-warehouse/{GROUP}/", list_all=True
        )
        assert f"tenant-sql-warehouse/{GROUP}/.s3keep" in set(sql_objects), (
            f"missing sql-warehouse .s3keep; got: {sql_objects}"
        )

        readme = await s3_client.get_object(
            BUCKET, f"tenant-general-warehouse/{GROUP}/README.txt"
        )
        assert GROUP.encode() in readme, (
            f"README.txt missing group name; got: {readme[:200]}"
        )
        ok("create_group creates S3 workspace with correct keys")
    except Exception as e:
        fail("create_group creates S3 workspace with correct keys", e)

    try:
        members = await iam_client.list_users_in_group(GROUP)
        assert CREATOR in members, f"creator not in {members}"
        ro_members = await iam_client.list_users_in_group(ro_group)
        assert CREATOR in ro_members, f"creator not in RO {ro_members}"
        ok("create_group adds creator to both groups")
    except Exception as e:
        fail("create_group adds creator to both groups", e)

    # ── group_exists / list_groups ────────────────────────────────────────────
    try:
        assert await gm.group_exists(GROUP) is True
        assert await gm.group_exists("inttest-gm-nobody") is False
        ok("group_exists returns correct boolean")
    except Exception as e:
        fail("group_exists returns correct boolean", e)

    try:
        groups = await gm.list_groups()
        assert GROUP in groups, f"{GROUP} not in {groups}"
        assert ro_group in groups, f"{ro_group} not in {groups}"
        ok("list_groups includes main and RO groups")
    except Exception as e:
        fail("list_groups includes main and RO groups", e)

    # ── add_user_to_group / remove_user_from_group ────────────────────────────
    try:
        try:
            await gm.add_user_to_group(MEMBER, "inttestgmnogroup")
            fail("add_user_to_group raises for missing group", "no exception raised")
        except GroupOperationError as e:
            if "inttestgmnogroup" in str(e):
                ok("add_user_to_group raises for missing group")
            else:
                fail("add_user_to_group raises for missing group", e)
    except Exception as e:
        fail("add_user_to_group raises for missing group", e)

    try:
        try:
            await gm.add_user_to_group("inttest-gm-nobody", GROUP)
            fail("add_user_to_group raises for missing user", "no exception raised")
        except GroupOperationError as e:
            if "inttest-gm-nobody" in str(e):
                ok("add_user_to_group raises for missing user")
            else:
                fail("add_user_to_group raises for missing user", e)
    except Exception as e:
        fail("add_user_to_group raises for missing user", e)

    try:
        await gm.add_user_to_group(MEMBER, GROUP)
        members = await iam_client.list_users_in_group(GROUP)
        assert MEMBER in members, f"{MEMBER} not in {members}"
        ok("add_user_to_group adds member")
    except Exception as e:
        fail("add_user_to_group adds member", e)

    try:
        try:
            await gm.remove_user_from_group(MEMBER, "inttestgmnogroup")
            fail(
                "remove_user_from_group raises for missing group", "no exception raised"
            )
        except GroupOperationError as e:
            if "inttestgmnogroup" in str(e):
                ok("remove_user_from_group raises for missing group")
            else:
                fail("remove_user_from_group raises for missing group", e)
    except Exception as e:
        fail("remove_user_from_group raises for missing group", e)

    try:
        await gm.remove_user_from_group(MEMBER, GROUP)
        members = await iam_client.list_users_in_group(GROUP)
        assert MEMBER not in members, f"{MEMBER} still in {members}"
        ok("remove_user_from_group removes member")
    except Exception as e:
        fail("remove_user_from_group removes member", e)

    # Re-add for subsequent tests
    await iam_client.add_user_to_group(MEMBER, GROUP)

    # ── get_group_members ─────────────────────────────────────────────────────
    try:
        try:
            await gm.get_group_members("inttestgmnogroup")
            fail("get_group_members raises for missing group", "no exception raised")
        except GroupOperationError as e:
            if "inttestgmnogroup" in str(e):
                ok("get_group_members raises for missing group")
            else:
                fail("get_group_members raises for missing group", e)
    except Exception as e:
        fail("get_group_members raises for missing group", e)

    try:
        members = await gm.get_group_members(GROUP)
        assert CREATOR in members, f"creator not in {members}"
        assert MEMBER in members, f"member not in {members}"
        ok("get_group_members returns all members")
    except Exception as e:
        fail("get_group_members returns all members", e)

    # ── get_group_info ────────────────────────────────────────────────────────
    try:
        info = await gm.get_group_info(GROUP)
        assert info.group_name == GROUP
        assert CREATOR in info.members
        assert MEMBER in info.members
        ok("get_group_info returns correct GroupModel")
    except Exception as e:
        fail("get_group_info returns correct GroupModel", e)

    # ── is_user_in_group ──────────────────────────────────────────────────────
    try:
        assert await gm.is_user_in_group(CREATOR, GROUP) is True
        assert await gm.is_user_in_group(MEMBER, GROUP) is True
        assert await gm.is_user_in_group("inttest-gm-nobody", GROUP) is False
        ok("is_user_in_group returns correct boolean")
    except Exception as e:
        fail("is_user_in_group returns correct boolean", e)

    # ── get_user_groups ───────────────────────────────────────────────────────
    try:
        groups = await gm.get_user_groups(CREATOR)
        assert GROUP in groups, f"{GROUP} not in {groups}"
        assert ro_group in groups, f"{ro_group} not in {groups}"
        ok("get_user_groups returns groups including main and RO")
    except Exception as e:
        fail("get_user_groups returns groups including main and RO", e)

    # ── delete_group ──────────────────────────────────────────────────────────
    try:
        await gm.delete_group(GROUP)
        assert not await iam_client.group_exists(GROUP), "main group must be gone"
        assert not await iam_client.group_exists(ro_group), "RO group must be gone"
        ok("delete_group removes main and RO IAM groups")
    except Exception as e:
        fail("delete_group removes main and RO IAM groups", e)

    try:
        general_objects = await s3_client.list_objects(
            BUCKET, f"tenant-general-warehouse/{GROUP}/", list_all=True
        )
        assert general_objects == [], (
            f"general-warehouse keys not deleted: {general_objects}"
        )
        sql_objects = await s3_client.list_objects(
            BUCKET, f"tenant-sql-warehouse/{GROUP}/", list_all=True
        )
        assert sql_objects == [], f"sql-warehouse keys not deleted: {sql_objects}"
        ok("delete_group removes S3 workspace keys")
    except Exception as e:
        fail("delete_group removes S3 workspace keys", e)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    try:
        await iam_client.delete_user(CREATOR)
        await iam_client.delete_user(MEMBER)
        ok("cleanup")
    except Exception as e:
        fail("cleanup", e)


async def main():
    print(f"\nGroupManager integration test — {ENDPOINT}\n")

    os.environ["REDIS_URL"] = REDIS_URL

    config = make_config()

    # Clean up any leftover state from a previous interrupted run
    try:
        async with S3IAMClient(
            ENDPOINT, ACCESS_KEY, SECRET_KEY, path_prefix=PATH_PREFIX
        ) as client:
            for username in [CREATOR, MEMBER]:
                if await client.user_exists(username):
                    await client.delete_user(username)
            for group_name in [GROUP, f"{GROUP}ro"]:
                if await client.group_exists(group_name):
                    await client.delete_group(group_name)
    except Exception:
        pass

    try:
        async with S3IAMClient(
            ENDPOINT, ACCESS_KEY, SECRET_KEY, path_prefix=PATH_PREFIX
        ) as iam_client:
            # Create the test users directly via IAM client (no user manager needed)
            await iam_client.create_user(CREATOR)
            await iam_client.create_user(MEMBER)

            s3_client = await S3Client.create(config)
            lock_manager = DistributedLockManager()
            pm = PolicyManager(iam_client, config, lock_manager)
            gm = GroupManager(
                iam_client=iam_client,
                s3_client=s3_client,
                policy_manager=pm,
                config=config,
            )

            await run(iam_client, gm, pm, s3_client)

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
