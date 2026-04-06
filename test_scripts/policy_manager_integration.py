"""
Integration smoke-test for PolicyManager against a live S3 endpoint.
Run with: PYTHONPATH=. uv run python test_scripts/policy_manager_integration.py
"""

import asyncio
import os
import sys
import traceback

from s3.core.distributed_lock import DistributedLockManager
from s3.core.s3_iam_client import S3IAMClient
from s3.managers.policy_manager import PolicyManager
from s3.models.policy import PolicyAction, PolicyPermissionLevel, PolicyTarget
from s3.models.s3_config import S3Config
from service.exceptions import PolicyOperationError

ENDPOINT = "http://localhost:9050"
ACCESS_KEY = "test_access_key"
SECRET_KEY = "test_access_secret"
PATH_PREFIX = "/mms-test/"
REDIS_URL = "redis://localhost:6389"

USERNAME = "inttest-pm-alice"
GROUP = "inttestpmresearchers"
GROUP_RO = "inttestpmresearchersro"

BUCKET = "cdm-lake-test"
SHARE_PATH = f"s3a://{BUCKET}/users-general-warehouse/{USERNAME}/shared/dataset/"
# S3 paths the group policy is expected to grant access to
GROUP_S3_PATH = f"s3a://{BUCKET}/tenant-general-warehouse/{GROUP}/"

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


def stmt_applies(stmts, actions, arn_marker):
    """True if any single statement applies one of `actions` to an ARN
    containing `arn_marker` — checks action and path together."""
    for s in stmts:
        if s.action not in actions:
            continue
        rs = s.resource if isinstance(s.resource, list) else [s.resource]
        if any(arn_marker in r for r in rs):
            return True
    return False


async def run(client: S3IAMClient, pm: PolicyManager):
    # ── ensure_user_policies ──────────────────────────────────────────────────
    try:
        home, system = await pm.ensure_user_policies(USERNAME)
        assert home.policy_name is None
        assert system.policy_name is None
        assert len(home.policy_document.statement) > 0
        assert len(system.policy_document.statement) > 0
        ok("ensure_user_policies creates home and system")
    except Exception as e:
        fail("ensure_user_policies creates home and system", e)

    try:
        # Alter both policies directly so ensure_* must return what's
        # there for each, not re-create them.
        altered_home = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::altered-home/*",
                }
            ],
        }
        altered_system = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::altered-system/*",
                }
            ],
        }
        await client.set_user_policy(USERNAME, "home", altered_home)
        await client.set_user_policy(USERNAME, "system", altered_system)
        home2, system2 = await pm.ensure_user_policies(USERNAME)
        assert home2.policy_name is None
        assert system2.policy_name is None
        assert home2.policy_document.to_dict() == altered_home, (
            f"ensure_user_policies must return existing home policy unchanged, "
            f"got: {home2.policy_document.to_dict()}"
        )
        assert system2.policy_document.to_dict() == altered_system, (
            f"ensure_user_policies must return existing system policy unchanged, "
            f"got: {system2.policy_document.to_dict()}"
        )
        ok("ensure_user_policies idempotent (preserves altered existing policy)")
    except Exception as e:
        fail("ensure_user_policies idempotent (preserves altered existing policy)", e)

    # ── get_user_home_policy / get_user_system_policy ─────────────────────────
    try:
        fetched = await pm.get_user_home_policy(USERNAME)
        assert fetched.policy_name is None
        assert fetched.policy_document.statement == home2.policy_document.statement
        ok("get_user_home_policy roundtrip")
    except Exception as e:
        fail("get_user_home_policy roundtrip", e)

    try:
        fetched = await pm.get_user_system_policy(USERNAME)
        assert fetched.policy_name is None
        assert fetched.policy_document.statement == system2.policy_document.statement
        ok("get_user_system_policy roundtrip")
    except Exception as e:
        fail("get_user_system_policy roundtrip", e)

    try:
        await pm.get_user_home_policy("inttest-pm-nobody")
        fail("get_user_home_policy raises for missing user", "no exception raised")
    except PolicyOperationError as e:
        if "inttest-pm-nobody" in str(e):
            ok("get_user_home_policy raises for missing user")
        else:
            fail("get_user_home_policy raises for missing user", e)
    except Exception as e:
        fail("get_user_home_policy raises for missing user", e)

    # ── regenerate_user_home_policy ───────────────────────────────────────────
    try:
        regenerated = await pm.regenerate_user_home_policy(USERNAME)
        assert regenerated.policy_name is None
        assert (
            regenerated.policy_document.statement == home.policy_document.statement
        ), "regenerated policy must match the original default"
        # Verify persisted by fetching again
        refetched = await pm.get_user_home_policy(USERNAME)
        assert (
            refetched.policy_document.statement == regenerated.policy_document.statement
        )
        ok("regenerate_user_home_policy overwrites and persists")
    except Exception as e:
        fail("regenerate_user_home_policy overwrites and persists", e)

    # ── ensure_group_policy ───────────────────────────────────────────────────
    write_actions = {PolicyAction.PUT_OBJECT, PolicyAction.DELETE_OBJECT}

    # arn_marker for GROUP that won't match GROUP_RO (which ends with "ro/*")
    group_arn = f"/{GROUP}/*"
    group_ro_arn = f"/{GROUP_RO}/*"

    try:
        group_policy = await pm.ensure_group_policy(GROUP)
        assert group_policy.policy_name is None
        stmts = group_policy.policy_document.statement
        assert stmt_applies(stmts, write_actions, group_arn), (
            "group policy should grant write access to group path"
        )
        ok("ensure_group_policy creates policy")
    except Exception as e:
        fail("ensure_group_policy creates policy", e)

    try:
        # Alter the group policy directly so ensure_* must return what's
        # there, not re-create it.
        altered = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::altered-bucket/*",
                }
            ],
        }
        await client.set_group_policy(GROUP, "group", altered)
        group_policy2 = await pm.ensure_group_policy(GROUP)
        assert group_policy2.policy_name is None
        assert group_policy2.policy_document.to_dict() == altered, (
            f"ensure_group_policy must return the existing policy unchanged, "
            f"got: {group_policy2.policy_document.to_dict()}"
        )
        ok("ensure_group_policy idempotent (preserves altered existing policy)")
    except Exception as e:
        fail("ensure_group_policy idempotent (preserves altered existing policy)", e)

    try:
        # GROUP_RO has no policy yet — tests both read_only creation and
        # path_target (the realistic RO shadow-group scenario).
        ro_with_target = await pm.ensure_group_policy(
            GROUP_RO, read_only=True, path_target=GROUP
        )
        assert ro_with_target.policy_name is None
        stmts = ro_with_target.policy_document.statement
        assert stmt_applies(stmts, {PolicyAction.GET_OBJECT}, group_arn), (
            "path_target policy should grant read access to GROUP path"
        )
        assert not stmt_applies(stmts, write_actions, group_arn), (
            "path_target policy must not grant write access to GROUP path"
        )
        assert not stmt_applies(stmts, {PolicyAction.GET_OBJECT}, group_ro_arn), (
            "path_target policy must not grant read access to GROUP_RO paths"
        )
        ok("ensure_group_policy read_only with path_target")
    except Exception as e:
        fail("ensure_group_policy read_only with path_target", e)

    # ── get_group_policy ──────────────────────────────────────────────────────
    try:
        fetched = await pm.get_group_policy(GROUP)
        assert fetched.policy_name is None
        assert (
            fetched.policy_document.statement == group_policy2.policy_document.statement
        ), "get_group_policy must return the current (altered) policy"
        ok("get_group_policy roundtrip")
    except Exception as e:
        fail("get_group_policy roundtrip", e)

    try:
        await pm.get_group_policy("inttest-pm-nobody")
        fail("get_group_policy raises for missing group", "no exception raised")
    except PolicyOperationError as e:
        if "inttest-pm-nobody" in str(e):
            ok("get_group_policy raises for missing group")
        else:
            fail("get_group_policy raises for missing group", e)
    except Exception as e:
        fail("get_group_policy raises for missing group", e)

    # ── regenerate_group_home_policy ──────────────────────────────────────────
    try:
        regen = await pm.regenerate_group_home_policy(GROUP)
        assert regen.policy_name is None
        assert (
            regen.policy_document.statement == group_policy.policy_document.statement
        ), "regenerated policy must match the original default"
        stmts = regen.policy_document.statement
        assert stmt_applies(stmts, write_actions, group_arn), (
            "regenerated group policy should grant write access to group path"
        )
        refetched = await pm.get_group_policy(GROUP)
        assert refetched.policy_document.statement == regen.policy_document.statement
        ok("regenerate_group_home_policy overwrites and persists")
    except Exception as e:
        fail("regenerate_group_home_policy overwrites and persists", e)

    try:
        regen_ro = await pm.regenerate_group_home_policy(GROUP, read_only=True)
        assert regen_ro.policy_name is None
        stmts = regen_ro.policy_document.statement
        assert stmt_applies(stmts, {PolicyAction.GET_OBJECT}, group_arn), (
            "read-only regenerated policy should grant read to group path"
        )
        assert not stmt_applies(stmts, write_actions, group_arn), (
            "read-only regenerated policy must not grant write to group path"
        )
        ok("regenerate_group_home_policy read_only=True")
    except Exception as e:
        fail("regenerate_group_home_policy read_only=True", e)

    try:
        # Alter GROUP_RO's policy to something different so regenerate must overwrite it
        await client.set_group_policy(
            GROUP_RO,
            "group",
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::altered-bucket/*",
                    }
                ],
            },
        )
        mod = await pm.get_group_policy(GROUP_RO)
        assert mod != ro_with_target
        regen_target = await pm.regenerate_group_home_policy(
            GROUP_RO, read_only=True, path_target=GROUP
        )
        assert regen_target == ro_with_target
        assert regen_target.policy_name is None
        stmts = regen_target.policy_document.statement
        assert stmt_applies(stmts, {PolicyAction.GET_OBJECT}, group_arn), (
            "path_target policy should grant read access to GROUP path"
        )
        assert not stmt_applies(stmts, write_actions, group_arn), (
            "path_target policy must not grant write access to GROUP path"
        )
        assert not stmt_applies(stmts, {PolicyAction.GET_OBJECT}, group_ro_arn), (
            "path_target policy must not grant read access to GROUP_RO paths"
        )
        refetched = await pm.get_group_policy(GROUP_RO)
        assert (
            refetched.policy_document.statement
            == regen_target.policy_document.statement
        ), "regenerated read_only path_target policy must be persisted"
        ok("regenerate_group_home_policy read_only with path_target")
    except Exception as e:
        fail("regenerate_group_home_policy read_only with path_target", e)

    # ── Locked read-modify-write ──────────────────────────────────────────────
    share_arn_marker = "shared/dataset"
    try:
        await pm.add_path_access_for_target(
            PolicyTarget.USER, USERNAME, SHARE_PATH, PolicyPermissionLevel.READ
        )
        updated = await pm.get_user_home_policy(USERNAME)
        stmts = updated.policy_document.statement
        paths = updated.get_accessible_paths()
        assert SHARE_PATH in paths, f"{SHARE_PATH} not in {paths}"
        assert stmt_applies(stmts, {PolicyAction.GET_OBJECT}, share_arn_marker), (
            "READ grant must include GET_OBJECT on shared path"
        )
        assert not stmt_applies(stmts, write_actions, share_arn_marker), (
            "READ grant must not include write actions on shared path"
        )
        ok("add_path_access_for_target user (under lock)")
    except Exception as e:
        fail("add_path_access_for_target user (under lock)", e)

    try:
        await pm.remove_path_access_for_target(PolicyTarget.USER, USERNAME, SHARE_PATH)
        updated = await pm.get_user_home_policy(USERNAME)
        paths = updated.get_accessible_paths()
        assert SHARE_PATH not in paths, f"{SHARE_PATH} still in {paths}"
        ok("remove_path_access_for_target user (under lock)")
    except Exception as e:
        fail("remove_path_access_for_target user (under lock)", e)

    try:
        await pm.add_path_access_for_target(
            PolicyTarget.GROUP, GROUP, SHARE_PATH, PolicyPermissionLevel.WRITE
        )
        updated = await pm.get_group_policy(GROUP)
        stmts = updated.policy_document.statement
        paths = updated.get_accessible_paths()
        assert SHARE_PATH in paths, f"{SHARE_PATH} not in {paths}"
        assert stmt_applies(stmts, {PolicyAction.GET_OBJECT}, share_arn_marker), (
            "WRITE grant must include GET_OBJECT on shared path"
        )
        assert stmt_applies(stmts, {PolicyAction.PUT_OBJECT}, share_arn_marker), (
            "WRITE grant must include PUT_OBJECT on shared path"
        )
        ok("add_path_access_for_target group (under lock)")
    except Exception as e:
        fail("add_path_access_for_target group (under lock)", e)

    try:
        await pm.remove_path_access_for_target(PolicyTarget.GROUP, GROUP, SHARE_PATH)
        updated = await pm.get_group_policy(GROUP)
        paths = updated.get_accessible_paths()
        assert SHARE_PATH not in paths, f"{SHARE_PATH} still in {paths}"
        ok("remove_path_access_for_target group (under lock)")
    except Exception as e:
        fail("remove_path_access_for_target group (under lock)", e)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    try:
        await client.delete_group(GROUP)
        await client.delete_group(GROUP_RO)
        await client.delete_user(USERNAME)
        ok("cleanup")
    except Exception as e:
        fail("cleanup", e)


async def main():
    print(f"\nPolicyManager integration test — {ENDPOINT}\n")

    os.environ["REDIS_URL"] = REDIS_URL

    config = make_config()

    # Clean up any leftover state from a previous interrupted run
    try:
        async with S3IAMClient(
            ENDPOINT, ACCESS_KEY, SECRET_KEY, path_prefix=PATH_PREFIX
        ) as client:
            if await client.user_exists(USERNAME):
                await client.delete_user(USERNAME)
            if await client.group_exists(GROUP):
                await client.delete_group(GROUP)
            if await client.group_exists(GROUP_RO):
                await client.delete_group(GROUP_RO)
    except Exception:
        pass

    try:
        async with S3IAMClient(
            ENDPOINT, ACCESS_KEY, SECRET_KEY, path_prefix=PATH_PREFIX
        ) as client:
            await client.create_user(USERNAME)
            await client.create_group(GROUP)
            await client.create_group(GROUP_RO)

            lock_manager = DistributedLockManager()
            pm = PolicyManager(client, config, lock_manager)

            await run(client, pm)

            await lock_manager.redis.aclose()

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
