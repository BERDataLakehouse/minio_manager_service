"""
Integration test for migrations/minio_to_s3_inline_iam.py.

Requires the docker-compose stack to be running:
    docker compose up -d minio ceph

Run with:
    MC_PATH=/path/to/mc PYTHONPATH=src uv run python \\
        test_scripts/minio_to_s3_inline_iam_integration.py

The test:
  1. Creates two users and one group in MinIO with standalone policies.
  2. Runs the migration script against the local Ceph instance.
  3. Verifies users, groups, inline policies, and memberships via IAM API.
  4. Cleans up both source and target.
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import traceback

from s3.core.s3_iam_client import S3IAMClient

# ── Config ────────────────────────────────────────────────────────────────────

MC_PATH = os.environ.get("MC_PATH", "mc")

SRC_ENDPOINT = "http://localhost:9012"
SRC_ACCESS_KEY = "minio"
SRC_SECRET_KEY = "minio123"

DST_ENDPOINT = "http://localhost:9050"
DST_ACCESS_KEY = "test_access_key"
DST_SECRET_KEY = "test_access_secret"
DST_PATH_PREFIX = "/mms-inttest/"

MIGRATION_SCRIPT = "migrations/minio_to_s3_inline_iam.py"

SRC_ALIAS = "mmsinttestsrc"

# Test entities
USER_ALICE = "inttest-mig-alice"
USER_BOB = "inttest-mig-bob"
# Charlie has only a home policy — used to test the incomplete-policy error
USER_CHARLIE = "inttest-mig-charlie"
GROUP = "inttest-mig-researchers"

HOME_POLICY_ALICE = f"user-home-policy-{USER_ALICE}"
SYSTEM_POLICY_ALICE = f"user-system-policy-{USER_ALICE}"
HOME_POLICY_BOB = f"user-home-policy-{USER_BOB}"
SYSTEM_POLICY_BOB = f"user-system-policy-{USER_BOB}"
HOME_POLICY_CHARLIE = f"user-home-policy-{USER_CHARLIE}"
GROUP_POLICY = f"group-policy-{GROUP}"

ALICE_HOME_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": [f"arn:aws:s3:::cdm-lake/{USER_ALICE}/*"],
        }
    ],
}
ALICE_SYSTEM_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [f"arn:aws:s3:::cdm-logs/{USER_ALICE}/*"],
        }
    ],
}
BOB_HOME_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": [f"arn:aws:s3:::cdm-lake/{USER_BOB}/*"],
        }
    ],
}
BOB_SYSTEM_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [f"arn:aws:s3:::cdm-logs/{USER_BOB}/*"],
        }
    ],
}
GROUP_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [f"arn:aws:s3:::cdm-lake/{GROUP}/*"],
        }
    ],
}

# ── Helpers ───────────────────────────────────────────────────────────────────


def normalize_policy(doc: dict) -> dict:
    """Return a copy of a policy document with action lists sorted, so that
    action-order differences from S3 endpoints don't cause false failures."""
    stmts = []
    for stmt in doc.get("Statement", []):
        s = dict(stmt)
        if isinstance(s.get("Action"), list):
            s["Action"] = sorted(s["Action"])
        stmts.append(s)
    return {**doc, "Statement": stmts}


# ── Test result tracking ──────────────────────────────────────────────────────

passed = []
failed = []


def ok(name: str) -> None:
    print(f"  PASS  {name}")
    passed.append(name)


def fail(name: str, exc: Exception) -> None:
    print(f"  FAIL  {name}: {exc}")
    failed.append(name)
    traceback.print_exc()


# ── mc helpers ────────────────────────────────────────────────────────────────


def mc(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [MC_PATH] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"mc command failed: {' '.join(cmd)}\nstderr: {result.stderr.strip()}"
        )
    return result


def mc_setup_source() -> None:
    mc(
        "alias",
        "set",
        SRC_ALIAS,
        SRC_ENDPOINT,
        SRC_ACCESS_KEY,
        SRC_SECRET_KEY,
        "--api",
        "S3v4",
    )


def mc_create_policy(policy_name: str, doc: dict) -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(doc, f)
        tmp = f.name
    try:
        mc("admin", "policy", "create", SRC_ALIAS, policy_name, tmp)
    finally:
        os.unlink(tmp)


def mc_create_user(username: str) -> None:
    mc("admin", "user", "add", SRC_ALIAS, username, "password123!")


def mc_attach_policy_to_user(policy_name: str, username: str) -> None:
    mc("admin", "policy", "attach", SRC_ALIAS, policy_name, "--user", username)


def mc_create_group(group_name: str, members: list[str]) -> None:
    mc("admin", "group", "add", SRC_ALIAS, group_name, *members)


def mc_attach_policy_to_group(policy_name: str, group_name: str) -> None:
    mc("admin", "policy", "attach", SRC_ALIAS, policy_name, "--group", group_name)


def mc_remove_policy(policy_name: str) -> None:
    mc("admin", "policy", "remove", SRC_ALIAS, policy_name, check=False)


def mc_remove_user(username: str) -> None:
    mc("admin", "user", "remove", SRC_ALIAS, username, check=False)


def mc_remove_group(group_name: str) -> None:
    mc("admin", "group", "remove", SRC_ALIAS, group_name, check=False)


# ── Setup and teardown ────────────────────────────────────────────────────────


def setup_minio_source() -> None:
    """Populate the MinIO source with test users, groups, and standalone policies."""
    print("\nSetting up MinIO source state…")
    mc_setup_source()

    mc_create_user(USER_ALICE)
    mc_create_user(USER_BOB)

    mc_create_policy(HOME_POLICY_ALICE, ALICE_HOME_DOC)
    mc_create_policy(SYSTEM_POLICY_ALICE, ALICE_SYSTEM_DOC)
    mc_create_policy(HOME_POLICY_BOB, BOB_HOME_DOC)
    mc_create_policy(SYSTEM_POLICY_BOB, BOB_SYSTEM_DOC)
    mc_create_policy(GROUP_POLICY, GROUP_DOC)

    mc_attach_policy_to_user(HOME_POLICY_ALICE, USER_ALICE)
    mc_attach_policy_to_user(SYSTEM_POLICY_ALICE, USER_ALICE)
    mc_attach_policy_to_user(HOME_POLICY_BOB, USER_BOB)
    mc_attach_policy_to_user(SYSTEM_POLICY_BOB, USER_BOB)

    mc_create_group(GROUP, [USER_ALICE])
    mc_attach_policy_to_group(GROUP_POLICY, GROUP)

    print("  MinIO source state set up.")


def teardown_minio_source() -> None:
    """Remove test state from MinIO."""
    print("\nCleaning up MinIO source state…")
    mc_remove_group(GROUP)
    mc_remove_policy(HOME_POLICY_ALICE)
    mc_remove_policy(SYSTEM_POLICY_ALICE)
    mc_remove_policy(HOME_POLICY_BOB)
    mc_remove_policy(SYSTEM_POLICY_BOB)
    mc_remove_policy(HOME_POLICY_CHARLIE)
    mc_remove_policy(GROUP_POLICY)
    mc_remove_user(USER_ALICE)
    mc_remove_user(USER_BOB)
    mc_remove_user(USER_CHARLIE)
    print("  MinIO source state cleaned up.")


async def teardown_ceph_target(client: S3IAMClient) -> None:
    """Remove test state from Ceph."""
    print("\nCleaning up Ceph target state…")
    for username in [USER_ALICE, USER_BOB]:
        if await client.user_exists(username):
            await client.delete_user(username)
    if await client.group_exists(GROUP):
        await client.delete_group(GROUP)
    print("  Ceph target state cleaned up.")


# ── Run migration ─────────────────────────────────────────────────────────────


_BASE_MIGRATION_ARGS = [
    "--src-endpoint",
    SRC_ENDPOINT,
    "--src-access-key",
    SRC_ACCESS_KEY,
    "--src-secret-key",
    SRC_SECRET_KEY,
    "--mc-path",
    MC_PATH,
    "--dst-endpoint",
    DST_ENDPOINT,
    "--dst-access-key",
    DST_ACCESS_KEY,
    "--dst-secret-key",
    DST_SECRET_KEY,
    "--dst-path-prefix",
    DST_PATH_PREFIX,
]


def run_migration(*extra_args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Invoke the migration script as a subprocess.

    Prints stdout as it would appear to a user. If check=True (default), raises
    RuntimeError on non-zero exit so callers don't need to inspect returncode.
    Pass check=False when a non-zero exit is the expected outcome being tested.
    """
    print("\nRunning migration script…")
    result = subprocess.run(
        [sys.executable, MIGRATION_SCRIPT] + _BASE_MIGRATION_ARGS + list(extra_args),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    print(result.stdout)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Migration script exited with code {result.returncode}."
            f"\nstderr: {result.stderr.strip()}"
        )
    return result


# ── Verification ──────────────────────────────────────────────────────────────


async def verify(client: S3IAMClient) -> None:
    print("\nVerifying migration results…")

    try:
        assert await client.user_exists(USER_ALICE)
        ok("alice exists in IAM")
    except Exception as e:
        fail("alice exists in IAM", e)

    try:
        assert await client.user_exists(USER_BOB)
        ok("bob exists in IAM")
    except Exception as e:
        fail("bob exists in IAM", e)

    try:
        doc = await client.get_user_policy(USER_ALICE, "home")
        assert doc is not None, "home policy not found for alice"
        assert normalize_policy(doc) == normalize_policy(ALICE_HOME_DOC), (
            f"mismatch: {doc}"
        )
        ok("alice home inline policy correct")
    except Exception as e:
        fail("alice home inline policy correct", e)

    try:
        doc = await client.get_user_policy(USER_ALICE, "system")
        assert doc is not None, "system policy not found for alice"
        assert normalize_policy(doc) == normalize_policy(ALICE_SYSTEM_DOC), (
            f"mismatch: {doc}"
        )
        ok("alice system inline policy correct")
    except Exception as e:
        fail("alice system inline policy correct", e)

    try:
        doc = await client.get_user_policy(USER_BOB, "home")
        assert doc is not None, "home policy not found for bob"
        assert normalize_policy(doc) == normalize_policy(BOB_HOME_DOC), (
            f"mismatch: {doc}"
        )
        ok("bob home inline policy correct")
    except Exception as e:
        fail("bob home inline policy correct", e)

    try:
        doc = await client.get_user_policy(USER_BOB, "system")
        assert doc is not None, "system policy not found for bob"
        assert normalize_policy(doc) == normalize_policy(BOB_SYSTEM_DOC), (
            f"mismatch: {doc}"
        )
        ok("bob system inline policy correct")
    except Exception as e:
        fail("bob system inline policy correct", e)

    try:
        assert await client.group_exists(GROUP)
        ok("researchers group exists in IAM")
    except Exception as e:
        fail("researchers group exists in IAM", e)

    try:
        doc = await client.get_group_policy(GROUP, "group")
        assert doc is not None, "group policy not found"
        assert normalize_policy(doc) == normalize_policy(GROUP_DOC), f"mismatch: {doc}"
        ok("researchers group inline policy correct")
    except Exception as e:
        fail("researchers group inline policy correct", e)

    try:
        members = await client.list_users_in_group(GROUP)
        assert USER_ALICE in members, f"{USER_ALICE} not in {members}"
        assert USER_BOB not in members, f"{USER_BOB} should not be in {members}"
        ok("group membership: alice in researchers, bob not")
    except Exception as e:
        fail("group membership: alice in researchers, bob not", e)


async def run_and_verify(client: S3IAMClient, name: str) -> None:
    print(f"\n--- Checking {name} ---")
    try:
        run_migration()
        ok(name)
    except Exception as e:
        fail(name, e)
    await verify(client)


async def check_incomplete_policies(client: S3IAMClient) -> None:
    """Add charlie who has only a home policy, then verify the migration aborts."""
    print("\n--- Checking incomplete policy detection… ---")
    mc_create_user(USER_CHARLIE)
    mc_create_policy(HOME_POLICY_CHARLIE, BOB_HOME_DOC)
    mc_attach_policy_to_user(HOME_POLICY_CHARLIE, USER_CHARLIE)

    try:
        result = run_migration(check=False)
        assert result.returncode != 0, "expected non-zero exit for incomplete policies"
        assert USER_CHARLIE in result.stdout, (
            f"expected {USER_CHARLIE} mentioned in output:\n{result.stdout}"
        )
        assert not await client.user_exists(USER_CHARLIE), (
            "charlie should not have been created — abort must precede writes"
        )
        ok("incomplete policies cause abort before any writes")
    except Exception as e:
        fail("incomplete policies cause abort before any writes", e)
    finally:
        mc_remove_policy(HOME_POLICY_CHARLIE)
        mc_remove_user(USER_CHARLIE)


# ── Main ──────────────────────────────────────────────────────────────────────


async def main() -> None:
    print("\nMinio→S3 IAM migration integration test")
    print(f"  Source: {SRC_ENDPOINT}")
    print(f"  Target: {DST_ENDPOINT}")

    async with S3IAMClient(
        DST_ENDPOINT, DST_ACCESS_KEY, DST_SECRET_KEY, DST_PATH_PREFIX
    ) as client:
        # Pre-clean any leftover state from a previous interrupted run
        await teardown_ceph_target(client)
        teardown_minio_source()

        try:
            setup_minio_source()
            await run_and_verify(client, "initial migration succeeds")
            await run_and_verify(client, "migration re-run succeeds (idempotent)")
            await check_incomplete_policies(client)
        finally:
            teardown_minio_source()
            await teardown_ceph_target(client)

    print(f"\n{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("Failed tests:")
        for name in failed:
            print(f"  - {name}")
        sys.exit(1)


asyncio.run(main())
