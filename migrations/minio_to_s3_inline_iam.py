"""
Migrate MinIO standalone IAM policies to S3 inline IAM policies.

MinIO stores policies as named standalone objects attached to users and groups.
The new system uses inline policies (per user/group, named "home"/"system"/"group").

This script:
  1. Reads all MMS-owned policies from a MinIO source via the mc CLI.
  2. Derives entity names from policy name prefixes.
  3. Creates the corresponding users and groups on the S3 IAM target.
  4. Sets their inline policies from the MinIO policy documents.
  5. Replicates group memberships.

The script is idempotent: re-running it will overwrite all inline policies with
their current MinIO values, so it is safe to re-run if interrupted.

Source policy prefix → entity and inline policy name:
  user-home-policy-{username}   → IAM user, inline policy "home"
  user-system-policy-{username} → IAM user, inline policy "system"
  group-policy-{groupname}      → IAM group, inline policy "group"

Every user must have both a home and a system policy. The script aborts before
making any changes if that is not the case.

Notable arguments: 

--dst-path-prefix:
    IAM path prefix applied to every created user and group (default: "/"). IAM
    paths are a metadata tag on each entity used for filtering — e.g. listing only
    MMS-managed users via PathPrefix="/mms/". They do not prevent name collisions:
    usernames must still be unique within the account regardless of path. Set this
    to match whatever prefix the MMS deployment uses so that the migrated entities
    are indistinguishable from ones the service would have created itself. The
    prefix must start and end with "/".


Usage:
    PYTHONPATH=src python migrations/minio_to_s3_inline_iam.py \
        --src-endpoint http://localhost:9012 \
        --src-access-key minio \
        --src-secret-key minio123 \
        --dst-endpoint http://localhost:9050 \
        --dst-access-key test_access_key \
        --dst-secret-key test_access_secret \
        [--mc-path /usr/local/bin/mc] \
        [--dst-path-prefix /mms/] \
        [--dry-run]
"""

import argparse
import asyncio
import json
import subprocess
import sys

from s3.core.s3_iam_client import S3IAMClient

# ── Policy name prefixes (must match the MMS naming convention) ──────────────

USER_HOME_PREFIX = "user-home-policy-"
USER_SYSTEM_PREFIX = "user-system-policy-"
GROUP_PREFIX = "group-policy-"

# Inline policy names used in the new S3 IAM model
HOME_INLINE = "home"
SYSTEM_INLINE = "system"
GROUP_INLINE = "group"

# Alias used when configuring mc for the source MinIO
_SRC_ALIAS = "mmsmigrationsrc"


# ── mc helpers (source side) ─────────────────────────────────────────────────


def _mc(mc_path: str, *args: str) -> str:
    """Run an mc command and return stdout. Raises on failure."""
    cmd = [mc_path] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"mc command failed: {' '.join(cmd)}\nstderr: {result.stderr.strip()}"
        )
    return result.stdout


def mc_setup_alias(
    mc_path: str, endpoint: str, access_key: str, secret_key: str
) -> None:
    """Register the source MinIO endpoint as an mc alias."""
    _mc(
        mc_path,
        "alias",
        "set",
        _SRC_ALIAS,
        endpoint,
        access_key,
        secret_key,
        "--api",
        "S3v4",
    )
    print(f"  mc alias set → {endpoint}")


def mc_list_policies(mc_path: str) -> list[str]:
    """Return all policy names from the source MinIO."""
    raw = _mc(mc_path, "admin", "policy", "list", _SRC_ALIAS, "--json")
    names = []
    for line in raw.strip().splitlines():
        if line.strip():
            obj = json.loads(line)
            names.append(obj["policy"])
    return names


def mc_get_policy_doc(mc_path: str, policy_name: str) -> dict:
    """Return the policy document dict for a named MinIO policy."""
    raw = _mc(mc_path, "admin", "policy", "info", _SRC_ALIAS, policy_name)
    data = json.loads(raw)
    # mc returns the document under "policyJSON" or "Policy", falling back to
    # the object itself if it IS the policy document.
    return data.get("policyJSON", data.get("Policy", data))


def mc_get_group_members(mc_path: str, group_name: str) -> list[str]:
    """Return the member list for a group from the source MinIO."""
    raw = _mc(mc_path, "admin", "group", "info", _SRC_ALIAS, group_name, "--json")
    data = json.loads(raw)
    return data.get("members", [])


# ── Migration orchestration ──────────────────────────────────────────────────


async def migrate(
    mc_path: str,
    src_endpoint: str,
    src_access_key: str,
    src_secret_key: str,
    dst_endpoint: str,
    dst_access_key: str,
    dst_secret_key: str,
    dst_path_prefix: str,
    dry_run: bool,
) -> None:
    print("\n── 1. Connecting to source MinIO via mc ─────────────────────────────")
    mc_setup_alias(mc_path, src_endpoint, src_access_key, src_secret_key)

    print("\n── 2. Reading policies from MinIO ───────────────────────────────────")
    all_policies = mc_list_policies(mc_path)
    print(f"  found {len(all_policies)} total policies")

    # Derive the set of MMS-managed entities from the policy names rather than
    # by listing users/groups directly. Listing all MinIO users/groups would
    # risk migrating non-MMS entities that happen to share the same instance into
    # the MMS specific prefix (if supplied)
    user_home_policies: dict[str, dict] = {}  # username → policy doc
    user_system_policies: dict[str, dict] = {}  # username → policy doc
    group_policies: dict[str, dict] = {}  # group_name → policy doc

    for policy_name in all_policies:
        if policy_name.startswith(USER_HOME_PREFIX):
            username = policy_name[len(USER_HOME_PREFIX) :]
            user_home_policies[username] = mc_get_policy_doc(mc_path, policy_name)
        elif policy_name.startswith(USER_SYSTEM_PREFIX):
            username = policy_name[len(USER_SYSTEM_PREFIX) :]
            user_system_policies[username] = mc_get_policy_doc(mc_path, policy_name)
        elif policy_name.startswith(GROUP_PREFIX):
            group_name = policy_name[len(GROUP_PREFIX) :]
            group_policies[group_name] = mc_get_policy_doc(mc_path, policy_name)
        else:
            print(f"  skipping non-MMS policy: {policy_name}")

    usernames = set(user_home_policies) | set(user_system_policies)
    group_names = set(group_policies)

    print(f"  MMS entities: {len(usernames)} users, {len(group_names)} groups")

    # Every user must have both policies — abort before touching the target if not
    missing_system = sorted(set(user_home_policies) - set(user_system_policies))
    missing_home = sorted(set(user_system_policies) - set(user_home_policies))
    errors = [
        f"  {u!r} has a home policy but no system policy" for u in missing_system
    ] + [f"  {u!r} has a system policy but no home policy" for u in missing_home]
    if errors:
        for e in errors:
            print(e)
        raise SystemExit(
            "Aborting: users with incomplete policies found. Fix the source data and re-run."
        )

    print("\n── 3. Reading group memberships from MinIO ──────────────────────────")
    group_members: dict[str, list[str]] = {}
    for group_name in sorted(group_names):
        members = mc_get_group_members(mc_path, group_name)
        group_members[group_name] = members
        print(f"  {group_name}: {len(members)} members")

    print("\n── 4. Migrating to target IAM endpoint ──────────────────────────────")
    if dry_run:
        print("  (dry-run: no changes will be made)")
        for username in sorted(usernames):
            print(f"  would create user {username!r} with home and system policies")
        for group_name in sorted(group_names):
            print(
                f"  would create group {group_name!r} with "
                f"{len(group_members[group_name])} members"
            )
        return

    async with S3IAMClient(
        dst_endpoint, dst_access_key, dst_secret_key, dst_path_prefix
    ) as client:
        print(f"\n  Migrating {len(usernames)} users…")
        for username in sorted(usernames):
            print(f"\n  user: {username}")
            await client.create_user(username, exists_ok=True)
            await client.set_user_policy(
                username, HOME_INLINE, user_home_policies[username]
            )
            print(f"    set inline policy '{HOME_INLINE}'")
            await client.set_user_policy(
                username, SYSTEM_INLINE, user_system_policies[username]
            )
            print(f"    set inline policy '{SYSTEM_INLINE}'")

        print(f"\n  Migrating {len(group_names)} groups…")
        for group_name in sorted(group_names):
            print(f"\n  group: {group_name}")
            await client.create_group(group_name, exists_ok=True)
            await client.set_group_policy(
                group_name, GROUP_INLINE, group_policies[group_name]
            )
            print(f"    set inline policy '{GROUP_INLINE}'")
            for member in group_members[group_name]:
                await client.add_user_to_group(member, group_name)
                print(f"    added member: {member}")

    print("\n── Migration complete ────────────────────────────────────────────────")


# ── CLI ──────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Migrate MinIO standalone policies to S3 IAM inline policies."
    )
    p.add_argument("--src-endpoint", required=True, help="MinIO source endpoint URL")
    p.add_argument("--src-access-key", required=True, help="MinIO source access key")
    p.add_argument("--src-secret-key", required=True, help="MinIO source secret key")
    p.add_argument(
        "--mc-path",
        default="mc",
        help="Path to the mc binary (default: 'mc' in PATH)",
    )
    p.add_argument("--dst-endpoint", required=True, help="Target S3 IAM endpoint URL")
    p.add_argument("--dst-access-key", required=True, help="Target access key")
    p.add_argument("--dst-secret-key", required=True, help="Target secret key")
    p.add_argument(
        "--dst-path-prefix",
        default="/",
        help="IAM path prefix for created users/groups (default: /)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without making any changes",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(
            migrate(
                mc_path=args.mc_path,
                src_endpoint=args.src_endpoint,
                src_access_key=args.src_access_key,
                src_secret_key=args.src_secret_key,
                dst_endpoint=args.dst_endpoint,
                dst_access_key=args.dst_access_key,
                dst_secret_key=args.dst_secret_key,
                dst_path_prefix=args.dst_path_prefix,
                dry_run=args.dry_run,
            )
        )
    except Exception as e:
        print(f"\nFATAL: {e}", file=sys.stderr)
        sys.exit(1)
