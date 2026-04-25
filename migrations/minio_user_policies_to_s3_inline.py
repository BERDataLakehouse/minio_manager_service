"""
Transfer MinIO user policies to S3 IAM inline policies for a given list of users.

For each username, this script:
  1. Reads the policies attached to that user on the MinIO source via the mc CLI.
  2. Fetches each policy document from MinIO.
  3. Optionally creates the user on the S3 IAM destination (--create-user).
  4. Sets each policy as an inline policy on the destination user, keeping the
     original MinIO policy name verbatim.

The script is idempotent: re-running it overwrites inline policies with their
current MinIO values, so it is safe to re-run if interrupted.

Usernames can be supplied directly on the command line (--usernames) or read
from a file (--usernames-file, one name per line, blank lines and # comments
ignored), or both.

Usage:
    PYTHONPATH=src python migrations/minio_user_policies_to_s3_inline.py \
        --src-endpoint http://localhost:9012 \
        --src-access-key minio \
        --src-secret-key minio123 \
        --dst-endpoint http://localhost:9050 \
        --dst-access-key test_access_key \
        --dst-secret-key test_access_secret \
        --usernames alice bob charlie \
        [--usernames-file users.txt] \
        [--create-user] \
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


def mc_get_user_policies(mc_path: str, username: str) -> list[str]:
    """Return the names of policies attached to a user on the source MinIO."""
    raw = _mc(mc_path, "admin", "user", "info", _SRC_ALIAS, username, "--json")
    data = json.loads(raw)
    # mc returns policyName as a comma-separated string or a list depending on version
    policy_field = data.get("policyName", "")
    if isinstance(policy_field, list):
        names = policy_field
    else:
        names = [p for p in policy_field.split(",") if p]
    return names


def mc_get_policy_doc(mc_path: str, policy_name: str) -> dict:
    """Return the policy document dict for a named MinIO policy."""
    raw = _mc(mc_path, "admin", "policy", "info", _SRC_ALIAS, policy_name)
    data = json.loads(raw)
    # mc returns the document under "policyJSON" or "Policy", falling back to
    # the object itself if it IS the policy document.
    return data.get("policyJSON", data.get("Policy", data))


# ── Migration orchestration ──────────────────────────────────────────────────


async def run(
    mc_path: str,
    src_endpoint: str,
    src_access_key: str,
    src_secret_key: str,
    dst_endpoint: str,
    dst_access_key: str,
    dst_secret_key: str,
    dst_path_prefix: str,
    usernames: list[str],
    create_user: bool,
    dry_run: bool,
) -> None:
    print("\n── 1. Connecting to source MinIO via mc ─────────────────────────────")
    mc_setup_alias(mc_path, src_endpoint, src_access_key, src_secret_key)

    print("\n── 2. Reading user policies from MinIO ──────────────────────────────")
    # username → {policy_name → policy_doc}
    user_policies: dict[str, dict[str, dict]] = {}
    policy_doc_cache: dict[str, dict] = {}

    for username in usernames:
        policy_names = mc_get_user_policies(mc_path, username)
        print(f"  {username}: {len(policy_names)} attached policies: {policy_names}")
        docs: dict[str, dict] = {}
        for policy_name in policy_names:
            if policy_name not in policy_doc_cache:
                policy_doc_cache[policy_name] = mc_get_policy_doc(mc_path, policy_name)
            docs[policy_name] = policy_doc_cache[policy_name]
        user_policies[username] = docs

    print("\n── 3. Writing inline policies to destination IAM ────────────────────")
    if dry_run:
        print("  (dry-run: no changes will be made)")
        for username in usernames:
            if create_user:
                print(f"  would create user {username!r}")
            for policy_name in user_policies[username]:
                print(f"  would set inline policy {policy_name!r} on user {username!r}")
        return

    async with S3IAMClient(
        dst_endpoint, dst_access_key, dst_secret_key, dst_path_prefix
    ) as client:
        for username in usernames:
            print(f"\n  user: {username}")
            if create_user:
                await client.create_user(username, exists_ok=True)
                print("    created (or already existed)")
            policies = user_policies[username]
            if not policies:
                print("    no policies to transfer")
                continue
            for policy_name, policy_doc in policies.items():
                await client.set_user_policy(username, policy_name, policy_doc)
                print(f"    set inline policy '{policy_name}'")

    print("\n── Transfer complete ─────────────────────────────────────────────────")


# ── Input helpers ────────────────────────────────────────────────────────────


def _load_usernames_file(path: str) -> list[str]:
    """Read usernames from a file, one per line. Ignores blank lines and # comments."""
    with open(path) as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


# ── CLI ──────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Transfer MinIO user policies to S3 IAM inline policies "
            "for a given list of users."
        )
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
        help="IAM path prefix for created users (default: /)",
    )
    p.add_argument(
        "--usernames",
        nargs="+",
        metavar="USERNAME",
        default=[],
        help="One or more usernames to process",
    )
    p.add_argument(
        "--usernames-file",
        metavar="FILE",
        help="File containing usernames, one per line (blank lines and # comments ignored)",
    )
    p.add_argument(
        "--create-user",
        action="store_true",
        help="Create each user on the destination if it does not already exist",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without making any changes",
    )
    args = p.parse_args()

    file_usernames = (
        _load_usernames_file(args.usernames_file) if args.usernames_file else []
    )
    all_usernames = list(
        dict.fromkeys(args.usernames + file_usernames)
    )  # deduplicate, preserve order

    if not all_usernames:
        p.error("Provide at least one username via --usernames or --usernames-file")

    args.all_usernames = all_usernames
    return args


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(
            run(
                mc_path=args.mc_path,
                src_endpoint=args.src_endpoint,
                src_access_key=args.src_access_key,
                src_secret_key=args.src_secret_key,
                dst_endpoint=args.dst_endpoint,
                dst_access_key=args.dst_access_key,
                dst_secret_key=args.dst_secret_key,
                dst_path_prefix=args.dst_path_prefix,
                usernames=args.all_usernames,
                create_user=args.create_user,
                dry_run=args.dry_run,
            )
        )
    except Exception as e:
        print(f"\nFATAL: {e}", file=sys.stderr)
        sys.exit(1)
