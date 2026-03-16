"""
MinIO admin verification utilities for integration tests.

Uses the ``mc`` CLI with ``--json`` output to query MinIO IAM state
(users, groups, policies) for test assertions.
"""

import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

MC_ALIAS = "integration_test"


def _setup_alias(endpoint: str, root_user: str, root_password: str) -> None:
    """Register an mc alias for the test MinIO instance."""
    subprocess.run(
        ["mc", "alias", "set", MC_ALIAS, endpoint, root_user, root_password],
        capture_output=True,
        text=True,
        check=True,
    )


def _mc_admin(*args: str) -> dict | None:
    """Run an ``mc admin`` sub-command and return parsed JSON, or *None* on error."""
    cmd = ["mc", "admin", *args, "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if not result.stdout.strip():
        return None
    try:
        data = json.loads(result.stdout.strip().splitlines()[0])
    except (json.JSONDecodeError, IndexError):
        return None
    if data.get("status") == "error":
        return None
    return data


class MinIOVerifier:
    """Read-only helper that inspects MinIO IAM state via ``mc admin``."""

    def __init__(
        self,
        endpoint: str | None = None,
        root_user: str | None = None,
        root_password: str | None = None,
    ):
        endpoint = endpoint or os.getenv("MINIO_ENDPOINT", "http://localhost:9012")
        root_user = root_user or os.getenv("MINIO_ROOT_USER", "minio")
        root_password = root_password or os.getenv("MINIO_ROOT_PASSWORD", "minio123")
        _setup_alias(endpoint, root_user, root_password)

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def user_exists(self, username: str) -> bool:
        data = _mc_admin("user", "info", MC_ALIAS, username)
        return data is not None and data.get("status") == "success"

    def get_user_info(self, username: str) -> dict | None:
        return _mc_admin("user", "info", MC_ALIAS, username)

    def get_user_groups(self, username: str) -> list[str]:
        data = _mc_admin("user", "info", MC_ALIAS, username)
        if data is None:
            return []
        return [g["name"] for g in data.get("memberOf", [])]

    def get_user_policies(self, username: str) -> list[str]:
        data = _mc_admin("user", "info", MC_ALIAS, username)
        if data is None:
            return []
        raw = data.get("policyName", "")
        return [p for p in raw.split(",") if p] if raw else []

    def get_user_accessible_paths(self, username: str) -> list[str]:
        """Return S3 resource ARN paths the user can access (via attached policies)."""
        paths: list[str] = []
        for policy_name in self.get_user_policies(username):
            paths.extend(self._get_policy_paths(policy_name))
        for group in self.get_user_groups(username):
            for policy_name in self.get_group_policies(group):
                paths.extend(self._get_policy_paths(policy_name))
        return paths

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def group_exists(self, group_name: str) -> bool:
        data = _mc_admin("group", "info", MC_ALIAS, group_name)
        return data is not None and data.get("status") == "success"

    def get_group_info(self, group_name: str) -> dict | None:
        return _mc_admin("group", "info", MC_ALIAS, group_name)

    def get_group_members(self, group_name: str) -> list[str]:
        data = _mc_admin("group", "info", MC_ALIAS, group_name)
        if data is None:
            return []
        return data.get("members", []) or []

    def get_group_policies(self, group_name: str) -> list[str]:
        data = _mc_admin("group", "info", MC_ALIAS, group_name)
        if data is None:
            return []
        raw = data.get("groupPolicy", "")
        return [p for p in raw.split(",") if p] if raw else []

    # ------------------------------------------------------------------
    # Policies (internal helper)
    # ------------------------------------------------------------------

    def _get_policy_paths(self, policy_name: str) -> list[str]:
        """Extract resource paths from a named MinIO policy."""
        data = _mc_admin("policy", "info", MC_ALIAS, policy_name)
        if data is None:
            return []
        policy_doc = data.get("policyInfo", {}).get("Policy", {})
        paths: list[str] = []
        for stmt in policy_doc.get("Statement", []):
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            paths.extend(resources)
        return paths
