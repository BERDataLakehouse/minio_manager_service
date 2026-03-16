"""
Root conftest.py for integration tests.

This file imports and re-exports all fixtures from the fixtures module
so they are available to all test files.
"""

import logging
import os
import sys
from pathlib import Path
import time

import httpx
import pytest

# Import all fixtures from fixtures module
# These imports make the fixtures available to all test files
from fixtures.auth import (
    admin_client,
    admin_headers,
    admin_username,
    api_client,
    test_config,
    user_client,
    user_headers,
)
from fixtures.groups import (
    temp_group,
    temp_group_with_members,
    temp_groups_factory,
)
from fixtures.users import (
    temp_user,
    temp_user_pair,
    temp_users_factory,
)
from fixtures.verification import (
    minio_verifier,
    verify_group_state,
    verify_sharing_state,
    verify_user_state,
)
from fixtures.credential_db import credential_db
from fixtures.polaris_verification import polaris_verifier

# Load environment variables from .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    # Manual .env loading if dotenv not available
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                if "=" in line and not line.strip().startswith("#"):
                    key, value = line.strip().split("=", 1)
                    os.environ[key] = value

# Ensure src directory is in path for imports
_base_path = Path(__file__).parent.parent
sys.path.insert(0, str(_base_path))
sys.path.insert(0, str(_base_path / "src"))
sys.path.insert(0, str(_base_path / "API_tests"))


# Re-export all fixtures so pytest can find them
__all__ = [
    # Auth fixtures
    "test_config",
    "api_client",
    "admin_headers",
    "admin_username",
    "user_headers",
    "admin_client",
    "user_client",
    # User fixtures
    "temp_user",
    "temp_user_pair",
    "temp_users_factory",
    # Group fixtures
    "temp_group",
    "temp_group_with_members",
    "temp_groups_factory",
    # Verification fixtures
    "minio_verifier",
    "verify_user_state",
    "verify_group_state",
    "verify_sharing_state",
    # Credential DB
    "credential_db",
    # Polaris
    "polaris_verifier",
    # Session fixtures
    "cleanup_stale_test_resources",
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session", autouse=True)
def cleanup_stale_test_resources(test_config, admin_headers):
    """
    Session-scoped fixture that cleans up stale test resources at session start.

    This runs automatically before any tests execute and removes:
    - Stale test GROUPS (cleaned first, since users may be members)
    - Stale test USERS

    This prevents accumulated test resources from causing issues like:
    - Slow list_users endpoint
    - "Failed to check if user is in group" errors

    The fixture uses autouse=True so it runs automatically for every test session.
    """
    base_url = test_config["base_url"]
    timeout = test_config.get("test_timeout", 120)

    # Prefixes used by test fixtures
    test_prefixes = (
        "testuser_",
        "owner_",
        "recipient_",
        "rotate_test_",
        "create_test_",
        "delete_test_",
        "lifecycle_",
        "dynamic_",
        "testgroup",
        "single_lock",
        "concurrent_lock",
        "user1_lock",
        "user2_lock",
        "lock_release",
        "lock_exists",
        "nonexistent",
        "unauthorized",
        "unauth",
        "cred_",
    )

    logger.info("Starting session cleanup of stale test resources...")

    with httpx.Client(base_url=base_url, timeout=timeout) as client:
        # ===== CLEAN UP GROUPS FIRST (users may be in groups) =====
        try:
            response = client.get("/management/groups", headers=admin_headers)

            if response.status_code == 200:
                data = response.json()
                groups = data.get("groups", [])

                stale_groups = []
                for group in groups:
                    group_name = (
                        group.get("group_name", "")
                        if isinstance(group, dict)
                        else str(group)
                    )
                    if any(
                        group_name.startswith(prefix)
                        or group_name.startswith(prefix.replace("_", ""))
                        for prefix in test_prefixes
                    ):
                        stale_groups.append(group_name)

                if stale_groups:
                    logger.info(
                        f"Found {len(stale_groups)} stale test groups to clean up"
                    )
                    deleted = 0
                    for group_name in stale_groups:
                        time.sleep(0.1)  # Small delay to avoid overwhelming server
                        try:
                            del_response = client.delete(
                                f"/management/groups/{group_name}",
                                headers=admin_headers,
                            )
                            if del_response.status_code in (200, 204, 404):
                                deleted += 1
                        except Exception as e:
                            logger.debug(f"Error deleting group {group_name}: {e}")
                    logger.info(f"Groups cleanup: {deleted} deleted")

        except Exception as e:
            logger.warning(f"Error during group cleanup: {e}")

        # ===== CLEAN UP USERS =====
        try:
            response = client.get(
                "/management/users", headers=admin_headers, params={"page_size": 500}
            )

            if response.status_code == 200:
                data = response.json()
                users = data.get("users", [])

                stale_users = []
                for user in users:
                    username = (
                        user.get("username", "")
                        if isinstance(user, dict)
                        else str(user)
                    )
                    if any(username.startswith(prefix) for prefix in test_prefixes):
                        stale_users.append(username)

                if stale_users:
                    logger.info(
                        f"Found {len(stale_users)} stale test users to clean up"
                    )
                    deleted = 0
                    for username in stale_users:
                        time.sleep(0.1)  # Small delay to avoid overwhelming server
                        try:
                            del_response = client.delete(
                                f"/management/users/{username}", headers=admin_headers
                            )
                            if del_response.status_code in (200, 204, 404):
                                deleted += 1
                        except Exception as e:
                            logger.debug(f"Error deleting user {username}: {e}")
                    logger.info(f"Users cleanup: {deleted} deleted")
                else:
                    logger.info("No stale test users found")

        except Exception as e:
            logger.warning(f"Error during user cleanup: {e}")

    # Yield to run tests
    yield

    logger.info("Test session complete")
