#!/usr/bin/env python3
"""
Test Prerequisites Setup Script

This script ensures that required test users and resources exist before running tests.
Run this after container restarts since test data is not persisted.

Usage:
    python ensure_test_prerequisites.py
"""

import os
import sys
import requests
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def load_env() -> dict:
    """Load environment variables from .env file."""
    env_vars = {}
    env_file = os.path.join(os.path.dirname(__file__), ".env")

    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    env_vars[key] = value
                    # Also set in os.environ for consistency
                    os.environ[key] = value

    return env_vars


def create_user_if_not_exists(base_url: str, admin_token: str, username: str) -> bool:
    """Create a user if it doesn't exist."""
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }

    # Check if user exists
    try:
        response = requests.get(
            f"{base_url}/management/users/{username}", headers=headers, timeout=30
        )
        if response.status_code == 200:
            logger.info(f"✓ User '{username}' already exists")
            return True
    except requests.RequestException:
        pass

    # Create user
    try:
        response = requests.post(
            f"{base_url}/management/users/{username}", headers=headers, timeout=60
        )
        if response.status_code == 201:
            logger.info(f"✓ Created user '{username}'")
            return True
        else:
            logger.error(
                f"✗ Failed to create user '{username}': {response.status_code} - {response.text}"
            )
            return False
    except requests.RequestException as e:
        logger.error(f"✗ Error creating user '{username}': {e}")
        return False


def create_group_if_not_exists(
    base_url: str, admin_token: str, group_name: str, members: list | None = None
) -> bool:
    """Create a group if it doesn't exist, then add members."""
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }

    if members is None:
        members = []

    # Check if group exists
    try:
        response = requests.get(
            f"{base_url}/management/groups/{group_name}", headers=headers, timeout=30
        )
        if response.status_code == 200:
            logger.info(f"✓ Group '{group_name}' already exists")
            return True
    except requests.RequestException:
        pass

    # Create group
    try:
        response = requests.post(
            f"{base_url}/management/groups/{group_name}", headers=headers, timeout=60
        )
        if response.status_code == 201:
            logger.info(f"✓ Created group '{group_name}'")

            # Add members to the group
            for member in members:
                try:
                    member_response = requests.post(
                        f"{base_url}/management/groups/{group_name}/members/{member}",
                        headers=headers,
                        timeout=30,
                    )
                    if member_response.status_code in (200, 201, 204):
                        logger.info(f"  + Added '{member}' to group '{group_name}'")
                    else:
                        logger.warning(
                            f"  - Failed to add '{member}' to group: {member_response.status_code}"
                        )
                except requests.RequestException as e:
                    logger.warning(f"  - Error adding '{member}' to group: {e}")

            return True
        else:
            logger.error(
                f"✗ Failed to create group '{group_name}': {response.status_code} - {response.text}"
            )
            return False
    except requests.RequestException as e:
        logger.error(f"✗ Error creating group '{group_name}': {e}")
        return False


def main():
    """Main function to set up test prerequisites."""
    logger.info("=" * 50)
    logger.info("Setting up test prerequisites...")
    logger.info("=" * 50)

    # Load environment
    env_vars = load_env()
    base_url = env_vars.get("API_BASE_URL", "http://localhost:8010")
    admin_token = env_vars.get("ADMIN_KBASE_TOKEN")

    if not admin_token:
        logger.error("ADMIN_KBASE_TOKEN not found in .env file")
        logger.error("Please ensure .env file exists with valid tokens")
        return False

    # Check API connectivity
    logger.info(f"\nChecking API at {base_url}...")
    try:
        response = requests.get(f"{base_url}/health", timeout=10)
        if response.status_code != 200:
            logger.error(f"API health check failed: {response.status_code}")
            return False
        logger.info("✓ API is healthy\n")
    except requests.RequestException as e:
        logger.error(f"Failed to connect to API: {e}")
        logger.error("Make sure the service is running (docker compose up -d)")
        return False

    # Create required users (the token owners)
    # Tests create their own temp users via fixtures, but we need
    # the users whose tokens we're using to exist in MinIO
    logger.info("Creating required users...")
    required_users = [
        "tgu2",  # Admin user (ADMIN_KBASE_TOKEN owner) - needed for all admin ops
        "tgu3",  # Regular user (KBASE_TOKEN owner)
    ]

    all_success = True
    for username in required_users:
        if not create_user_if_not_exists(base_url, admin_token, username):
            all_success = False

    # Summary
    logger.info("\n" + "=" * 50)
    if all_success:
        logger.info("✅ All test prerequisites are ready!")
        logger.info("You can now run: pytest -n auto")
    else:
        logger.error("❌ Some test prerequisites failed to set up")
        logger.error("Check the errors above and try again")
    logger.info("=" * 50)

    return all_success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
