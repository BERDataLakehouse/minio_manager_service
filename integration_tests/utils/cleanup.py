"""
Cleanup utilities for integration tests.

Provides helpers for cleaning up test resources, with error handling
to ensure cleanup doesn't fail tests due to already-deleted resources.
"""

import logging
from typing import List
import httpx

logger = logging.getLogger(__name__)


def safe_delete_user(
    client: httpx.Client, username: str, headers: dict, ignore_errors: bool = True
) -> bool:
    """
    Safely delete a user, ignoring 404 errors.

    Args:
        client: HTTP client
        username: Username to delete
        headers: Auth headers
        ignore_errors: If True, ignore all errors (default: True)

    Returns:
        bool: True if deleted, False if failed/not found
    """
    try:
        response = client.delete(f"/management/users/{username}", headers=headers)
        if response.status_code in (200, 204):
            logger.debug(f"Deleted user: {username}")
            return True
        elif response.status_code == 404:
            logger.debug(f"User not found (already deleted?): {username}")
            return False
        else:
            logger.warning(f"Failed to delete user {username}: {response.status_code}")
            return False
    except Exception as e:
        if not ignore_errors:
            raise
        logger.warning(f"Error deleting user {username}: {e}")
        return False


def safe_delete_group(
    client: httpx.Client, group_name: str, headers: dict, ignore_errors: bool = True
) -> bool:
    """
    Safely delete a group, ignoring 404 errors.

    Args:
        client: HTTP client
        group_name: Group name to delete
        headers: Auth headers
        ignore_errors: If True, ignore all errors (default: True)

    Returns:
        bool: True if deleted, False if failed/not found
    """
    try:
        response = client.delete(f"/management/groups/{group_name}", headers=headers)
        if response.status_code in (200, 204):
            logger.debug(f"Deleted group: {group_name}")
            return True
        elif response.status_code == 404:
            logger.debug(f"Group not found (already deleted?): {group_name}")
            return False
        else:
            logger.warning(
                f"Failed to delete group {group_name}: {response.status_code}"
            )
            return False
    except Exception as e:
        if not ignore_errors:
            raise
        logger.warning(f"Error deleting group {group_name}: {e}")
        return False


def cleanup_users(client: httpx.Client, usernames: List[str], headers: dict) -> dict:
    """
    Clean up multiple users.

    Args:
        client: HTTP client
        usernames: List of usernames to delete
        headers: Auth headers

    Returns:
        dict: {'deleted': [...], 'failed': [...]}
    """
    results = {"deleted": [], "failed": []}
    for username in usernames:
        if safe_delete_user(client, username, headers):
            results["deleted"].append(username)
        else:
            results["failed"].append(username)
    return results


def cleanup_groups(client: httpx.Client, group_names: List[str], headers: dict) -> dict:
    """
    Clean up multiple groups.

    Args:
        client: HTTP client
        group_names: List of group names to delete
        headers: Auth headers

    Returns:
        dict: {'deleted': [...], 'failed': [...]}
    """
    results = {"deleted": [], "failed": []}
    for group_name in group_names:
        if safe_delete_group(client, group_name, headers):
            results["deleted"].append(group_name)
        else:
            results["failed"].append(group_name)
    return results


class ResourceTracker:
    """
    Track created resources for cleanup at test end.

    Usage:
        tracker = ResourceTracker()
        tracker.track_user("testuser_abc123")
        tracker.track_group("testgroup_def456")

        # At cleanup
        tracker.cleanup_all(client, headers)
    """

    def __init__(self):
        self.users: List[str] = []
        self.groups: List[str] = []

    def track_user(self, username: str):
        """Track a user for later cleanup."""
        if username not in self.users:
            self.users.append(username)

    def track_group(self, group_name: str):
        """Track a group for later cleanup."""
        if group_name not in self.groups:
            self.groups.append(group_name)

    def cleanup_all(self, client: httpx.Client, headers: dict) -> dict:
        """
        Clean up all tracked resources.

        Order: users first (may be in groups), then groups.
        """
        results = {
            "users": cleanup_users(client, self.users, headers),
            "groups": cleanup_groups(client, self.groups, headers),
        }
        self.users.clear()
        self.groups.clear()
        return results
