"""
User factory fixtures for integration tests.

Provides fixtures to create temporary users with automatic cleanup.
Each fixture creates unique users to ensure parallel-safe execution.
"""

import pytest
import httpx
from typing import Generator, Dict, Any

from utils.unique import unique_username
from utils.cleanup import safe_delete_user


@pytest.fixture(scope="function")
def temp_user(
    api_client: httpx.Client, admin_headers: dict
) -> Generator[Dict[str, Any], None, None]:
    """
    Create a temporary user for this test.

    The user is automatically cleaned up after the test completes.

    Yields:
        dict: User data including:
            - username: str
            - access_key: str
            - secret_key: str
            - home_paths: list[str]

    Example:
        def test_something(temp_user):
            username = temp_user["username"]
            # Use the user...
    """
    username = unique_username()

    # Create user via API
    response = api_client.post(f"/management/users/{username}", headers=admin_headers)

    if response.status_code != 201:
        pytest.fail(
            f"Failed to create temp user {username}: {response.status_code} - {response.text}"
        )

    user_data = response.json()
    user_data["username"] = username

    yield user_data

    # Cleanup: Delete user after test
    safe_delete_user(api_client, username, admin_headers)


@pytest.fixture(scope="function")
def temp_user_pair(
    api_client: httpx.Client, admin_headers: dict
) -> Generator[Dict[str, Any], None, None]:
    """
    Create a pair of temporary users for sharing tests.

    Useful for owner/recipient scenarios.

    Yields:
        dict: Contains 'owner' and 'recipient' user data

    Example:
        def test_sharing(temp_user_pair):
            owner = temp_user_pair["owner"]
            recipient = temp_user_pair["recipient"]
    """
    owner_name = unique_username("owner")
    recipient_name = unique_username("recipient")
    users = {}

    try:
        # Create owner
        owner_resp = api_client.post(
            f"/management/users/{owner_name}", headers=admin_headers
        )
        if owner_resp.status_code != 201:
            pytest.fail(f"Failed to create owner user: {owner_resp.text}")
        users["owner"] = owner_resp.json()
        users["owner"]["username"] = owner_name

        # Create recipient
        recipient_resp = api_client.post(
            f"/management/users/{recipient_name}", headers=admin_headers
        )
        if recipient_resp.status_code != 201:
            pytest.fail(f"Failed to create recipient user: {recipient_resp.text}")
        users["recipient"] = recipient_resp.json()
        users["recipient"]["username"] = recipient_name

        yield users

    finally:
        # Cleanup both users
        safe_delete_user(api_client, owner_name, admin_headers)
        safe_delete_user(api_client, recipient_name, admin_headers)


@pytest.fixture(scope="function")
def temp_users_factory(api_client: httpx.Client, admin_headers: dict):
    """
    Factory fixture to create multiple temporary users on demand.

    Use this when you need to create users dynamically within a test.
    All created users are tracked and cleaned up automatically.

    Yields:
        callable: Function that creates users

    Example:
        def test_multi_user(temp_users_factory):
            user1 = temp_users_factory("prefix1")
            user2 = temp_users_factory("prefix2")
            # Both cleaned up automatically
    """
    created_users = []

    def create_user(prefix: str = "dynamic") -> Dict[str, Any]:
        username = unique_username(prefix)
        response = api_client.post(
            f"/management/users/{username}", headers=admin_headers
        )
        if response.status_code != 201:
            pytest.fail(f"Failed to create user {username}: {response.text}")

        user_data = response.json()
        user_data["username"] = username
        created_users.append(username)
        return user_data

    yield create_user

    # Cleanup all created users
    for username in created_users:
        safe_delete_user(api_client, username, admin_headers)
