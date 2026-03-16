"""
Group/Tenant factory fixtures for integration tests.

Provides fixtures to create temporary groups with automatic cleanup.
Each fixture creates unique groups to ensure parallel-safe execution.
"""

import time
from typing import Any, Dict, Generator, List

import httpx
import pytest
from utils.cleanup import safe_delete_group, safe_delete_user
from utils.unique import unique_group_name, unique_username


@pytest.fixture(scope="function")
def temp_group(
    api_client: httpx.Client, admin_headers: dict
) -> Generator[Dict[str, Any], None, None]:
    """
    Create a temporary group for this test.

    The group is automatically cleaned up after the test completes.

    Yields:
        dict: Group data including:
            - group_name: str
            - members: list[str]
            - policy_name: str

    Example:
        def test_something(temp_group):
            group_name = temp_group["group_name"]
    """
    group_name = unique_group_name()

    # Create group via API
    response = api_client.post(
        f"/management/groups/{group_name}", headers=admin_headers, json={"members": []}
    )

    if response.status_code not in (200, 201):
        pytest.fail(
            f"Failed to create temp group {group_name}: {response.status_code} - {response.text}"
        )

    group_data = response.json()
    group_data["group_name"] = group_name

    yield group_data

    # Cleanup: Delete group after test
    safe_delete_group(api_client, group_name, admin_headers)


@pytest.fixture(scope="function")
def temp_group_with_members(
    api_client: httpx.Client, admin_headers: dict
) -> Generator[Dict[str, Any], None, None]:
    """
    Create a temporary group with two member users.

    Creates the group and two users, adds users to the group.
    All resources are cleaned up automatically.

    Yields:
        dict: Contains:
            - group_name: str
            - members: list of user dicts

    Example:
        def test_group_access(temp_group_with_members):
            group_name = temp_group_with_members["group_name"]
            member1 = temp_group_with_members["members"][0]
    """
    group_name = unique_group_name()
    member1_name = unique_username("member1")
    member2_name = unique_username("member2")

    members = []

    try:
        # Create member users first
        for username in [member1_name, member2_name]:
            resp = api_client.post(
                f"/management/users/{username}", headers=admin_headers
            )
            if resp.status_code != 201:
                pytest.fail(f"Failed to create member user {username}: {resp.text}")
            user_data = resp.json()
            user_data["username"] = username
            members.append(user_data)

        # Create group (API doesn't accept members in create body)
        response = api_client.post(
            f"/management/groups/{group_name}",
            headers=admin_headers,
        )

        if response.status_code not in (200, 201):
            pytest.fail(f"Failed to create group {group_name}: {response.text}")

        group_data = response.json()

        # Add members via separate API calls
        for member in members:
            time.sleep(1)
            add_resp = api_client.post(
                f"/management/groups/{group_name}/members/{member['username']}",
                headers=admin_headers,
            )
            if add_resp.status_code not in (200, 201):
                pytest.fail(
                    f"Failed to add member {member['username']}: {add_resp.text}"
                )

        yield {
            "group_name": group_name,
            "group_data": group_data,
            "members": members,
        }

    finally:
        # Cleanup: group first, then users
        safe_delete_group(api_client, group_name, admin_headers)
        safe_delete_user(api_client, member1_name, admin_headers)
        safe_delete_user(api_client, member2_name, admin_headers)


@pytest.fixture(scope="function")
def temp_groups_factory(api_client: httpx.Client, admin_headers: dict):
    """
    Factory fixture to create multiple temporary groups on demand.

    Use this when you need to create groups dynamically within a test.
    All created groups are tracked and cleaned up automatically.

    Yields:
        callable: Function that creates groups

    Example:
        def test_multi_group(temp_groups_factory):
            group1 = temp_groups_factory("team1")
            group2 = temp_groups_factory("team2", members=["user1"])
    """
    created_groups = []

    def create_group(
        prefix: str = "dynamic", members: "List[str] | None" = None
    ) -> Dict[str, Any]:
        group_name = unique_group_name(prefix)
        response = api_client.post(
            f"/management/groups/{group_name}",
            headers=admin_headers,
            json={"members": members or []},
        )
        if response.status_code not in (200, 201):
            pytest.fail(f"Failed to create group {group_name}: {response.text}")

        group_data = response.json()
        group_data["group_name"] = group_name
        created_groups.append(group_name)
        return group_data

    yield create_group

    # Cleanup all created groups
    for group_name in created_groups:
        safe_delete_group(api_client, group_name, admin_headers)
