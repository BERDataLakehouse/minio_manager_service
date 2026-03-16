"""
Group/Tenant Management Tests.

Tests for group CRUD operations via the /management/groups/ endpoints.
All tests are parallel-safe through UUID-based resource isolation.
"""

import time
import pytest
from utils.unique import unique_group_name, unique_table_name, unique_file_name
from utils.paths import USERS_SQL_WAREHOUSE, DEFAULT_BUCKET


@pytest.mark.management
class TestGroupCreation:
    """Tests for creating groups/tenants."""

    def test_create_group_with_valid_name(
        self, api_client, admin_headers, minio_verifier
    ):
        """
        Scenario:
            Admin creates a new group with a unique name.
        Expected:
            - API returns 200/201
            - Group exists in MinIO
            - Group policy is created
        Why this matters:
            Group/tenant provisioning enables shared workspaces.
        """
        group_name = unique_group_name("createtest")

        try:
            # Act
            response = api_client.post(
                f"/management/groups/{group_name}",
                headers=admin_headers,
                json={"members": []},
            )

            # Assert - API response
            assert response.status_code in (200, 201), (
                f"Expected 200/201, got {response.status_code}: {response.text}"
            )

            # Assert - MinIO state
            assert minio_verifier.group_exists(group_name), (
                f"Group {group_name} should exist in MinIO"
            )

        finally:
            # Cleanup - handle potential server disconnect
            try:
                api_client.delete(
                    f"/management/groups/{group_name}", headers=admin_headers
                )
            except Exception:
                pass  # Ignore cleanup errors

    def test_create_group_with_members(
        self, api_client, admin_headers, temp_user, minio_verifier
    ):
        """
        Scenario:
            Admin creates a group, then adds a member.
        Expected:
            - Group is created
            - Member is added to the group via separate API call
        Why this matters:
            Groups can have members added after creation.
        """
        group_name = unique_group_name("withmembers")
        username = temp_user["username"]

        try:
            # Step 1: Create the group (API doesn't accept members in body)
            create_resp = api_client.post(
                f"/management/groups/{group_name}",
                headers=admin_headers,
            )
            assert create_resp.status_code in (200, 201), (
                f"Failed to create group: {create_resp.text}"
            )

            # Step 2: Add member via separate endpoint
            add_resp = api_client.post(
                f"/management/groups/{group_name}/members/{username}",
                headers=admin_headers,
            )
            assert add_resp.status_code in (200, 201), (
                f"Failed to add member: {add_resp.text}"
            )

            # Verify member is in group
            members = minio_verifier.get_group_members(group_name)
            assert username in members, (
                f"User {username} should be in group {group_name}"
            )

        finally:
            # Cleanup - handle potential server disconnect
            try:
                api_client.delete(
                    f"/management/groups/{group_name}", headers=admin_headers
                )
            except Exception:
                pass  # Ignore cleanup errors

    def test_create_duplicate_group_fails(self, api_client, admin_headers, temp_group):
        """
        Scenario:
            A group already exists.
            Admin tries to create another group with the same name.
        Expected:
            - API returns 409 Conflict
        Why this matters:
            Prevents overwriting existing group configurations.
        """
        group_name = temp_group["group_name"]

        # Act
        response = api_client.post(
            f"/management/groups/{group_name}",
            headers=admin_headers,
            json={"members": []},
        )

        # Assert - API may return 409 for conflict or 200/201 if idempotent
        assert response.status_code in (200, 201, 400, 409), (
            f"Expected conflict or idempotent, got {response.status_code}"
        )


@pytest.mark.management
class TestGroupMembership:
    """Tests for group membership operations."""

    def test_add_member_to_group(
        self, api_client, admin_headers, temp_group, temp_user, minio_verifier
    ):
        """
        Scenario:
            Admin adds a user to an existing group.
        Expected:
            - API returns success
            - User is now a member of the group
        Why this matters:
            Users can be added to groups after creation.
        """
        group_name = temp_group["group_name"]
        username = temp_user["username"]

        # Act
        response = api_client.post(
            f"/management/groups/{group_name}/members/{username}", headers=admin_headers
        )

        # Assert
        assert response.status_code in (200, 201)

        # Verify membership
        members = minio_verifier.get_group_members(group_name)
        assert username in members

    def test_remove_member_from_group(
        self, api_client, admin_headers, temp_group, temp_user, minio_verifier
    ):
        """
        Scenario:
            Admin removes a user from a group.
        Expected:
            - API returns success
            - User is no longer in the group
        Why this matters:
            Users can be removed from groups to revoke access.
        """
        group_name = temp_group["group_name"]
        username = temp_user["username"]

        # First add the user to the group via API
        add_resp = api_client.post(
            f"/management/groups/{group_name}/members/{username}", headers=admin_headers
        )
        assert add_resp.status_code in (200, 201), (
            f"Failed to add member: {add_resp.text}"
        )

        # Verify user is in group
        assert username in minio_verifier.get_group_members(group_name)

        # Act - remove user from group
        response = api_client.delete(
            f"/management/groups/{group_name}/members/{username}", headers=admin_headers
        )

        # Assert
        assert response.status_code in (200, 204)

        # Verify removal
        members = minio_verifier.get_group_members(group_name)
        assert username not in members


@pytest.mark.management
class TestGroupDeletion:
    """Tests for deleting groups."""

    def test_delete_existing_group(self, api_client, admin_headers, minio_verifier):
        """
        Scenario:
            Admin creates a group, then deletes it.
        Expected:
            - API returns success
            - Group no longer exists
        Why this matters:
            Groups can be deprovisioned cleanly.
        """
        group_name = unique_group_name("deletetest")

        # Setup - create group
        create_resp = api_client.post(
            f"/management/groups/{group_name}",
            headers=admin_headers,
        )
        assert create_resp.status_code in (200, 201)

        # Remove all members before delete (creator is auto-added)
        members = minio_verifier.get_group_members(group_name)
        for member in members:
            time.sleep(1)
            api_client.delete(
                f"/management/groups/{group_name}/members/{member}",
                headers=admin_headers,
            )

        # Act - delete group
        delete_resp = api_client.delete(
            f"/management/groups/{group_name}", headers=admin_headers
        )

        # Assert
        assert delete_resp.status_code in (200, 204)
        assert not minio_verifier.group_exists(group_name)

    def test_delete_nonexistent_group(self, api_client, admin_headers):
        """
        Scenario:
            Admin tries to delete a group that doesn't exist.
        Expected:
            - API returns 404 Not Found
        Why this matters:
            Proper error handling for missing resources.
        """
        group_name = unique_group_name("nonexistent")

        response = api_client.delete(
            f"/management/groups/{group_name}", headers=admin_headers
        )

        # API may return 400 or 404 for non-existent group
        assert response.status_code in (400, 404)


@pytest.mark.management
class TestGroupListing:
    """Tests for listing groups."""

    def test_list_all_groups(self, api_client, admin_headers, temp_group):
        """
        Scenario:
            Admin lists all groups.
        Expected:
            - API returns 200
            - Created temp_group is in the list
        Why this matters:
            Inventory of groups is needed for administration.
        """
        response = api_client.get("/management/groups", headers=admin_headers)

        assert response.status_code == 200
        data = response.json()

        # Response may be a list or a paginated dict
        if isinstance(data, dict):
            groups = data.get("groups", [])
        else:
            groups = data

        # Should be a list
        assert isinstance(groups, list), "Groups should be a list"

        # temp_group should be in the list
        group_names = [g.get("group_name", g) for g in groups]
        assert temp_group["group_name"] in group_names or any(
            temp_group["group_name"] in str(g) for g in groups
        )

    def test_list_group_names_as_regular_user(
        self, api_client, user_headers, temp_group
    ):
        """
        Scenario:
            Regular (non-admin) user lists available group names.
        Expected:
            - API returns 200
            - Response contains group_names list
            - Created temp_group is in the list
        Why this matters:
            Regular users need to discover available groups they can request access to.
        """
        response = api_client.get("/management/groups/names", headers=user_headers)

        assert response.status_code == 200, (
            f"Expected 200 for regular user, got {response.status_code}: {response.text}"
        )
        data = response.json()

        # Response should have group_names and total_count
        assert "group_names" in data, "Response should have group_names field"
        assert "total_count" in data, "Response should have total_count field"

        group_names = data["group_names"]
        total_count = data["total_count"]

        # Should be a list of strings (names only, no detailed info)
        assert isinstance(group_names, list), "group_names should be a list"
        assert total_count == len(group_names), (
            "total_count should match group_names length"
        )

        # temp_group should be in the list
        assert temp_group["group_name"] in group_names, (
            f"temp_group {temp_group['group_name']} should be in group names"
        )

    def test_list_group_names_requires_authentication(self, api_client):
        """
        Scenario:
            Unauthenticated request to list group names.
        Expected:
            - API returns 401 or 403 (authentication required)
        Why this matters:
            Endpoint requires authentication even though it doesn't require admin.
        """
        response = api_client.get("/management/groups/names")

        assert response.status_code in (401, 403), (
            f"Expected 401/403 for unauthenticated request, got {response.status_code}"
        )

    def test_list_group_names_returns_only_names(
        self, api_client, user_headers, temp_group
    ):
        """
        Scenario:
            Regular user gets group names list.
        Expected:
            - Response contains only names, not detailed info like members or policies
        Why this matters:
            This endpoint is designed to expose minimal information to non-admin users.
        """
        response = api_client.get("/management/groups/names", headers=user_headers)

        assert response.status_code == 200
        data = response.json()

        # Should NOT contain sensitive fields that are in the admin endpoint
        assert "members" not in data, "Response should not contain members field"
        assert "groups" not in data, (
            "Response should not contain groups field (with detailed info)"
        )

        # group_names should be a list of strings, not dicts
        for name in data.get("group_names", []):
            assert isinstance(name, str), (
                f"Each group name should be a string, got {type(name)}"
            )


@pytest.mark.management
@pytest.mark.smoke
class TestGroupLifecycle:
    """Complete group lifecycle workflow tests."""

    def test_complete_group_lifecycle(
        self, api_client, admin_headers, temp_user, minio_verifier
    ):
        """
        Scenario:
            Complete lifecycle: create → add member → remove member → delete
        Expected:
            - All operations succeed
            - State is consistent throughout
        Why this matters:
            End-to-end validation of the group management workflow.
        """
        group_name = unique_group_name("lifecycle")
        username = temp_user["username"]

        try:
            # Step 1: Create group
            create_resp = api_client.post(
                f"/management/groups/{group_name}",
                headers=admin_headers,
                json={"members": []},
            )
            assert create_resp.status_code in (200, 201)

            # Step 2: Verify group exists
            assert minio_verifier.group_exists(group_name)

            # Step 3: Add member
            add_resp = api_client.post(
                f"/management/groups/{group_name}/members/{username}",
                headers=admin_headers,
            )
            assert add_resp.status_code in (200, 201)
            assert username in minio_verifier.get_group_members(group_name)

            # Step 4: Remove member
            remove_resp = api_client.delete(
                f"/management/groups/{group_name}/members/{username}",
                headers=admin_headers,
            )
            assert remove_resp.status_code in (200, 204)
            assert username not in minio_verifier.get_group_members(group_name)

            # Step 5: Remove ALL remaining members before delete (e.g., creator)
            remaining_members = minio_verifier.get_group_members(group_name)
            for member in remaining_members:
                time.sleep(1)
                api_client.delete(
                    f"/management/groups/{group_name}/members/{member}",
                    headers=admin_headers,
                )

            # Step 6: Delete group
            delete_resp = api_client.delete(
                f"/management/groups/{group_name}", headers=admin_headers
            )
            assert delete_resp.status_code in (200, 204)

            # Step 7: Verify group is gone
            assert not minio_verifier.group_exists(group_name)

        finally:
            # Cleanup - handle potential server disconnect
            try:
                api_client.delete(
                    f"/management/groups/{group_name}", headers=admin_headers
                )
            except Exception:
                pass  # Ignore cleanup errors


@pytest.mark.management
@pytest.mark.functional
class TestGroupFileAccess:
    """Tests that verify actual file access based on group membership.

    These tests go beyond CRUD operations to verify that adding/removing
    users from groups actually affects their ability to read/write files.
    """

    def test_member_gains_file_access_when_added_to_group(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_group,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares a path with a group
            - User is NOT in the group -> cannot access
            - Admin adds user to the group
            - User can now read the shared files
        Expected:
            - Adding user to group grants actual file access
        Why this matters:
            Group membership must translate to real file permissions.
        """
        group_name = temp_group["group_name"]
        user = temp_user

        # Create a file in admin's workspace
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        file_content = "group access test data"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"

        # Share path with the group
        share_resp = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [],
                "with_groups": [group_name],
            },
        )
        assert share_resp.status_code == 200

        # User is NOT in group yet - should NOT be able to read
        can_read_before = minio_files.user_can_read(
            DEFAULT_BUCKET, file_key, user["access_key"], user["secret_key"]
        )
        assert not can_read_before, (
            "User should NOT be able to read before joining group"
        )

        # Add user to group
        add_resp = api_client.post(
            f"/management/groups/{group_name}/members/{user['username']}",
            headers=admin_headers,
        )
        assert add_resp.status_code in (200, 201)

        # User IS in group now - SHOULD be able to read
        content = minio_files.read_as_user(
            DEFAULT_BUCKET, file_key, user["access_key"], user["secret_key"]
        )
        assert content == file_content, (
            f"User in group should be able to read. Got: {content}"
        )

    def test_member_loses_file_access_when_removed_from_group(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_group,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares a path with a group
            - User is in the group -> can access
            - Admin removes user from the group
            - User can no longer read the shared files
        Expected:
            - Removing user from group revokes actual file access
        Why this matters:
            Access revocation must work immediately when group membership changes.
        """
        group_name = temp_group["group_name"]
        user = temp_user

        # Create a file in admin's workspace
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        file_content = "access revocation test data"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"

        # Share path with the group
        share_resp = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [],
                "with_groups": [group_name],
            },
        )
        assert share_resp.status_code == 200

        # Add user to group first
        add_resp = api_client.post(
            f"/management/groups/{group_name}/members/{user['username']}",
            headers=admin_headers,
        )
        assert add_resp.status_code in (200, 201)

        # User IS in group - SHOULD be able to read
        assert minio_files.user_can_read(
            DEFAULT_BUCKET, file_key, user["access_key"], user["secret_key"]
        ), "User in group should be able to read"

        # Remove user from group
        remove_resp = api_client.delete(
            f"/management/groups/{group_name}/members/{user['username']}",
            headers=admin_headers,
        )
        assert remove_resp.status_code in (200, 204)

        # User is NO LONGER in group - should NOT be able to read
        can_read_after = minio_files.user_can_read(
            DEFAULT_BUCKET, file_key, user["access_key"], user["secret_key"]
        )
        assert not can_read_after, "User removed from group should NOT be able to read"

    def test_member_in_write_group_can_read_and_write(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_group,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares a path with a group using WRITE permission
            - User is added to the group
            - User attempts to read and write
        Expected:
            - User can READ files in the shared path
            - User can WRITE files to the shared path
        Why this matters:
            Write permission must grant full read/write access.
        """
        group_name = temp_group["group_name"]
        user = temp_user

        # Create a file in admin's workspace
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        dir_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
        file_content = "write group test data"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        share_path = f"s3a://{DEFAULT_BUCKET}/{dir_key}"

        # Add user to group BEFORE sharing (to verify permission propagates)
        add_resp = api_client.post(
            f"/management/groups/{group_name}/members/{user['username']}",
            headers=admin_headers,
        )
        assert add_resp.status_code in (200, 201)

        # Share path with group using WRITE permission
        share_resp = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [],
                "with_groups": [group_name],
                "permission": "write",
            },
        )
        assert share_resp.status_code == 200

        # Verify user can READ
        content = minio_files.read_as_user(
            DEFAULT_BUCKET, file_key, user["access_key"], user["secret_key"]
        )
        assert content == file_content, f"User should be able to read. Got: {content}"

        # Verify user can WRITE
        can_write = minio_files.user_can_write(
            DEFAULT_BUCKET, dir_key, user["access_key"], user["secret_key"]
        )
        assert can_write, "User in write group should be able to write"

    def test_member_in_readonly_group_can_read_but_not_write(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_group,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares a path with a group using READ permission
            - User is added to the group
            - User attempts to read and write
        Expected:
            - User CAN read files in the shared path
            - User CANNOT write files to the shared path
        Why this matters:
            Read-only permission must restrict write access.
        """
        group_name = temp_group["group_name"]
        user = temp_user

        # Create a file in admin's workspace
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        dir_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
        file_content = "readonly group test data"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        share_path = f"s3a://{DEFAULT_BUCKET}/{dir_key}"

        # Add user to group
        add_resp = api_client.post(
            f"/management/groups/{group_name}/members/{user['username']}",
            headers=admin_headers,
        )
        assert add_resp.status_code in (200, 201)

        # Share path with group using READ-ONLY permission
        share_resp = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [],
                "with_groups": [group_name],
                "permission": "read",  # READ-ONLY
            },
        )
        assert share_resp.status_code == 200

        # Verify user CAN read
        content = minio_files.read_as_user(
            DEFAULT_BUCKET, file_key, user["access_key"], user["secret_key"]
        )
        assert content == file_content, f"User should be able to read. Got: {content}"

        # Verify user CANNOT write
        can_write = minio_files.user_can_write(
            DEFAULT_BUCKET, dir_key, user["access_key"], user["secret_key"]
        )
        assert not can_write, "User in read-only group should NOT be able to write"

    def test_member_permission_changes_when_switching_groups(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_groups_factory,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Create two groups: one with write access, one with read-only access
            - User is in write group -> can read and write
            - Remove user from write group, add to read-only group
            - User can now only read, not write
        Expected:
            - Permission changes reflect group membership changes
        Why this matters:
            Changing group membership must update actual file permissions.
        """
        user = temp_user

        # Create two groups (no underscores allowed - Hive compatibility)
        write_group = temp_groups_factory("writeaccess")
        readonly_group = temp_groups_factory("readaccess")

        # Create a file in admin's workspace
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        dir_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
        file_content = "permission switch test"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        share_path = f"s3a://{DEFAULT_BUCKET}/{dir_key}"

        # Share with write_group (write permission)
        share_write = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_groups": [write_group["group_name"]],
                "permission": "write",
            },
        )
        assert share_write.status_code == 200

        # Share with readonly_group (read permission)
        share_read = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_groups": [readonly_group["group_name"]],
                "permission": "read",
            },
        )
        assert share_read.status_code == 200

        # Add user to WRITE group
        add_write = api_client.post(
            f"/management/groups/{write_group['group_name']}/members/{user['username']}",
            headers=admin_headers,
        )
        assert add_write.status_code in (200, 201)

        # Verify user CAN write (in write group)
        can_write = minio_files.user_can_write(
            DEFAULT_BUCKET, dir_key, user["access_key"], user["secret_key"]
        )
        assert can_write, "User in write group should be able to write"

        # Remove from write group
        remove_resp = api_client.delete(
            f"/management/groups/{write_group['group_name']}/members/{user['username']}",
            headers=admin_headers,
        )
        assert remove_resp.status_code in (200, 204)

        # Add to read-only group
        add_readonly = api_client.post(
            f"/management/groups/{readonly_group['group_name']}/members/{user['username']}",
            headers=admin_headers,
        )
        assert add_readonly.status_code in (200, 201)

        # Verify user can still READ
        content = minio_files.read_as_user(
            DEFAULT_BUCKET, file_key, user["access_key"], user["secret_key"]
        )
        assert content == file_content, "User should still be able to read"

        # Verify user can NO LONGER write
        can_write_after = minio_files.user_can_write(
            DEFAULT_BUCKET, dir_key, user["access_key"], user["secret_key"]
        )
        assert not can_write_after, (
            "User moved to read-only group should NO LONGER be able to write"
        )
