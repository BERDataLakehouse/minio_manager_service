"""
Group Permission Tests.

Tests for verifying that group membership correctly grants or restricts
file access based on read/write vs read-only permissions.
"""

import pytest
from utils.unique import unique_table_name, unique_file_name
from utils.paths import USERS_SQL_WAREHOUSE, DEFAULT_BUCKET


@pytest.mark.sharing
@pytest.mark.functional
class TestGroupPermissions:
    """Tests for group-based permission access control."""

    def test_user_in_shared_group_can_read_and_write(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_user,
        temp_group,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares a path with a group (default WRITE permission)
            - User is added to the group
            - User attempts to read and write

        Expected:
            - User can read files in the shared path
            - User can write files to the shared path

        Why this matters:
            Group sharing with write permission should grant full read/write access.
        """
        group_name = temp_group["group_name"]
        recipient = temp_user

        # Create path in admin's space
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        dir_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
        share_path = f"s3a://{DEFAULT_BUCKET}/{dir_key}"

        # Create a file to read
        file_content = "group shared data"
        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        # Add user to group
        add_resp = api_client.post(
            f"/management/groups/{group_name}/members/{recipient['username']}",
            headers=admin_headers,
        )
        assert add_resp.status_code in (200, 201)

        # Share path with group (default write permission)
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

        # Verify user can read
        content = minio_files.read_as_user(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert content == file_content, (
            f"User in group should be able to read. Got: {content}"
        )

        # Verify user can write
        can_write = minio_files.user_can_write(
            DEFAULT_BUCKET,
            dir_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert can_write, "User in group with write permission should be able to write"

    def test_user_in_readonly_group_cannot_write(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_user,
        temp_group,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares a path with a group using READ permission
            - User is added to the group
            - User attempts to read and write

        Expected:
            - User can read files in the shared path
            - User CANNOT write files to the shared path

        Why this matters:
            Read-only group sharing should only grant read access.
        """
        group_name = temp_group["group_name"]
        recipient = temp_user

        # Create path in admin's space
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        dir_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
        share_path = f"s3a://{DEFAULT_BUCKET}/{dir_key}"

        # Create a file to read
        file_content = "read-only group data"
        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        # Add user to group
        add_resp = api_client.post(
            f"/management/groups/{group_name}/members/{recipient['username']}",
            headers=admin_headers,
        )
        assert add_resp.status_code in (200, 201)

        # Share path with group (READ-ONLY permission)
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

        # Verify user can read
        content = minio_files.read_as_user(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert content == file_content, (
            f"User in read-only group should be able to read. Got: {content}"
        )

        # Verify user CANNOT write
        can_write = minio_files.user_can_write(
            DEFAULT_BUCKET,
            dir_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert not can_write, "User in read-only group should NOT be able to write"

    def test_user_permission_changes_after_group_switch(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_user,
        temp_groups_factory,
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
            Access revocation works correctly when group membership changes.
        """
        recipient = temp_user

        # Create two groups (no underscores allowed in group names - Hive compatibility)
        write_group = temp_groups_factory("writegroup")
        readonly_group = temp_groups_factory("readonlygroup")

        # Create path in admin's space
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        dir_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
        share_path = f"s3a://{DEFAULT_BUCKET}/{dir_key}"

        # Create a file
        file_content = "permission switch test"
        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        # Share with both groups - write_group gets write, readonly_group gets read
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

        # Add user to write group
        add_resp = api_client.post(
            f"/management/groups/{write_group['group_name']}/members/{recipient['username']}",
            headers=admin_headers,
        )
        assert add_resp.status_code in (200, 201)

        # Verify user can write (in write group)
        can_write = minio_files.user_can_write(
            DEFAULT_BUCKET,
            dir_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert can_write, "User in write group should be able to write"

        # Remove from write group
        remove_resp = api_client.delete(
            f"/management/groups/{write_group['group_name']}/members/{recipient['username']}",
            headers=admin_headers,
        )
        assert remove_resp.status_code in (200, 204)

        # Add to read-only group
        add_readonly_resp = api_client.post(
            f"/management/groups/{readonly_group['group_name']}/members/{recipient['username']}",
            headers=admin_headers,
        )
        assert add_readonly_resp.status_code in (200, 201)

        # Verify user can still read
        content = minio_files.read_as_user(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert content == file_content, "User should still be able to read"

        # Verify user can NO LONGER write
        can_write_after = minio_files.user_can_write(
            DEFAULT_BUCKET,
            dir_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert not can_write_after, (
            "User moved to read-only group should NO LONGER be able to write"
        )
