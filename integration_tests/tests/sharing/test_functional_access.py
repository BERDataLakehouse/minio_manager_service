"""
Functional Access Tests for Sharing.

CRITICAL: These tests verify that sharing actually works by performing
real file operations as the shared user, not just checking policy updates.

These tests:
1. Create a file in the owner's workspace
2. Share with a recipient
3. Verify the recipient can actually read/write the file
4. Verify access is revoked after unshare
"""

import pytest
from utils.unique import unique_file_name, unique_table_name
from utils.paths import DEFAULT_BUCKET, USERS_SQL_WAREHOUSE


# Note: minio_files fixture is defined in conftest.py


@pytest.mark.sharing
@pytest.mark.functional
class TestSharedFileReadAccess:
    """Tests that verify recipients can actually read shared files."""

    def test_recipient_can_read_file_after_share(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Admin (tgu2) creates a file in their workspace
            - Admin shares the path with recipient (read)
            - Recipient attempts to read the file

        Expected:
            - Recipient can successfully read the file content

        Why this matters:
            This is the core use case - sharing must grant actual access.
        """
        recipient = temp_user

        # Create file path in admin's space (tgu2)
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        file_content = "Hello from owner!"

        # Step 1: Create file as root (simulating owner's file)
        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content), (
            "Failed to create test file"
        )

        # Step 2: Before sharing - recipient should NOT be able to read
        # (This may or may not fail depending on default policies)

        # Step 3: Share with recipient
        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
        share_resp = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [recipient["username"]],
                "with_groups": [],
            },
        )
        assert share_resp.status_code == 200, f"Share failed: {share_resp.text}"

        # Step 4: Verify recipient can read
        content = minio_files.read_as_user(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert content == file_content, (
            f"Recipient should be able to read shared file. Got: {content}"
        )

    def test_recipient_cannot_read_before_share(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Admin (tgu2) has a file in their workspace
            - Recipient tries to read before admin shares

        Expected:
            - Recipient cannot read the file (access denied)

        Why this matters:
            Access should only be granted through explicit sharing.
        """
        recipient = temp_user

        # Create file in admin's space
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, "private data")

        # Recipient should NOT be able to read
        can_read = minio_files.user_can_read(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert not can_read, "Recipient should NOT be able to read unshared file"


@pytest.mark.sharing
@pytest.mark.functional
class TestSharedFileWriteAccess:
    """Tests for read-write sharing permissions."""

    def test_recipient_can_write_to_shared_path(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares path with recipient
            - Recipient tries to write

        Expected:
            - Recipient CAN write to the shared path

        Why this matters:
            Sharing grants WRITE permission by design (not read-only).
        """
        recipient = temp_user

        # Create path in admin's space
        table_name = unique_table_name(admin_username)
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"

        # Ensure directory exists
        assert minio_files.create_file(DEFAULT_BUCKET, f"{file_key}.keep", "marker")

        # Share with recipient (grants WRITE permission)
        share_path = f"s3a://{DEFAULT_BUCKET}/{file_key}"
        share_resp = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [recipient["username"]],
                "with_groups": [],
            },
        )
        assert share_resp.status_code == 200

        # Recipient SHOULD be able to write (sharing grants WRITE permission)
        can_write = minio_files.user_can_write(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert can_write, "Recipient should be able to write to shared path"

    def test_recipient_cannot_write_to_readonly_share(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares path with recipient using read-only permission
            - Recipient tries to read and write

        Expected:
            - Recipient CAN read the shared file
            - Recipient CANNOT write to the shared path

        Why this matters:
            Read-only sharing should only grant read access, not write.
        """
        recipient = temp_user

        # Create path in admin's space
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        share_path_dir = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"

        # Create a file to read
        file_content = "read-only test data"
        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        # Share with recipient (READ-ONLY permission)
        share_resp = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path_dir,
                "with_users": [recipient["username"]],
                "with_groups": [],
                "permission": "read",  # READ-ONLY permission
            },
        )
        assert share_resp.status_code == 200

        # Recipient SHOULD be able to read
        content = minio_files.read_as_user(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert content == file_content, (
            f"Recipient should be able to read read-only shared file. Got: {content}"
        )

        # Recipient should NOT be able to write
        dir_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
        can_write = minio_files.user_can_write(
            DEFAULT_BUCKET,
            dir_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert not can_write, (
            "Recipient should NOT be able to write to read-only shared path"
        )


@pytest.mark.sharing
@pytest.mark.functional
class TestAccessRevocation:
    """Tests that access is properly revoked after unshare."""

    def test_access_revoked_after_unshare(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares with recipient
            - Recipient can read
            - Admin unshares
            - Recipient can no longer read

        Expected:
            - Access is revoked immediately after unshare

        Why this matters:
            Security requires timely access revocation.
        """
        recipient = temp_user

        # Create file
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, "shared data")

        # Share
        share_resp = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [recipient["username"]],
                "with_groups": [],
            },
        )
        assert share_resp.status_code == 200

        # Verify can read
        assert minio_files.user_can_read(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        ), "Should be able to read after share"

        # Unshare
        unshare_resp = api_client.post(
            "/sharing/unshare",
            headers=admin_headers,
            json={
                "path": share_path,
                "from_users": [recipient["username"]],
                "from_groups": [],
            },
        )
        assert unshare_resp.status_code == 200

        # Verify can NO LONGER read
        can_read = minio_files.user_can_read(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert not can_read, "Should NOT be able to read after unshare"


@pytest.mark.sharing
@pytest.mark.functional
class TestGroupSharingAccess:
    """Tests that group sharing grants access to all members."""

    # @pytest.mark.skip(
    #     reason="Flaky due to MinIO group policy propagation timing - needs investigation"
    # )
    def test_group_member_can_read_shared_file(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_group_with_members,
        minio_files,
    ):
        """
        Scenario:
            - Admin shares path with a group
            - Group member attempts to read

        Expected:
            - All group members can read the shared file

        Why this matters:
            Group sharing must work for all members, not just some.
        """
        group_name = temp_group_with_members["group_name"]
        member = temp_group_with_members["members"][0]

        # Create file in admin's space
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, "group shared data")

        # Share with group
        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
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

        # Verify group member can read
        content = minio_files.read_as_user(
            DEFAULT_BUCKET,
            file_key,
            member["access_key"],
            member["secret_key"],
        )
        assert content == "group shared data", (
            f"Group member should be able to read. Got: {content}"
        )


@pytest.mark.sharing
@pytest.mark.functional
@pytest.mark.smoke
class TestSharingFunctionalWorkflow:
    """Complete functional workflow test."""

    def test_complete_sharing_functional_workflow(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_user,
        minio_files,
    ):
        """
        Scenario:
            Complete workflow: create file → share → verify read → unshare → verify no access

        Expected:
            - All operations work correctly end-to-end

        Why this matters:
            End-to-end validation of the entire sharing lifecycle.
        """
        recipient = temp_user

        # Create file
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"
        file_content = "workflow test data"

        # Step 1: Create file
        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        # Step 2: Verify recipient cannot read (pre-share)
        assert not minio_files.user_can_read(
            DEFAULT_BUCKET, file_key, recipient["access_key"], recipient["secret_key"]
        )

        # Step 3: Share
        share_resp = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [recipient["username"]],
                "with_groups": [],
            },
        )
        assert share_resp.status_code == 200

        # Step 4: Verify recipient CAN read (post-share)
        content = minio_files.read_as_user(
            DEFAULT_BUCKET, file_key, recipient["access_key"], recipient["secret_key"]
        )
        assert content == file_content

        # Step 5: Unshare
        unshare_resp = api_client.post(
            "/sharing/unshare",
            headers=admin_headers,
            json={
                "path": share_path,
                "from_users": [recipient["username"]],
                "from_groups": [],
            },
        )
        assert unshare_resp.status_code == 200

        # Step 6: Verify recipient CANNOT read (post-unshare)
        assert not minio_files.user_can_read(
            DEFAULT_BUCKET, file_key, recipient["access_key"], recipient["secret_key"]
        )
