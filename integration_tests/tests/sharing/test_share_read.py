"""
Sharing Read Permission Tests.

Tests for sharing data with read-only permissions.
Focus on functional verification - actually testing that shared data is accessible.
"""

import time

import pytest
from utils.paths import DEFAULT_BUCKET, USERS_SQL_WAREHOUSE, user_table_path
from utils.unique import unique_file_name, unique_table_name


@pytest.mark.sharing
class TestShareReadWithUser:
    """Tests for sharing read access with individual users."""

    def test_share_path_with_user_read_permission(
        self, api_client, admin_headers, admin_username, temp_user, minio_files
    ):
        """
        Scenario:
            - Admin (tgu2) creates a file in their workspace
            - Admin shares the path with recipient (read permission)
            - Recipient attempts to read the file
        Expected:
            - API returns success
            - Recipient can actually read the file
        Why this matters:
            Basic sharing functionality must work correctly.
        """
        recipient = temp_user

        # Create a file in admin's workspace
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        file_content = "shared content for read test"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content), (
            "Failed to create test file"
        )

        # Path to share (directory level)
        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"

        # Act - Owner shares with recipient
        response = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [recipient["username"]],
                "with_groups": [],
            },
        )

        # Assert - API response
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}"
        )

        # Assert - Recipient can actually read the file
        content = minio_files.read_as_user(
            DEFAULT_BUCKET,
            file_key,
            recipient["access_key"],
            recipient["secret_key"],
        )
        assert content == file_content, (
            f"Recipient should be able to read shared file. Got: {content}"
        )

    def test_share_multiple_paths_with_user(
        self, api_client, admin_headers, admin_username, temp_user, minio_files
    ):
        """
        Scenario:
            Admin shares multiple paths with recipient.
        Expected:
            - Recipient can read files in all shared paths
        Why this matters:
            Batch sharing should work correctly.
        """
        recipient = temp_user

        # Create files in two different paths
        table_name1 = unique_table_name(admin_username)
        table_name2 = unique_table_name(admin_username)
        file_name1 = unique_file_name()
        file_name2 = unique_file_name()

        file_key1 = (
            f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name1}.db/{file_name1}"
        )
        file_key2 = (
            f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name2}.db/{file_name2}"
        )
        file_content1 = "content in path 1"
        file_content2 = "content in path 2"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key1, file_content1)
        assert minio_files.create_file(DEFAULT_BUCKET, file_key2, file_content2)

        path1 = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name1}.db/"
        path2 = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name2}.db/"

        # Share first path
        resp1 = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": path1,
                "with_users": [recipient["username"]],
                "with_groups": [],
            },
        )
        assert resp1.status_code == 200

        # Share second path
        resp2 = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": path2,
                "with_users": [recipient["username"]],
                "with_groups": [],
            },
        )
        assert resp2.status_code == 200

        # Verify recipient can read from BOTH paths
        content1 = minio_files.read_as_user(
            DEFAULT_BUCKET, file_key1, recipient["access_key"], recipient["secret_key"]
        )
        assert content1 == file_content1, f"Should read path1. Got: {content1}"

        content2 = minio_files.read_as_user(
            DEFAULT_BUCKET, file_key2, recipient["access_key"], recipient["secret_key"]
        )
        assert content2 == file_content2, f"Should read path2. Got: {content2}"


@pytest.mark.sharing
class TestShareReadWithGroup:
    """Tests for sharing read access with groups."""

    def test_share_path_with_group(
        self,
        api_client,
        admin_headers,
        admin_username,
        temp_group_with_members,
        minio_files,
    ):
        """
        Scenario:
            - Admin creates a file
            - Admin shares the path with a group
            - Group member attempts to read
        Expected:
            - Group members can actually read the file
        Why this matters:
            Group-based sharing enables team collaboration.
        """
        group_name = temp_group_with_members["group_name"]
        member = temp_group_with_members["members"][0]

        # Create a file in admin's workspace
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        file_content = "group shared content"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"

        # Act - Share with group
        response = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [],
                "with_groups": [group_name],
            },
        )

        # Assert - API response
        assert response.status_code == 200

        # Assert - Group member can actually read the file
        content = minio_files.read_as_user(
            DEFAULT_BUCKET,
            file_key,
            member["access_key"],
            member["secret_key"],
        )
        assert content == file_content, (
            f"Group member should be able to read shared file. Got: {content}"
        )


@pytest.mark.sharing
class TestUnshare:
    """Tests for removing shared access."""

    def test_unshare_from_user(
        self, api_client, admin_headers, admin_username, temp_user, minio_files
    ):
        """
        Scenario:
            - Admin shares a path with recipient
            - Recipient can read the file
            - Admin unshares the path
            - Recipient can no longer read the file
        Expected:
            - Recipient loses actual file access
        Why this matters:
            Access revocation must work correctly for security.
        """
        recipient = temp_user

        # Create a file in admin's workspace
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        file_content = "unshare test content"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"

        # Setup - Share first
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

        # Verify recipient CAN read after share
        assert minio_files.user_can_read(
            DEFAULT_BUCKET, file_key, recipient["access_key"], recipient["secret_key"]
        ), "Recipient should be able to read after share"

        # Act - Unshare
        unshare_resp = api_client.post(
            "/sharing/unshare",
            headers=admin_headers,
            json={
                "path": share_path,
                "from_users": [recipient["username"]],
                "from_groups": [],
            },
        )

        # Assert - API response
        assert unshare_resp.status_code == 200

        # Assert - Recipient can NO LONGER read
        can_read = minio_files.user_can_read(
            DEFAULT_BUCKET, file_key, recipient["access_key"], recipient["secret_key"]
        )
        assert not can_read, "Recipient should NOT be able to read after unshare"


@pytest.mark.sharing
class TestSharingValidation:
    """Tests for sharing input validation."""

    def test_share_with_invalid_path_format(
        self, api_client, admin_headers, admin_username
    ):
        """
        Scenario:
            User tries to share with an invalid path format.
        Expected:
            - API returns 400 or 422
        Why this matters:
            Input validation prevents security issues.
        """
        invalid_paths = [
            "not-an-s3-path",
            "file:///local/path",
            "../traversal/attack",
        ]

        for invalid_path in invalid_paths:
            time.sleep(1)
            response = api_client.post(
                "/sharing/share",
                headers=admin_headers,
                json={
                    "path": invalid_path,
                    "with_users": [admin_username],  # Use admin as recipient
                    "with_groups": [],
                },
            )
            assert response.status_code in (400, 422), (
                f"Expected 400/422 for path '{invalid_path}', got {response.status_code}"
            )

    def test_share_with_empty_recipients(
        self, api_client, admin_headers, admin_username
    ):
        """
        Scenario:
            User tries to share without specifying recipients.
        Expected:
            - API returns 200 (treats as successful no-op)
        Why this matters:
            Empty recipients list is allowed but results in no sharing.
        """
        share_path = user_table_path(admin_username)

        response = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [],
                "with_groups": [],
            },
        )

        # API allows empty recipients (no-op, but successful)
        assert response.status_code == 200
        # Verify that no one was shared with
        data = response.json()
        assert len(data.get("shared_with_users", [])) == 0
        assert len(data.get("shared_with_groups", [])) == 0


@pytest.mark.sharing
class TestSharingSecurity:
    """Tests for sharing security constraints."""

    def test_sharing_requires_authentication(self, api_client, admin_username):
        """
        Scenario:
            Unauthenticated request tries to share.
        Expected:
            - API returns 401 or 403
        Why this matters:
            Sharing requires authentication.
        """
        share_path = user_table_path(admin_username)

        response = api_client.post(
            "/sharing/share",
            # No headers
            json={
                "path": share_path,
                "with_users": ["someone"],
                "with_groups": [],
            },
        )

        assert response.status_code in (401, 403)

    def test_path_traversal_attack_blocked(
        self, api_client, admin_headers, admin_username
    ):
        """
        Scenario:
            Attacker tries path traversal in share path.
        Expected:
            - API rejects the request
        Why this matters:
            Security boundary must prevent directory traversal.
        """
        traversal_paths = [
            "s3a://cdm-lake/../../../etc/passwd",
            "s3a://cdm-lake/users-general-warehouse/../../other-bucket/sensitive",
        ]

        for path in traversal_paths:
            time.sleep(1)
            response = api_client.post(
                "/sharing/share",
                headers=admin_headers,
                json={
                    "path": path,
                    "with_users": [admin_username],  # Use admin as recipient
                    "with_groups": [],
                },
            )
            # Should be rejected
            assert response.status_code in (400, 403, 422), (
                f"Path traversal '{path}' should be rejected"
            )


@pytest.mark.sharing
@pytest.mark.smoke
class TestSharingWorkflow:
    """Complete sharing workflow tests."""

    def test_complete_sharing_workflow(
        self, api_client, admin_headers, admin_username, temp_user, minio_files
    ):
        """
        Scenario:
            Complete workflow: create file → share → verify read → unshare → verify no access
        Expected:
            - Sharing grants actual file access
            - Unsharing revokes actual file access
        Why this matters:
            End-to-end validation of the sharing workflow with real file operations.
        """
        recipient = temp_user

        # Create a file in admin's workspace
        table_name = unique_table_name(admin_username)
        file_name = unique_file_name()
        file_key = f"{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/{file_name}"
        file_content = "workflow test data"

        assert minio_files.create_file(DEFAULT_BUCKET, file_key, file_content)

        share_path = f"s3a://{DEFAULT_BUCKET}/{USERS_SQL_WAREHOUSE}/{admin_username}/{table_name}.db/"

        # Step 1: Verify recipient CANNOT read before share
        assert not minio_files.user_can_read(
            DEFAULT_BUCKET, file_key, recipient["access_key"], recipient["secret_key"]
        ), "Recipient should NOT be able to read before share"

        # Step 2: Share
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

        # Step 3: Verify recipient CAN read after share
        content = minio_files.read_as_user(
            DEFAULT_BUCKET, file_key, recipient["access_key"], recipient["secret_key"]
        )
        assert content == file_content, (
            f"Recipient should be able to read after share. Got: {content}"
        )

        # Step 4: Unshare
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

        # Step 5: Verify recipient CANNOT read after unshare
        can_read = minio_files.user_can_read(
            DEFAULT_BUCKET, file_key, recipient["access_key"], recipient["secret_key"]
        )
        assert not can_read, "Recipient should NOT be able to read after unshare"
