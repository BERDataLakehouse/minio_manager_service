"""
Input Validation Security Tests.

Tests that verify endpoints properly reject malicious or invalid input.
"""

import time

import pytest
from utils.paths import user_table_path


@pytest.mark.security
class TestPathTraversalPrevention:
    """Tests that path traversal attacks are blocked."""

    def test_share_path_traversal_blocked(self, api_client, admin_headers, temp_user):
        """
        Scenario:
            Attacker tries path traversal in share path.
        Expected:
            - API returns 400 or 422
        Why this matters:
            Path traversal could expose unauthorized data.
        """
        traversal_paths = [
            "s3a://cdm-lake/../../../etc/passwd",
            "s3a://cdm-lake/users-general-warehouse/../../admin/secrets",
            "s3a://cdm-lake/users-general-warehouse/../tenant-general-warehouse/kbase/",
        ]

        for path in traversal_paths:
            time.sleep(1)
            response = api_client.post(
                "/sharing/share",
                headers=admin_headers,
                json={
                    "path": path,
                    "with_users": [temp_user["username"]],
                    "with_groups": [],
                },
            )
            assert response.status_code in (400, 403, 422), (
                f"Path traversal '{path}' should be rejected, got {response.status_code}"
            )

    def test_unshare_path_traversal_blocked(self, api_client, admin_headers, temp_user):
        """
        Scenario:
            Attacker tries path traversal in unshare path.
        Expected:
            - API returns 400 or 422
        Why this matters:
            Prevents manipulation of unshare operations.
        """
        traversal_paths = [
            "s3a://cdm-lake/../other-bucket/data",
            "s3a://cdm-lake/users-general-warehouse/victim/../../../admin/",
        ]

        for path in traversal_paths:
            time.sleep(1)
            response = api_client.post(
                "/sharing/unshare",
                headers=admin_headers,
                json={
                    "path": path,
                    "from_users": [temp_user["username"]],
                    "from_groups": [],
                },
            )
            assert response.status_code in (400, 403, 422), (
                f"Path traversal '{path}' should be rejected"
            )


@pytest.mark.security
class TestInvalidPathFormat:
    """Tests that invalid path formats are rejected."""

    def test_non_s3_path_rejected(self, api_client, admin_headers, temp_user):
        """
        Scenario:
            User provides a non-S3 path format.
        Expected:
            - API returns 400 or 422
        Why this matters:
            Only valid S3 paths should be accepted.
        """
        invalid_paths = [
            "file:///etc/passwd",
            "http://example.com/data",
            "/local/filesystem/path",
            "just-a-string",
            "",
        ]

        for path in invalid_paths:
            time.sleep(1)
            response = api_client.post(
                "/sharing/share",
                headers=admin_headers,
                json={
                    "path": path,
                    "with_users": [temp_user["username"]],
                    "with_groups": [],
                },
            )
            assert response.status_code in (400, 422), (
                f"Invalid path '{path}' should be rejected, got {response.status_code}"
            )

    def test_wrong_bucket_rejected(self, api_client, admin_headers, temp_user):
        """
        Scenario:
            User tries to share from unauthorized bucket.
        Expected:
            - API returns 400 or 403
        Why this matters:
            Access should be restricted to allowed buckets.
        """
        wrong_bucket_paths = [
            "s3a://other-bucket/data/",
            "s3a://private-bucket/secrets/",
        ]

        for path in wrong_bucket_paths:
            time.sleep(1)
            response = api_client.post(
                "/sharing/share",
                headers=admin_headers,
                json={
                    "path": path,
                    "with_users": [temp_user["username"]],
                    "with_groups": [],
                },
            )
            # May be rejected with 400/403/422 depending on validation order
            assert response.status_code in (400, 403, 422), (
                f"Wrong bucket '{path}' should be rejected"
            )


@pytest.mark.security
class TestMaliciousInputRejected:
    """Tests that malicious payloads are rejected."""

    def test_sql_injection_in_username_rejected(self, api_client, admin_headers):
        """
        Scenario:
            Attacker tries SQL injection in username parameter.
        Expected:
            - API returns 400, 422, or handles safely
        Why this matters:
            Prevents SQL injection attacks.
        """
        malicious_usernames = [
            "'; DROP TABLE users; --",
            "admin'--",
            "1; DELETE FROM policies",
            "user' OR '1'='1",
        ]

        for username in malicious_usernames:
            time.sleep(1)
            response = api_client.post(
                f"/management/users/{username}",
                headers=admin_headers,
            )
            # Should either reject with validation error or handle safely
            # (create user with weird name that causes no harm)
            assert response.status_code in (400, 404, 422, 201), (
                f"SQL injection '{username}' should be handled safely"
            )

    def test_very_long_input_rejected(self, api_client, admin_headers):
        """
        Scenario:
            Attacker sends extremely long input to cause DoS.
        Expected:
            - API returns 400 or 422
        Why this matters:
            Prevents resource exhaustion attacks.
        """
        # 10KB username
        very_long_username = "x" * 10000

        response = api_client.post(
            f"/management/users/{very_long_username}",
            headers=admin_headers,
        )
        # Should be rejected early
        assert response.status_code in (400, 414, 422)

    def test_special_characters_in_path_handled(
        self, api_client, admin_headers, temp_user
    ):
        """
        Scenario:
            User provides path with special characters.
        Expected:
            - API either rejects or handles safely
        Why this matters:
            Special characters shouldn't break the system.
        """
        paths_with_special_chars = [
            "s3a://cdm-lake/users-general-warehouse/test/data<script>alert(1)</script>/",
            "s3a://cdm-lake/users-general-warehouse/test/data\x00null/",
            "s3a://cdm-lake/users-general-warehouse/test/data%00null/",
        ]

        for path in paths_with_special_chars:
            time.sleep(1)
            response = api_client.post(
                "/sharing/share",
                headers=admin_headers,
                json={
                    "path": path,
                    "with_users": [temp_user["username"]],
                    "with_groups": [],
                },
            )
            # Should either reject or handle safely (not crash)
            # 403 is valid - server may reject as forbidden
            assert response.status_code in (400, 403), (
                f"Special chars in '{path}' should be handled safely, got {response.status_code}"
            )


@pytest.mark.security
class TestEmptyAndMissingInput:
    """Tests for empty and missing required input."""

    def test_share_empty_recipients_rejected(
        self, api_client, admin_headers, temp_user
    ):
        """
        Scenario:
            User tries to share without specifying recipients.
        Expected:
            - API returns 400 or 403
        Why this matters:
            Sharing requires at least one recipient.
        """
        share_path = user_table_path(temp_user["username"])

        response = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "path": share_path,
                "with_users": [],
                "with_groups": [],
            },
        )
        assert response.status_code in (400, 403)

    def test_share_missing_path_rejected(self, api_client, admin_headers, temp_user):
        """
        Scenario:
            User tries to share without specifying path.
        Expected:
            - API returns 422 (validation error)
        Why this matters:
            Required fields must be enforced.
        """
        response = api_client.post(
            "/sharing/share",
            headers=admin_headers,
            json={
                "with_users": [temp_user["username"]],
                "with_groups": [],
            },
        )
        assert response.status_code == 422

    def test_create_group_with_invalid_name_rejected(self, api_client, admin_headers):
        """
        Scenario:
            Admin tries to create group with invalid name format.
        Expected:
            - API returns 400 (validation error for invalid group name)
        Why this matters:
            Group names must follow naming conventions (no underscores, lowercase only).
        """
        invalid_group_names = [
            "invalid_name",  # Underscores not allowed
            "InvalidName",  # Uppercase not allowed
            "123invalid",  # Must start with letter
        ]

        for group_name in invalid_group_names:
            time.sleep(1)
            response = api_client.post(
                f"/management/groups/{group_name}",
                headers=admin_headers,
            )
            # Should be rejected with 400 due to validation error
            assert response.status_code == 400, (
                f"Invalid group name '{group_name}' should be rejected with 400, "
                f"got {response.status_code}: {response.text}"
            )
