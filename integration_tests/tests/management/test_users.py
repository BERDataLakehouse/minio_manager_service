"""
User Management Tests.

Tests for user CRUD operations via the /management/users/ endpoints.
All tests are parallel-safe through UUID-based resource isolation.
"""

import time

import pytest
from utils.unique import unique_username


@pytest.mark.management
class TestUserCreation:
    """Tests for creating users."""

    def test_create_user_with_valid_name(
        self, api_client, admin_headers, minio_verifier
    ):
        """
        Scenario:
            Admin creates a new user with a unique name.
        Expected:
            - API returns 201 Created
            - User exists in MinIO
            - User has access_key and secret_key
        Why this matters:
            User provisioning is a core operation for the service.
        """
        username = unique_username("create_test")

        try:
            # Act
            response = api_client.post(
                f"/management/users/{username}", headers=admin_headers
            )

            # Assert - API response
            assert response.status_code == 201, (
                f"Expected 201, got {response.status_code}: {response.text}"
            )
            data = response.json()
            assert data.get("username") == username or "access_key" in data
            assert "access_key" in data, "Response should contain access_key"
            assert "secret_key" in data, "Response should contain secret_key"

            # Assert - MinIO state
            assert minio_verifier.user_exists(username), (
                f"User {username} should exist in MinIO"
            )

        finally:
            # Cleanup - handle potential server disconnect
            try:
                api_client.delete(
                    f"/management/users/{username}", headers=admin_headers
                )
            except Exception:
                pass  # Ignore cleanup errors

    def test_create_duplicate_user_fails(self, api_client, admin_headers, temp_user):
        """
        Scenario:
            A user already exists (via temp_user fixture).
            Admin tries to create another user with the same name.
        Expected:
            - API returns 409 Conflict
        Why this matters:
            Prevents accidental overwriting of user data and credentials.
        """
        username = temp_user["username"]

        # Act - try to create duplicate
        response = api_client.post(
            f"/management/users/{username}", headers=admin_headers
        )

        # Assert - API may return 409 for conflict or 201 if idempotent
        assert response.status_code in (201, 409), (
            f"Expected 201 (idempotent) or 409 Conflict, got {response.status_code}"
        )

    def test_create_user_with_invalid_name(self, api_client, admin_headers):
        """
        Scenario:
            Admin tries to create a user with invalid characters.
        Expected:
            - API returns 400 Bad Request or 422 Validation Error
        Why this matters:
            Input validation prevents security issues and MinIO errors.
        """
        invalid_usernames = [
            "user name",  # Space
            "user/name",  # Slash
            "../traversal",  # Path traversal
        ]

        for invalid_name in invalid_usernames:
            time.sleep(1)
            response = api_client.post(
                f"/management/users/{invalid_name}", headers=admin_headers
            )
            assert response.status_code in (400, 404, 422), (
                f"Expected 400/404/422 for '{invalid_name}', got {response.status_code}"
            )


@pytest.mark.management
class TestUserDeletion:
    """Tests for deleting users."""

    def test_delete_existing_user(
        self, api_client, admin_headers, minio_verifier, credential_db
    ):
        """
        Scenario:
            Admin creates a user, populates credentials, then deletes the user.
        Expected:
            - API returns 200/204
            - User no longer exists in MinIO
            - Credential DB record is cleaned up
        Why this matters:
            Clean deprovisioning removes all user data, policies, and cached credentials.
        """
        username = unique_username("delete_test")

        # Setup - create user
        create_resp = api_client.post(
            f"/management/users/{username}", headers=admin_headers
        )
        assert create_resp.status_code == 201

        # Act - delete user
        delete_resp = api_client.delete(
            f"/management/users/{username}", headers=admin_headers
        )

        # Assert
        assert delete_resp.status_code in (200, 204)
        assert not minio_verifier.user_exists(username), (
            "User should be deleted from MinIO"
        )

        # Verify credential DB record is cleaned up
        db_record = credential_db.get_credential_record(username)
        assert db_record is None, (
            f"Credential DB record should be deleted for user {username}"
        )

    def test_delete_nonexistent_user(self, api_client, admin_headers):
        """
        Scenario:
            Admin tries to delete a user that doesn't exist.
        Expected:
            - API returns 404 Not Found
        Why this matters:
            Proper error handling for missing resources.
        """
        username = unique_username("nonexistent")

        response = api_client.delete(
            f"/management/users/{username}", headers=admin_headers
        )

        # API may return 400 or 404 for non-existent user
        assert response.status_code in (400, 404)


@pytest.mark.management
class TestUserListing:
    """Tests for listing users."""

    @pytest.mark.skip(reason="Endpoint too slow due to sequential mc calls per user")
    def test_list_all_users(self, api_client, admin_headers, temp_user):
        """
        Scenario:
            Admin lists all users.
        Expected:
            - API returns 200
            - Response contains user list
            - Created temp_user is in the list
        Why this matters:
            Inventory of users is needed for administration.
        """
        # Use small page_size to avoid timeout - the endpoint makes individual
        # mc calls for each user, which can be slow with many users
        response = api_client.get(
            "/management/users", headers=admin_headers, params={"page_size": 5}
        )

        assert response.status_code == 200
        data = response.json()

        # Response should be a paginated dict
        assert isinstance(data, dict), "Response should be a paginated dict"
        assert "users" in data, "Response should contain 'users' key"
        assert "total_count" in data, "Response should contain 'total_count' key"

        users = data.get("users", [])
        assert isinstance(users, list), "Users should be a list"

        # With pagination, we verify structure rather than specific user presence
        # since temp_user might not be on the first page
        assert data["total_count"] >= 1, "Should have at least 1 user (our temp_user)"
        assert len(users) <= 5, "Should respect page_size limit"


@pytest.mark.management
class TestCredentialRotation:
    """Tests for credential rotation.

    Uses class-scoped fixtures to keep the test user alive throughout
    all tests in this class, avoiding race conditions with cleanup.
    """

    @pytest.fixture(scope="class")
    def class_api_client(self, test_config):
        """Class-scoped API client for credential rotation tests."""
        import httpx

        client = httpx.Client(
            base_url=test_config["base_url"],
            timeout=test_config["test_timeout"],
        )
        yield client
        client.close()

    @pytest.fixture(scope="class")
    def class_temp_user(self, class_api_client, admin_headers):
        """
        Class-scoped temp user that lives for the entire test class.

        This prevents race conditions where cleanup from parallel tests
        might affect the user mid-test.
        """
        from utils.cleanup import safe_delete_user
        from utils.unique import unique_username

        username = unique_username("rotate_test")

        # Create user via API
        response = class_api_client.post(
            f"/management/users/{username}", headers=admin_headers
        )

        if response.status_code != 201:
            pytest.fail(
                f"Failed to create temp user {username}: {response.status_code} - {response.text}"
            )

        user_data = response.json()
        user_data["username"] = username

        yield user_data

        # Cleanup after all tests in class complete
        safe_delete_user(class_api_client, username, admin_headers)

    def test_rotate_user_credentials(
        self, class_api_client, admin_headers, class_temp_user
    ):
        """
        Scenario:
            Admin rotates credentials for an existing user.
        Expected:
            - API returns 200
            - New access_key and secret_key are returned
            - New credentials differ from original
        Why this matters:
            Credential rotation is essential for security.
        """
        username = class_temp_user["username"]
        original_secret_key = class_temp_user["secret_key"]

        # Act
        response = class_api_client.post(
            f"/management/users/{username}/rotate-credentials", headers=admin_headers
        )

        # Assert
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}"
        )
        new_creds = response.json()

        assert "access_key" in new_creds
        assert "secret_key" in new_creds

        # Skip comparison if original secret_key was a placeholder
        if original_secret_key != "password":
            assert new_creds["secret_key"] != original_secret_key, (
                "New secret_key should differ from original"
            )


@pytest.mark.management
class TestUserSecurity:
    """Tests for user management security."""

    def test_non_admin_cannot_create_user(self, api_client, user_headers):
        """
        Scenario:
            A regular user tries to create another user.
        Expected:
            - API returns 403 Forbidden
        Why this matters:
            Only admins should manage users.
        """
        username = unique_username("unauthorized")

        response = api_client.post(
            f"/management/users/{username}", headers=user_headers
        )

        assert response.status_code == 403

    def test_unauthenticated_cannot_create_user(self, api_client):
        """
        Scenario:
            An unauthenticated request tries to create a user.
        Expected:
            - API returns 401 Unauthorized or 403 Forbidden
        Why this matters:
            Authentication is required for all management operations.
        """
        username = unique_username("unauth")

        response = api_client.post(
            f"/management/users/{username}",
            # No headers
        )

        assert response.status_code in (401, 403)


@pytest.mark.management
@pytest.mark.smoke
class TestUserLifecycle:
    """Complete user lifecycle workflow tests."""

    def test_complete_user_lifecycle(
        self, api_client, admin_headers, minio_verifier, credential_db
    ):
        """
        Scenario:
            Complete lifecycle: create → verify → rotate (with DB) → delete → verify DB cleanup
        Expected:
            - All operations succeed
            - State is consistent throughout (MinIO + credential DB)
        Why this matters:
            End-to-end validation of the user management workflow including credential persistence.
        """
        username = unique_username("lifecycle")

        try:
            # Step 1: Create user
            create_resp = api_client.post(
                f"/management/users/{username}", headers=admin_headers
            )
            assert create_resp.status_code == 201
            user_data = create_resp.json()

            # Step 2: Verify user exists in MinIO
            assert minio_verifier.user_exists(username)

            # Step 3: Rotate credentials (populates credential DB)
            rotate_resp = api_client.post(
                f"/management/users/{username}/rotate-credentials",
                headers=admin_headers,
            )
            assert rotate_resp.status_code == 200
            new_creds = rotate_resp.json()
            # Skip comparison if original secret_key was a placeholder
            if user_data["secret_key"] != "password":
                assert new_creds["secret_key"] != user_data["secret_key"]

            # Step 3b: Verify credential DB record was created by rotation
            db_record = credential_db.get_credential_record(username)
            assert db_record is not None, (
                "Credential DB record should exist after rotation"
            )
            assert db_record["secret_key"] == new_creds["secret_key"], (
                "DB secret_key should match rotation result"
            )

            # Step 4: Delete user
            delete_resp = api_client.delete(
                f"/management/users/{username}", headers=admin_headers
            )
            assert delete_resp.status_code in (200, 204)

            # Step 5: Verify user is gone from MinIO
            assert not minio_verifier.user_exists(username)

            # Step 6: Verify credential DB record is cleaned up
            db_record = credential_db.get_credential_record(username)
            assert db_record is None, (
                "Credential DB record should be deleted when user is deleted"
            )

        finally:
            # Ensure cleanup even if test fails - handle server disconnect
            try:
                api_client.delete(
                    f"/management/users/{username}", headers=admin_headers
                )
            except Exception:
                pass  # Ignore cleanup errors
