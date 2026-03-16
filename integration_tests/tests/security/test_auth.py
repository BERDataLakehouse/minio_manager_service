"""
Authentication Security Tests.

Tests that verify endpoints properly enforce authentication requirements.
"""

import pytest


@pytest.mark.security
class TestManagementAuthRequired:
    """Tests that management endpoints require admin authentication."""

    def test_list_users_requires_admin(self, api_client, user_headers):
        """
        Scenario:
            Regular user tries to access admin-only list users endpoint.
        Expected:
            - API returns 403 Forbidden
        Why this matters:
            Admin endpoints must not be accessible to regular users.
        """
        response = api_client.get("/management/users", headers=user_headers)
        assert response.status_code == 403

    def test_create_user_requires_admin(self, api_client, user_headers):
        """
        Scenario:
            Regular user tries to create a new user.
        Expected:
            - API returns 403 Forbidden
        Why this matters:
            User creation is an admin-only operation.
        """
        response = api_client.post(
            "/management/users/should_not_exist",
            headers=user_headers,
        )
        assert response.status_code == 403

    def test_delete_user_requires_admin(self, api_client, user_headers):
        """
        Scenario:
            Regular user tries to delete a user.
        Expected:
            - API returns 403 Forbidden
        Why this matters:
            User deletion is an admin-only operation.
        """
        response = api_client.delete(
            "/management/users/anyone",
            headers=user_headers,
        )
        assert response.status_code == 403

    def test_list_groups_requires_admin(self, api_client, user_headers):
        """
        Scenario:
            Regular user tries to list groups.
        Expected:
            - API returns 403 Forbidden
        Why this matters:
            Group listing is an admin-only operation.
        """
        response = api_client.get("/management/groups", headers=user_headers)
        assert response.status_code == 403

    def test_create_group_requires_admin(self, api_client, user_headers):
        """
        Scenario:
            Regular user tries to create a group.
        Expected:
            - API returns 403 Forbidden
        Why this matters:
            Group creation is an admin-only operation.
        """
        response = api_client.post(
            "/management/groups/should_not_exist",
            headers=user_headers,
            json={"members": []},
        )
        assert response.status_code == 403


@pytest.mark.security
class TestEndpointAuthRequired:
    """Tests that endpoints require authentication."""

    def test_workspace_requires_auth(self, api_client):
        """
        Scenario:
            Unauthenticated request to workspace endpoint.
        Expected:
            - API returns 401 Unauthorized
        Why this matters:
            Workspace info requires authentication.
        """
        response = api_client.get("/workspaces/me")
        assert response.status_code == 401

    def test_credentials_requires_auth(self, api_client):
        """
        Scenario:
            Unauthenticated request to credentials endpoint.
        Expected:
            - API returns 401 Unauthorized
        Why this matters:
            Credentials must not be exposed without auth.
        """
        response = api_client.get("/credentials/")
        assert response.status_code == 401

    def test_sharing_requires_auth(self, api_client):
        """
        Scenario:
            Unauthenticated request to share endpoint.
        Expected:
            - API returns 401 Unauthorized
        Why this matters:
            Sharing operations require authentication.
        """
        response = api_client.post(
            "/sharing/share",
            json={
                "path": "s3a://cdm-lake/test/",
                "with_users": ["someone"],
                "with_groups": [],
            },
        )
        assert response.status_code == 401


@pytest.mark.security
class TestInvalidTokenRejected:
    """Tests that invalid tokens are rejected."""

    def test_invalid_token_rejected(self, api_client):
        """
        Scenario:
            Request with invalid/malformed token.
        Expected:
            - API returns 401 Unauthorized
        Why this matters:
            Invalid tokens must not grant access.
        """
        invalid_headers = {
            "Authorization": "Bearer invalid_token_12345",
            "Content-Type": "application/json",
        }
        response = api_client.get("/workspaces/me", headers=invalid_headers)
        assert response.status_code == 401

    def test_expired_token_rejected(self, api_client):
        """
        Scenario:
            Request with expired token format.
        Expected:
            - API returns 401 Unauthorized
        Why this matters:
            Expired tokens must not grant access.
        """
        # Using a malformed JWT-like token
        expired_headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxfQ.expired",
            "Content-Type": "application/json",
        }
        response = api_client.get("/workspaces/me", headers=expired_headers)
        assert response.status_code == 401

    def test_missing_bearer_prefix_rejected(self, api_client, test_config):
        """
        Scenario:
            Request with token but missing 'Bearer' prefix.
        Expected:
            - API returns 401 Unauthorized
        Why this matters:
            Token format must be strictly validated.
        """
        if not test_config.get("user_token"):
            pytest.skip("No user token configured")

        bad_headers = {
            "Authorization": test_config["user_token"],  # Missing "Bearer "
            "Content-Type": "application/json",
        }
        response = api_client.get("/workspaces/me", headers=bad_headers)
        assert response.status_code == 401
