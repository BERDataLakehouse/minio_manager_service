"""
Workspace Information Tests.

Tests for workspace information endpoints.
These tests verify user-facing workspace data is correct.
"""

import pytest


@pytest.mark.workspaces
class TestWorkspaceOverview:
    """Tests for workspace overview endpoint."""

    def test_get_workspace_overview(self, api_client, user_headers, minio_verifier):
        """
        Scenario:
            Regular user requests their workspace overview.
        Expected:
            - API returns 200
            - Response contains home paths
            - Response contains groups
        Why this matters:
            Users need to know their workspace structure.
        """
        response = api_client.get("/workspaces/me", headers=user_headers)

        assert response.status_code == 200
        data = response.json()

        # Should contain workspace information
        assert "username" in data or "home_paths" in data or "groups" in data

    def test_workspace_requires_auth(self, api_client):
        """
        Scenario:
            Unauthenticated request to workspace endpoint.
        Expected:
            - API returns 401 or 403
        Why this matters:
            User data requires authentication.
        """
        response = api_client.get("/workspaces/me")
        assert response.status_code in (401, 403)


@pytest.mark.workspaces
class TestAccessiblePaths:
    """Tests for accessible paths endpoint."""

    def test_get_accessible_paths(self, api_client, user_headers):
        """
        Scenario:
            User requests their accessible paths.
        Expected:
            - API returns 200
            - Response is a list of paths
        Why this matters:
            Users need to know what data they can access.
        """
        response = api_client.get(
            "/workspaces/me/accessible-paths", headers=user_headers
        )

        assert response.status_code == 200
        data = response.json()

        # Should be a list or dict containing paths
        assert isinstance(data, (list, dict))


@pytest.mark.workspaces
class TestUserGroups:
    """Tests for user groups endpoint."""

    def test_get_user_groups(self, api_client, user_headers):
        """
        Scenario:
            User requests their group memberships.
        Expected:
            - API returns 200
            - Response contains group list
        Why this matters:
            Users need to know their group memberships.
        """
        response = api_client.get("/workspaces/me/groups", headers=user_headers)

        assert response.status_code == 200
        data = response.json()

        # Should contain groups
        assert isinstance(data, (list, dict))


@pytest.mark.workspaces
class TestUserPolicies:
    """Tests for user policies endpoint."""

    def test_get_user_policies(self, api_client, user_headers):
        """
        Scenario:
            User requests their policies.
        Expected:
            - API returns 200
            - Response contains policy information
        Why this matters:
            Users should be able to see their access policies.
        """
        response = api_client.get("/workspaces/me/policies", headers=user_headers)

        assert response.status_code == 200
        data = response.json()

        # Should contain policy info
        assert isinstance(data, (list, dict))


@pytest.mark.workspaces
@pytest.mark.smoke
class TestWorkspaceConsistency:
    """Tests for workspace information consistency."""

    def test_workspace_info_is_consistent(
        self, api_client, user_headers, minio_verifier
    ):
        """
        Scenario:
            Compare API response with MinIO state.
        Expected:
            - API data matches MinIO verification
        Why this matters:
            API must accurately reflect actual state.
        """
        # Get workspace from API
        api_resp = api_client.get("/workspaces/me", headers=user_headers)
        assert api_resp.status_code == 200
        api_data = api_resp.json()

        # Extract username from API response
        username = api_data.get("username")
        if not username:
            pytest.skip("API response doesn't include username")

        # Verify against MinIO
        assert minio_verifier.user_exists(username), (
            f"User {username} should exist in MinIO"
        )

        # Check groups match
        api_groups = set(api_data.get("groups", []))
        minio_groups = set(minio_verifier.get_user_groups(username))

        # They should match (or minio may have more internal groups)
        assert api_groups.issubset(minio_groups) or api_groups == minio_groups, (
            f"Groups mismatch: API={api_groups}, MinIO={minio_groups}"
        )


@pytest.mark.workspaces
class TestReadOnlyGroupAccess:
    """Tests for read-only group member access to workspace endpoints."""

    def _add_to_ro_group(self, api_client, admin_headers, group_name, username):
        """Add user to the read-only group variant and return the RO group name."""
        ro_group_name = f"{group_name}ro"
        add_resp = api_client.post(
            f"/management/groups/{ro_group_name}/members/{username}",
            headers=admin_headers,
        )
        assert add_resp.status_code in (200, 201, 204)
        return ro_group_name

    def _remove_from_ro_group(self, api_client, admin_headers, ro_group_name, username):
        """Remove user from RO group (best-effort cleanup)."""
        try:
            api_client.delete(
                f"/management/groups/{ro_group_name}/members/{username}",
                headers=admin_headers,
            )
        except Exception:
            pass

    def test_ro_member_can_access_group_workspace(
        self, api_client, admin_headers, user_headers, temp_group
    ):
        """
        Scenario:
            User is added to read-only group variant ({group}ro) and tries to access group workspace.
        Expected:
            - User can successfully access group workspace endpoint
            - Returns 200 with group information
        Why this matters:
            Read-only group members should have access to view group workspace information.
        """
        group_name = temp_group["group_name"]

        me_resp = api_client.get("/workspaces/me", headers=user_headers)
        assert me_resp.status_code == 200
        test_username = me_resp.json().get("username")

        ro_group_name = self._add_to_ro_group(
            api_client, admin_headers, group_name, test_username
        )

        try:
            workspace_resp = api_client.get(
                f"/workspaces/me/groups/{group_name}", headers=user_headers
            )
            assert workspace_resp.status_code == 200
            workspace_data = workspace_resp.json()
            assert workspace_data["group_name"] == group_name
        finally:
            self._remove_from_ro_group(
                api_client, admin_headers, ro_group_name, test_username
            )

    def test_ro_member_can_get_sql_warehouse_prefix(
        self, api_client, admin_headers, user_headers, temp_group
    ):
        """
        Scenario:
            User in read-only group ({group}ro) requests SQL warehouse prefix.
        Expected:
            - User can successfully get SQL warehouse prefix
            - Returns 200 with prefix path
        Why this matters:
            Read-only members need access to SQL warehouse prefix for queries.
        """
        group_name = temp_group["group_name"]

        me_resp = api_client.get("/workspaces/me", headers=user_headers)
        assert me_resp.status_code == 200
        test_username = me_resp.json().get("username")
        if not test_username:
            pytest.skip("Could not determine test user's username")

        ro_group_name = self._add_to_ro_group(
            api_client, admin_headers, group_name, test_username
        )

        try:
            prefix_resp = api_client.get(
                f"/workspaces/me/groups/{group_name}/sql-warehouse-prefix",
                headers=user_headers,
            )
            assert prefix_resp.status_code == 200
            prefix_data = prefix_resp.json()
            assert "sql_warehouse_prefix" in prefix_data
            assert group_name in prefix_data["sql_warehouse_prefix"]
        finally:
            self._remove_from_ro_group(
                api_client, admin_headers, ro_group_name, test_username
            )

    def test_ro_member_can_get_namespace_prefix(
        self, api_client, admin_headers, user_headers, temp_group
    ):
        """
        Scenario:
            User in read-only group ({group}ro) requests namespace prefix with tenant.
        Expected:
            - User can successfully get namespace prefix
            - Returns 200 with tenant namespace prefix
        Why this matters:
            Read-only members need namespace prefix for governance integration.
        """
        group_name = temp_group["group_name"]

        me_resp = api_client.get("/workspaces/me", headers=user_headers)
        assert me_resp.status_code == 200
        test_username = me_resp.json().get("username")
        if not test_username:
            pytest.skip("Could not determine test user's username")

        ro_group_name = self._add_to_ro_group(
            api_client, admin_headers, group_name, test_username
        )

        try:
            prefix_resp = api_client.get(
                f"/workspaces/me/namespace-prefix?tenant={group_name}",
                headers=user_headers,
            )
            assert prefix_resp.status_code == 200
            prefix_data = prefix_resp.json()
            assert "tenant_namespace_prefix" in prefix_data
            assert prefix_data["tenant"] == group_name
        finally:
            self._remove_from_ro_group(
                api_client, admin_headers, ro_group_name, test_username
            )

    def test_non_member_cannot_access_group_workspace(
        self, api_client, admin_headers, user_headers, temp_group
    ):
        """
        Scenario:
            User is NOT a member of either main or read-only group.
        Expected:
            - Access denied (400/403/404)
        Why this matters:
            Non-members should not access group information.
        """
        group_name = temp_group["group_name"]

        workspace_resp = api_client.get(
            f"/workspaces/me/groups/{group_name}", headers=user_headers
        )
        assert workspace_resp.status_code in (400, 403, 404)
