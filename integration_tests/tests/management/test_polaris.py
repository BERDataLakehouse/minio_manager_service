# """
# Polaris Integration Tests — Full Lifecycle Verification.

# These tests exercise the complete MinIO ↔ Polaris synchronization lifecycle:

#   1. User provisioning  — Polaris principal + personal catalog are created
#   2. Tenant creation    — Polaris tenant catalog + roles are created
#   3. Member add/remove  — principal-role assignments match MinIO group membership
#   4. Read-only groups   — `fooro_member` role assigned, not the writer role
#   5. Deletion cascade   — deleting a group/user removes Polaris resources

# Each test makes assertions against BOTH MinIO (via `minio_verifier`) and
# Polaris (via `polaris_verifier`) to confirm they stay in sync.

# The tests are guarded by `pytest.mark.polaris` so they can be selectively
# run or skipped when Polaris is not available.

# Run with:
#     cd integration_tests
#     pytest tests/management/test_polaris.py -v
# """

# import time
# import pytest

# from utils.unique import unique_group_name, unique_username  # type: ignore


# # ---------------------------------------------------------------------------
# # Helper: re-try a boolean condition for up to `timeout` seconds.
# # Polaris is eventually consistent after MinIO API calls.
# # ---------------------------------------------------------------------------
# def wait_for(condition_fn, timeout: int = 15, interval: float = 1.0) -> bool:
#     """Poll a boolean callable until it returns True or timeout expires."""
#     deadline = time.monotonic() + timeout
#     while time.monotonic() < deadline:
#         if condition_fn():
#             return True
#         time.sleep(interval)
#     return False


# # ---------------------------------------------------------------------------
# # Pytest mark for filtering
# # ---------------------------------------------------------------------------
# pytestmark = pytest.mark.polaris


# # ===========================================================================
# # 1. User Lifecycle — provisioning, then deletion
# # ===========================================================================


# @pytest.mark.management
# class TestUserPolarisLifecycle:
#     """Verify that user provisioning and deletion keeps MinIO and Polaris in sync."""

#     def test_provision_user_creates_polaris_assets(
#         self, api_client, admin_headers, temp_user, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         A temp user is created via the MinIO Manager API.
#         Then, `/polaris/user_provision/{username}` is called to bootstrap
#         their Polaris environment.

#         Expected — MinIO
#         ----------------
#         - User exists in MinIO.

#         Expected — Polaris (must match MinIO)
#         -------------------------------------
#         - Principal `{username}` exists.
#         - Personal catalog `user_{username}` exists.
#         - Principal role `{username}_role` exists.
#         - Role `{username}_role` is assigned to principal `{username}`.

#         Why this matters
#         ----------------
#         Full-stack onboarding must set up both systems atomically; if either
#         fails the user cannot launch Spark.
#         """
#         username = temp_user["username"]

#         # ---- MinIO side ----
#         assert minio_verifier.user_exists(username), (
#             f"User {username} should exist in MinIO"
#         )

#         # ---- Polaris provisioning ----
#         resp = api_client.post(
#             f"/polaris/user_provision/{username}",
#             headers=admin_headers,
#         )
#         assert resp.status_code == 200, f"Polaris provision failed: {resp.text}"

#         # ---- Polaris side ----
#         assert wait_for(lambda: polaris_verifier.principal_exists(username)), (
#             f"Principal '{username}' should exist in Polaris after provisioning"
#         )
#         assert wait_for(lambda: polaris_verifier.catalog_exists(f"user_{username}")), (
#             f"Personal catalog 'user_{username}' should exist in Polaris"
#         )
#         principal_role = f"{username}_role"
#         assert wait_for(
#             lambda: polaris_verifier.principal_role_exists(principal_role)
#         ), f"Principal role '{principal_role}' should exist in Polaris"
#         assert wait_for(
#             lambda: polaris_verifier.is_role_assigned_to_principal(
#                 username, principal_role
#             )
#         ), f"Role '{principal_role}' should be assigned to principal '{username}'"

#     def test_delete_user_removes_polaris_principal(
#         self, api_client, admin_headers, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         A fully-provisioned user is deleted via the MinIO Manager API.

#         Expected — MinIO
#         ----------------
#         - User no longer exists in MinIO.

#         Expected — Polaris (must match MinIO)
#         -------------------------------------
#         - Principal `{username}` is deleted from Polaris.

#         Why this matters
#         ----------------
#         Access must be fully revoked across both systems on user deletion.
#         """
#         # Create and provision a dedicated user for this test
#         username = unique_username("poldelete")

#         create_resp = api_client.post(
#             f"/management/users/{username}", headers=admin_headers
#         )
#         assert create_resp.status_code in (200, 201)

#         api_client.post(f"/polaris/user_provision/{username}", headers=admin_headers)

#         # Verify user + principal exist
#         assert minio_verifier.user_exists(username)
#         assert wait_for(lambda: polaris_verifier.principal_exists(username))

#         # ---- Delete ----
#         del_resp = api_client.delete(
#             f"/management/users/{username}", headers=admin_headers
#         )
#         assert del_resp.status_code in (200, 204)

#         # MinIO
#         assert not minio_verifier.user_exists(username), (
#             "User should be removed from MinIO"
#         )

#         # Polaris
#         assert wait_for(
#             lambda: not polaris_verifier.principal_exists(username), timeout=20
#         ), f"Principal '{username}' should be removed from Polaris after user deletion"


# # ===========================================================================
# # 2. Tenant (Group) Lifecycle — creation, then deletion
# # ===========================================================================


# @pytest.mark.management
# class TestTenantPolarisLifecycle:
#     """Verify that group creation and deletion keeps MinIO and Polaris in sync."""

#     def test_create_tenant_creates_polaris_catalog(
#         self, api_client, admin_headers, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         Admin creates a new group (tenant) via the MinIO Manager API.

#         Expected — MinIO
#         ----------------
#         - Group exists in MinIO.
#         - Read/write and read-only group policies are attached.

#         Expected — Polaris (must match MinIO)
#         -------------------------------------
#         - Tenant catalog `tenant_{group_name}` exists.
#         - Writer principal role `{group_name}_member` exists.
#         - Reader principal role `{group_name}ro_member` exists.

#         Why this matters
#         ----------------
#         Every MinIO tenant must have a corresponding Polaris Iceberg catalog
#         for Spark SQL isolation.
#         """
#         group_name = unique_group_name("poltenant")

#         try:
#             # ---- Create tenant ----
#             resp = api_client.post(
#                 f"/management/groups/{group_name}", headers=admin_headers
#             )
#             assert resp.status_code in (200, 201), (
#                 f"Failed to create group: {resp.text}"
#             )

#             # MinIO
#             assert minio_verifier.group_exists(group_name), (
#                 "Group should exist in MinIO"
#             )

#             # Polaris
#             catalog_name = f"tenant_{group_name}"
#             assert wait_for(lambda: polaris_verifier.catalog_exists(catalog_name)), (
#                 f"Tenant catalog '{catalog_name}' should exist in Polaris"
#             )
#             writer_role = f"{group_name}_member"
#             assert wait_for(
#                 lambda: polaris_verifier.principal_role_exists(writer_role)
#             ), f"Writer principal role '{writer_role}' should exist in Polaris"
#             reader_role = f"{group_name}ro_member"
#             assert wait_for(
#                 lambda: polaris_verifier.principal_role_exists(reader_role)
#             ), f"Reader principal role '{reader_role}' should exist in Polaris"

#         finally:
#             api_client.delete(f"/management/groups/{group_name}", headers=admin_headers)

#     def test_delete_tenant_removes_polaris_catalog(
#         self, api_client, admin_headers, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         Admin creates then deletes a group (tenant).

#         Expected — MinIO
#         ----------------
#         - Group no longer exists in MinIO.

#         Expected — Polaris (must match MinIO)
#         -------------------------------------
#         - Tenant catalog is deleted.
#         - Writer and reader principal roles are deleted.

#         Why this matters
#         ----------------
#         Orphaned catalogs in Polaris would accumulate and confuse users.
#         """
#         group_name = unique_group_name("poldelete")

#         resp = api_client.post(
#             f"/management/groups/{group_name}", headers=admin_headers
#         )
#         assert resp.status_code in (200, 201)

#         catalog_name = f"tenant_{group_name}"
#         assert wait_for(lambda: polaris_verifier.catalog_exists(catalog_name)), (
#             "Catalog should exist before deletion"
#         )

#         # Remove all members (including auto-added creator) before deleting group
#         members = minio_verifier.get_group_members(group_name)
#         for m in members:
#             time.sleep(0.5)
#             api_client.delete(
#                 f"/management/groups/{group_name}/members/{m}", headers=admin_headers
#             )

#         # ---- Delete tenant ----
#         del_resp = api_client.delete(
#             f"/management/groups/{group_name}", headers=admin_headers
#         )
#         assert del_resp.status_code in (200, 204)

#         # MinIO
#         assert not minio_verifier.group_exists(group_name), (
#             "Group should be removed from MinIO"
#         )

#         # Polaris
#         assert wait_for(
#             lambda: not polaris_verifier.catalog_exists(catalog_name), timeout=20
#         ), f"Tenant catalog '{catalog_name}' should be removed from Polaris"
#         assert wait_for(
#             lambda: not polaris_verifier.principal_role_exists(f"{group_name}_member"),
#             timeout=20,
#         ), "Writer role should be removed from Polaris"
#         assert wait_for(
#             lambda: (
#                 not polaris_verifier.principal_role_exists(f"{group_name}ro_member")
#             ),
#             timeout=20,
#         ), "Reader role should be removed from Polaris"


# # ===========================================================================
# # 3. Member Add / Remove — role sync
# # ===========================================================================


# @pytest.mark.management
# class TestMemberPolarisSync:
#     """Verify that adding/removing members keeps MinIO group and Polaris role in sync."""

#     def test_add_member_to_rw_group_grants_polaris_role(
#         self, api_client, admin_headers, temp_user, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         Admin adds a provisioned user to a read/write group.

#         Expected — MinIO
#         ----------------
#         - User is now a member of the group.

#         Expected — Polaris (must match MinIO)
#         -------------------------------------
#         - User's principal has the writer role `{group_name}_member` assigned.

#         Why this matters
#         ----------------
#         Members of a group must be able to read/write the shared Iceberg catalog.
#         """
#         username = temp_user["username"]
#         group_name = unique_group_name("polrwmember")

#         try:
#             # Setup: create group + provision user
#             api_client.post(f"/management/groups/{group_name}", headers=admin_headers)
#             api_client.post(
#                 f"/polaris/user_provision/{username}", headers=admin_headers
#             )
#             assert wait_for(lambda: polaris_verifier.principal_exists(username))

#             # ---- Add member ----
#             resp = api_client.post(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert resp.status_code in (200, 201)

#             # MinIO
#             assert username in minio_verifier.get_group_members(group_name)

#             # Polaris
#             writer_role = f"{group_name}_member"
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, writer_role
#                 )
#             ), (
#                 f"Writer role '{writer_role}' should be assigned to '{username}' in Polaris"
#             )

#         finally:
#             api_client.delete(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             api_client.delete(f"/management/groups/{group_name}", headers=admin_headers)

#     def test_remove_member_from_rw_group_revokes_polaris_role(
#         self, api_client, admin_headers, temp_user, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         A user is added to a group, then removed.

#         Expected — MinIO
#         ----------------
#         - User is no longer a member of the group.

#         Expected — Polaris (must match MinIO)
#         -------------------------------------
#         - The writer role `{group_name}_member` is unassigned from the principal.

#         Why this matters
#         ----------------
#         Revocation must propagate across both systems immediately.
#         """
#         username = temp_user["username"]
#         group_name = unique_group_name("polrevoke")

#         try:
#             # Setup
#             api_client.post(f"/management/groups/{group_name}", headers=admin_headers)
#             api_client.post(
#                 f"/polaris/user_provision/{username}", headers=admin_headers
#             )
#             assert wait_for(lambda: polaris_verifier.principal_exists(username))

#             api_client.post(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             writer_role = f"{group_name}_member"
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, writer_role
#                 )
#             ), "Role should be assigned before removal"

#             # ---- Remove member ----
#             remove_resp = api_client.delete(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert remove_resp.status_code in (200, 204)

#             # MinIO
#             assert username not in minio_verifier.get_group_members(group_name)

#             # Polaris
#             assert wait_for(
#                 lambda: (
#                     not polaris_verifier.is_role_assigned_to_principal(
#                         username, writer_role
#                     )
#                 ),
#                 timeout=20,
#             ), (
#                 f"Writer role '{writer_role}' should be REVOKED from '{username}' in Polaris"
#             )

#         finally:
#             api_client.delete(f"/management/groups/{group_name}", headers=admin_headers)

#     def test_add_member_to_ro_group_grants_reader_role(
#         self, api_client, admin_headers, temp_user, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         Admin adds a user to the READ-ONLY variant of a group
#         (the MinIO group whose name ends in ``ro``).

#         Expected — MinIO
#         ----------------
#         - User is a member of `{base_group}ro`.

#         Expected — Polaris (must match MinIO)
#         -------------------------------------
#         - User's principal has the READER role `{base_group}ro_member` assigned.
#         - User does NOT have the writer role `{base_group}_member` assigned.

#         Why this matters
#         ----------------
#         Read-only group members must get read-only Polaris access; assigning the
#         wrong role would grant write access to the shared Iceberg catalog.
#         """
#         username = temp_user["username"]
#         base_group = unique_group_name("polro")
#         ro_group = f"{base_group}ro"

#         try:
#             # Setup: create rw group (which also creates the ro group)
#             api_client.post(f"/management/groups/{base_group}", headers=admin_headers)
#             assert wait_for(
#                 lambda: polaris_verifier.catalog_exists(f"tenant_{base_group}")
#             )

#             # Provision user
#             api_client.post(
#                 f"/polaris/user_provision/{username}", headers=admin_headers
#             )
#             assert wait_for(lambda: polaris_verifier.principal_exists(username))

#             # ---- Add to RO group ----
#             resp = api_client.post(
#                 f"/management/groups/{ro_group}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert resp.status_code in (200, 201)

#             # MinIO
#             assert username in minio_verifier.get_group_members(ro_group)

#             # Polaris — reader role granted
#             reader_role = f"{base_group}ro_member"
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, reader_role
#                 )
#             ), f"Reader role '{reader_role}' should be assigned in Polaris"

#             # Polaris — writer role NOT granted
#             writer_role = f"{base_group}_member"
#             roles = polaris_verifier.get_roles_for_principal(username)
#             assert writer_role not in roles, (
#                 f"Writer role '{writer_role}' must NOT be assigned for RO group member"
#             )

#         finally:
#             api_client.delete(
#                 f"/management/groups/{ro_group}/members/{username}",
#                 headers=admin_headers,
#             )
#             api_client.delete(f"/management/groups/{base_group}", headers=admin_headers)

#     def test_remove_member_from_ro_group_revokes_reader_role(
#         self, api_client, admin_headers, temp_user, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         A user is added to the read-only group, then removed.

#         Expected — Polaris
#         ------------------
#         - The reader role `{group_name}ro_member` is revoked from the principal.

#         Why this matters
#         ----------------
#         Read-only access must be revocable without affecting writer access.
#         """
#         username = temp_user["username"]
#         base_group = unique_group_name("polrorev")
#         ro_group = f"{base_group}ro"

#         try:
#             api_client.post(f"/management/groups/{base_group}", headers=admin_headers)
#             api_client.post(
#                 f"/polaris/user_provision/{username}", headers=admin_headers
#             )
#             assert wait_for(lambda: polaris_verifier.principal_exists(username))

#             # Add first
#             api_client.post(
#                 f"/management/groups/{ro_group}/members/{username}",
#                 headers=admin_headers,
#             )
#             reader_role = f"{base_group}ro_member"
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, reader_role
#                 )
#             ), "Reader role should be assigned before removal"

#             # ---- Remove ----
#             remove_resp = api_client.delete(
#                 f"/management/groups/{ro_group}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert remove_resp.status_code in (200, 204)

#             # MinIO
#             assert username not in minio_verifier.get_group_members(ro_group)

#             # Polaris
#             assert wait_for(
#                 lambda: (
#                     not polaris_verifier.is_role_assigned_to_principal(
#                         username, reader_role
#                     )
#                 ),
#                 timeout=20,
#             ), f"Reader role '{reader_role}' should be REVOKED in Polaris"

#         finally:
#             api_client.delete(f"/management/groups/{base_group}", headers=admin_headers)


# # ===========================================================================
# # 4. Complete end-to-end lifecycle smoke test
# # ===========================================================================


# @pytest.mark.management
# @pytest.mark.smoke
# class TestFullPolarisLifecycle:
#     """
#     Full lifecycle smoke test combining user provisioning, tenant creation,
#     membership changes, and finally deletion — with MinIO + Polaris checked
#     at every step.
#     """

#     def test_full_lifecycle(
#         self,
#         api_client,
#         admin_headers,
#         polaris_verifier,
#         minio_verifier,
#     ):
#         """
#         Scenario (step-by-step)
#         -----------------------
#         1.  Create user in MinIO.
#         2.  Provision user in Polaris.
#         3.  Create group (tenant) — check MinIO and Polaris resources.
#         4.  Add user to R/W group — check MinIO membership and Polaris role.
#         5.  Add user to RO group  — check MinIO membership and Polaris RO role.
#         6.  Remove user from R/W group — MinIO + Polaris reflect the removal.
#         7.  Remove user from RO group  — MinIO + Polaris reflect the removal.
#         8.  Delete group   — Polaris catalog + roles cleaned up.
#         9.  Delete user    — Polaris principal cleaned up.

#         All MinIO and Polaris assertions are paired so any divergence between
#         the two systems is caught immediately.

#         Why this matters
#         ----------------
#         This is the canonical end-to-end validation of the integration.
#         If this test passes, the system is production-ready for Iceberg access control.
#         """
#         username = unique_username("pollifecycle")
#         group_name = unique_group_name("pollifecycle")
#         ro_group = f"{group_name}ro"
#         catalog_name = f"tenant_{group_name}"
#         writer_role = f"{group_name}_member"
#         reader_role = f"{group_name}ro_member"
#         personal_catalog = f"user_{username}"
#         personal_role = f"{username}_role"

#         try:
#             # ================================================================
#             # Step 1 — Create user
#             # ================================================================
#             cr = api_client.post(f"/management/users/{username}", headers=admin_headers)
#             assert cr.status_code in (200, 201), f"Create user failed: {cr.text}"
#             assert minio_verifier.user_exists(username), "User should exist in MinIO"

#             # ================================================================
#             # Step 2 — Provision Polaris
#             # ================================================================
#             pr = api_client.post(
#                 f"/polaris/user_provision/{username}", headers=admin_headers
#             )
#             assert pr.status_code == 200, f"Polaris provision failed: {pr.text}"

#             assert wait_for(lambda: polaris_verifier.principal_exists(username)), (
#                 "Principal should exist after provisioning"
#             )
#             assert wait_for(
#                 lambda: polaris_verifier.catalog_exists(personal_catalog)
#             ), "Personal catalog should exist after provisioning"
#             assert wait_for(
#                 lambda: polaris_verifier.principal_role_exists(personal_role)
#             ), "Personal role should exist after provisioning"
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, personal_role
#                 )
#             ), "Personal role should be assigned to user"

#             # ================================================================
#             # Step 3 — Create tenant (group)
#             # ================================================================
#             gr = api_client.post(
#                 f"/management/groups/{group_name}", headers=admin_headers
#             )
#             assert gr.status_code in (200, 201), f"Create group failed: {gr.text}"
#             assert minio_verifier.group_exists(group_name), (
#                 "Group should exist in MinIO"
#             )

#             assert wait_for(lambda: polaris_verifier.catalog_exists(catalog_name)), (
#                 f"Tenant catalog '{catalog_name}' should exist in Polaris"
#             )
#             assert wait_for(
#                 lambda: polaris_verifier.principal_role_exists(writer_role)
#             ), f"Writer role '{writer_role}' should exist in Polaris"
#             assert wait_for(
#                 lambda: polaris_verifier.principal_role_exists(reader_role)
#             ), f"Reader role '{reader_role}' should exist in Polaris"

#             # ================================================================
#             # Step 4 — Add user to R/W group
#             # ================================================================
#             ar = api_client.post(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert ar.status_code in (200, 201)
#             assert username in minio_verifier.get_group_members(group_name), (
#                 "User should be in MinIO group"
#             )
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, writer_role
#                 )
#             ), (
#                 f"Writer role '{writer_role}' should be assigned to '{username}' in Polaris"
#             )

#             # ================================================================
#             # Step 5 — Add user to RO group
#             # ================================================================
#             arr = api_client.post(
#                 f"/management/groups/{ro_group}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert arr.status_code in (200, 201)
#             assert username in minio_verifier.get_group_members(ro_group), (
#                 "User should be in MinIO RO group"
#             )
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, reader_role
#                 )
#             ), (
#                 f"Reader role '{reader_role}' should be assigned to '{username}' in Polaris"
#             )

#             # ================================================================
#             # Step 6 — Remove user from R/W group
#             # ================================================================
#             rr = api_client.delete(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert rr.status_code in (200, 204)
#             assert username not in minio_verifier.get_group_members(group_name), (
#                 "User should no longer be in MinIO R/W group"
#             )
#             assert wait_for(
#                 lambda: (
#                     not polaris_verifier.is_role_assigned_to_principal(
#                         username, writer_role
#                     )
#                 ),
#                 timeout=20,
#             ), f"Writer role '{writer_role}' should be REVOKED in Polaris"

#             # Reader role must still be intact (user is still in RO group)
#             assert polaris_verifier.is_role_assigned_to_principal(
#                 username, reader_role
#             ), "Reader role should still be assigned while user is in RO group"

#             # ================================================================
#             # Step 7 — Remove user from RO group
#             # ================================================================
#             rrr = api_client.delete(
#                 f"/management/groups/{ro_group}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert rrr.status_code in (200, 204)
#             assert username not in minio_verifier.get_group_members(ro_group), (
#                 "User should no longer be in MinIO RO group"
#             )
#             assert wait_for(
#                 lambda: (
#                     not polaris_verifier.is_role_assigned_to_principal(
#                         username, reader_role
#                     )
#                 ),
#                 timeout=20,
#             ), f"Reader role '{reader_role}' should be REVOKED in Polaris"

#             # ================================================================
#             # Step 8 — Delete group
#             # ================================================================
#             remaining = minio_verifier.get_group_members(group_name)
#             for m in remaining:
#                 time.sleep(0.3)
#                 api_client.delete(
#                     f"/management/groups/{group_name}/members/{m}",
#                     headers=admin_headers,
#                 )

#             dr = api_client.delete(
#                 f"/management/groups/{group_name}", headers=admin_headers
#             )
#             assert dr.status_code in (200, 204)
#             assert not minio_verifier.group_exists(group_name), (
#                 "Group should be removed from MinIO"
#             )
#             assert wait_for(
#                 lambda: not polaris_verifier.catalog_exists(catalog_name), timeout=20
#             ), f"Tenant catalog '{catalog_name}' should be removed from Polaris"

#             # ================================================================
#             # Step 9 — Delete user
#             # ================================================================
#             dur = api_client.delete(
#                 f"/management/users/{username}", headers=admin_headers
#             )
#             assert dur.status_code in (200, 204)
#             assert not minio_verifier.user_exists(username), (
#                 "User should be removed from MinIO"
#             )
#             assert wait_for(
#                 lambda: not polaris_verifier.principal_exists(username), timeout=20
#             ), f"Principal '{username}' should be removed from Polaris"

#         except Exception:
#             # Best-effort cleanup to avoid polluting subsequent tests
#             try:
#                 api_client.delete(
#                     f"/management/groups/{group_name}/members/{username}",
#                     headers=admin_headers,
#                 )
#             except Exception:
#                 pass
#             try:
#                 api_client.delete(
#                     f"/management/groups/{group_name}", headers=admin_headers
#                 )
#             except Exception:
#                 pass
#             try:
#                 api_client.delete(
#                     f"/management/users/{username}", headers=admin_headers
#                 )
#             except Exception:
#                 pass
#             raise


# # ===========================================================================
# # 5. Pre-Polaris Entity Scenarios
# # ===========================================================================


# @pytest.mark.management
# class TestPrePolarisEntities:
#     """
#     Verify correct behavior when MinIO entities exist but their Polaris
#     counterparts do not — simulating the state before Polaris was integrated.

#     These tests create resources normally, then delete the Polaris side to
#     simulate a pre-Polaris deployment, and verify that subsequent operations
#     lazily recreate the missing Polaris resources.
#     """

#     def test_add_member_creates_principal_for_pre_polaris_user(
#         self, api_client, admin_headers, temp_user, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         A user exists in MinIO but has never been provisioned in Polaris
#         (no principal). Admin adds this user to a group.

#         Expected
#         --------
#         - ``add_group_member`` creates the Polaris principal on demand.
#         - The writer role is assigned to the new principal.

#         Why this matters
#         ----------------
#         Pre-Polaris users must be seamlessly onboarded when they are first
#         added to a group, without requiring a separate provisioning step.
#         """
#         username = temp_user["username"]
#         group_name = unique_group_name("prepoluser")

#         try:
#             # Setup: create group (this creates tenant catalog in Polaris)
#             api_client.post(f"/management/groups/{group_name}", headers=admin_headers)
#             assert wait_for(
#                 lambda: polaris_verifier.catalog_exists(f"tenant_{group_name}")
#             )

#             # Verify user has NO Polaris principal (temp_user only creates MinIO user)
#             assert not polaris_verifier.principal_exists(username), (
#                 "User should NOT have a Polaris principal before add_group_member"
#             )

#             # ---- Add member (user has no Polaris principal) ----
#             resp = api_client.post(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert resp.status_code in (200, 201), (
#                 f"add_group_member failed: {resp.text}"
#             )

#             # MinIO
#             assert username in minio_verifier.get_group_members(group_name)

#             # Polaris — principal should now exist (created on demand)
#             assert wait_for(lambda: polaris_verifier.principal_exists(username)), (
#                 f"Principal '{username}' should be created on demand by add_group_member"
#             )

#             # Polaris — writer role should be assigned
#             writer_role = f"{group_name}_member"
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, writer_role
#                 )
#             ), f"Writer role '{writer_role}' should be assigned to pre-Polaris user"

#         finally:
#             api_client.delete(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             api_client.delete(f"/management/groups/{group_name}", headers=admin_headers)

#     def test_add_member_recreates_tenant_catalog_for_pre_polaris_group(
#         self, api_client, admin_headers, temp_user, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         A group exists in MinIO and has a Polaris tenant catalog. The Polaris
#         catalog and roles are deleted (simulating a pre-Polaris group). Then
#         a member is added.

#         Expected
#         --------
#         - ``add_group_member`` recreates the tenant catalog and roles via
#           ``ensure_tenant_catalog``.
#         - The member gets the writer role assigned.

#         Why this matters
#         ----------------
#         Groups that existed before Polaris was deployed must have their
#         catalogs lazily created when members are added.
#         """
#         username = temp_user["username"]
#         group_name = unique_group_name("prepolgrp")

#         try:
#             # Setup: create group normally (creates tenant catalog)
#             api_client.post(f"/management/groups/{group_name}", headers=admin_headers)
#             assert wait_for(
#                 lambda: polaris_verifier.catalog_exists(f"tenant_{group_name}")
#             )

#             # Simulate pre-Polaris state: delete the Polaris tenant catalog + roles
#             polaris_verifier.drop_tenant_catalog(group_name)
#             assert wait_for(
#                 lambda: not polaris_verifier.catalog_exists(f"tenant_{group_name}"),
#                 timeout=10,
#             ), "Tenant catalog should be deleted for pre-Polaris simulation"

#             # ---- Add member (tenant catalog doesn't exist in Polaris) ----
#             resp = api_client.post(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert resp.status_code in (200, 201), (
#                 f"add_group_member failed: {resp.text}"
#             )

#             # Polaris — tenant catalog should be recreated
#             assert wait_for(
#                 lambda: polaris_verifier.catalog_exists(f"tenant_{group_name}")
#             ), "Tenant catalog should be recreated by add_group_member"

#             # Polaris — principal roles should be recreated
#             assert wait_for(
#                 lambda: polaris_verifier.principal_role_exists(f"{group_name}_member")
#             ), "Writer principal role should be recreated"
#             assert wait_for(
#                 lambda: polaris_verifier.principal_role_exists(f"{group_name}ro_member")
#             ), "Reader principal role should be recreated"

#             # Polaris — writer role assigned to user
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, f"{group_name}_member"
#                 )
#             ), "Writer role should be assigned to user after catalog recreation"

#         finally:
#             api_client.delete(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             api_client.delete(f"/management/groups/{group_name}", headers=admin_headers)

#     def test_user_provision_discovers_existing_groups(
#         self, api_client, admin_headers, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         A user is a member of multiple MinIO groups, but has never been
#         provisioned in Polaris. On first login, ``user_provision`` is called.

#         Expected
#         --------
#         - Personal catalog ``user_{username}`` is created.
#         - All tenant catalogs for the user's groups are created (idempotent).
#         - The user gets writer/reader roles for all their groups.

#         Why this matters
#         ----------------
#         At login, ``user_provision`` is the single reconciliation point.
#         It must discover ALL existing MinIO group memberships and lazily
#         initialize every missing Polaris resource.
#         """
#         username = unique_username("prepoldisco")
#         group1 = unique_group_name("prepoldisco1")
#         group2 = unique_group_name("prepoldisco2")

#         try:
#             # Setup: create user and two groups, add user to both
#             api_client.post(f"/management/users/{username}", headers=admin_headers)
#             api_client.post(f"/management/groups/{group1}", headers=admin_headers)
#             api_client.post(f"/management/groups/{group2}", headers=admin_headers)

#             api_client.post(
#                 f"/management/groups/{group1}/members/{username}",
#                 headers=admin_headers,
#             )
#             api_client.post(
#                 f"/management/groups/{group2}/members/{username}",
#                 headers=admin_headers,
#             )

#             # Verify user is in both MinIO groups
#             assert username in minio_verifier.get_group_members(group1)
#             assert username in minio_verifier.get_group_members(group2)

#             # Delete the user's Polaris principal to simulate pre-Polaris state.
#             # (add_group_member created it; delete it so user_provision must recreate.)
#             polaris_verifier.cleanup_principal(username)
#             assert wait_for(
#                 lambda: not polaris_verifier.principal_exists(username), timeout=10
#             ), "Principal should be deleted for pre-Polaris simulation"

#             # ---- Provision user (simulates first login) ----
#             resp = api_client.post(
#                 f"/polaris/user_provision/{username}", headers=admin_headers
#             )
#             assert resp.status_code == 200, f"user_provision failed: {resp.text}"
#             data = resp.json()

#             # Personal catalog created
#             assert data["personal_catalog"] == f"user_{username}"
#             assert wait_for(
#                 lambda: polaris_verifier.catalog_exists(f"user_{username}")
#             ), "Personal catalog should be created"

#             # Tenant catalogs discovered
#             assert f"tenant_{group1}" in data["tenant_catalogs"], (
#                 f"tenant_{group1} should be in tenant_catalogs response"
#             )
#             assert f"tenant_{group2}" in data["tenant_catalogs"], (
#                 f"tenant_{group2} should be in tenant_catalogs response"
#             )

#             # Writer roles assigned for both groups
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, f"{group1}_member"
#                 )
#             ), f"Writer role for {group1} should be assigned"
#             assert wait_for(
#                 lambda: polaris_verifier.is_role_assigned_to_principal(
#                     username, f"{group2}_member"
#                 )
#             ), f"Writer role for {group2} should be assigned"

#         finally:
#             for g in [group1, group2]:
#                 try:
#                     api_client.delete(
#                         f"/management/groups/{g}/members/{username}",
#                         headers=admin_headers,
#                     )
#                 except Exception:
#                     pass
#                 try:
#                     api_client.delete(f"/management/groups/{g}", headers=admin_headers)
#                 except Exception:
#                     pass
#             try:
#                 api_client.delete(
#                     f"/management/users/{username}", headers=admin_headers
#                 )
#             except Exception:
#                 pass

#     def test_idempotent_reprovisioning(
#         self, api_client, admin_headers, temp_user, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         A user is fully provisioned in Polaris (personal catalog, group roles).
#         ``user_provision`` is called again (e.g., second login).

#         Expected
#         --------
#         - No errors — all create/grant operations are idempotent.
#         - Response contains the same catalogs and roles as before.

#         Why this matters
#         ----------------
#         Every user login calls ``user_provision``. It must be safe to call
#         repeatedly without causing duplicate key errors or 500s.
#         """
#         username = temp_user["username"]
#         group_name = unique_group_name("polidem")

#         try:
#             # Setup: create group and add user
#             api_client.post(f"/management/groups/{group_name}", headers=admin_headers)
#             api_client.post(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )

#             # ---- First provision ----
#             resp1 = api_client.post(
#                 f"/polaris/user_provision/{username}", headers=admin_headers
#             )
#             assert resp1.status_code == 200, f"First provision failed: {resp1.text}"
#             data1 = resp1.json()

#             assert data1["personal_catalog"] == f"user_{username}"
#             assert f"tenant_{group_name}" in data1["tenant_catalogs"]

#             # ---- Second provision (must not error) ----
#             resp2 = api_client.post(
#                 f"/polaris/user_provision/{username}", headers=admin_headers
#             )
#             assert resp2.status_code == 200, (
#                 f"Second provision should succeed (idempotent): {resp2.text}"
#             )
#             data2 = resp2.json()

#             # Same resources returned
#             assert data2["personal_catalog"] == data1["personal_catalog"]
#             assert set(data2["tenant_catalogs"]) == set(data1["tenant_catalogs"])

#             # Polaris state unchanged
#             assert polaris_verifier.principal_exists(username)
#             assert polaris_verifier.catalog_exists(f"user_{username}")
#             assert polaris_verifier.is_role_assigned_to_principal(
#                 username, f"{group_name}_member"
#             )

#         finally:
#             api_client.delete(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             api_client.delete(f"/management/groups/{group_name}", headers=admin_headers)

#     def test_remove_member_from_pre_polaris_group_no_error(
#         self, api_client, admin_headers, temp_user, polaris_verifier, minio_verifier
#     ):
#         """
#         Scenario
#         --------
#         A user is a member of a MinIO group. The user's Polaris principal is
#         deleted (simulating pre-Polaris state). Admin removes the user from
#         the group.

#         Expected
#         --------
#         - No error — ``revoke_principal_role_from_principal`` handles missing
#           principal (404) gracefully.
#         - User is removed from MinIO group.

#         Why this matters
#         ----------------
#         Removing a member whose Polaris principal doesn't exist (e.g., a user
#         who was added before Polaris was deployed) must not crash.
#         """
#         username = temp_user["username"]
#         group_name = unique_group_name("prepolrev")

#         try:
#             # Setup: create group, provision user, add to group
#             api_client.post(f"/management/groups/{group_name}", headers=admin_headers)
#             api_client.post(
#                 f"/polaris/user_provision/{username}", headers=admin_headers
#             )
#             assert wait_for(lambda: polaris_verifier.principal_exists(username))

#             api_client.post(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert username in minio_verifier.get_group_members(group_name)

#             # Simulate pre-Polaris state: delete the user's principal
#             polaris_verifier.cleanup_principal(username)
#             assert wait_for(
#                 lambda: not polaris_verifier.principal_exists(username), timeout=10
#             ), "Principal should be deleted for pre-Polaris simulation"

#             # ---- Remove member (principal doesn't exist in Polaris) ----
#             resp = api_client.delete(
#                 f"/management/groups/{group_name}/members/{username}",
#                 headers=admin_headers,
#             )
#             assert resp.status_code in (200, 204), (
#                 f"Remove member should succeed even without Polaris principal: {resp.text}"
#             )

#             # MinIO — user removed from group
#             assert username not in minio_verifier.get_group_members(group_name)

#         finally:
#             api_client.delete(f"/management/groups/{group_name}", headers=admin_headers)
