#!/usr/bin/env python3
"""
Integration smoke-test for all MMS API routes using HTTP.

Requires the docker compose stack to be running:
    docker compose up -d

Run with:
    INTEG_TEST_KBASE_TOKEN_STANDARD=<token> INTEG_TEST_KBASE_TOKEN_ADMIN=<token> \
    python test_scripts/mms_routes_integration.py

Environment variables:
    INTEG_TEST_KBASE_TOKEN_STANDARD  KBase token for a regular BERDL user
    INTEG_TEST_KBASE_TOKEN_ADMIN     KBase token for an MMS admin
    KBASE_AUTH_HOST                  KBase auth host (default: https://ci.kbase.us)
"""

# NOTE: These tests are smoke tests, not comprehensive, and do not thoroughly check outputs.
#       Also they're focused on S3 implementation checking, and so the metadata tests are a
#       bit sparse since they're in Postgres
#       Sharing tests are also not great since they're deprecated

import asyncio
import os
import sys
import traceback
from datetime import datetime

import requests
from s3.core.s3_client import S3Client
from s3.core.s3_iam_client import S3IAMClient
from s3.models.s3_config import S3Config

MMS_URL = "http://localhost:8010"
AUTH_HOST = os.environ.get("KBASE_AUTH_HOST", "https://ci.kbase.us")
AUTH_TOKEN_URL = f"{AUTH_HOST}/services/auth/api/V2/token"
AUTH_ME_URL = f"{AUTH_HOST}/services/auth/api/V2/me"

REQUIRED_ROLE = "BERDL_USER"
ADMIN_ROLE = "CDM_JUPYTERHUB_ADMIN"

BUCKET = "cdm-lake"
USERS_GENERAL_PREFIX = "users-general-warehouse"
USERS_SQL_PREFIX = "users-sql-warehouse"
TENANT_GENERAL_PREFIX = "tenant-general-warehouse"
TENANT_SQL_PREFIX = "tenant-sql-warehouse"
GLOBALUSERS = "globalusers"
SPARK_LOGS_BUCKET = "cdm-spark-job-logs"
SPARK_LOGS_PREFIX = "spark-job-logs"
TASK_SERVICE_BUCKET = "cts"
GROUP_NAME = "inttestapitestgroup"
EPHEMERAL_USER = "mmsinttestephemeraluser"

# Direct Ceph connection — same backend MMS talks to (see docker-compose.yml)
CEPH_ENDPOINT = "http://localhost:9050"
CEPH_ACCESS_KEY = "test_access_key"
CEPH_SECRET_KEY = "test_access_secret"
IAM_PATH_PREFIX = "/data_governance_service"
S3_ARN = "arn:aws:s3:::"


passed = []
failed = []


# ── Helpers ───────────────────────────────────────────────────────────────────


def assert_user_accessible_paths(
    paths: list, username: str, extra_paths: set[str] | None = None
) -> None:
    """Assert accessible_paths matches exactly the expected set for this user.

    Pass extra_paths for any additional group or shared paths the user has been granted.
    """
    expected = {
        # Personal home paths
        f"s3a://{BUCKET}/{USERS_GENERAL_PREFIX}/{username}/",
        f"s3a://{BUCKET}/{USERS_SQL_PREFIX}/{username}/",
        f"s3a://{BUCKET}/{USERS_SQL_PREFIX}/{username}/u_{username}__*/",
        # globalusers group paths
        f"s3a://{BUCKET}/{TENANT_GENERAL_PREFIX}/{GLOBALUSERS}/",
        f"s3a://{BUCKET}/{TENANT_SQL_PREFIX}/{GLOBALUSERS}/",
        f"s3a://{BUCKET}/{TENANT_SQL_PREFIX}/{GLOBALUSERS}/{GLOBALUSERS}_*/",
        # System policy paths
        f"s3a://{SPARK_LOGS_BUCKET}/{SPARK_LOGS_PREFIX}/{username}/",
        f"s3a://{TASK_SERVICE_BUCKET}/logs/",
        f"s3a://{TASK_SERVICE_BUCKET}/io/",
    } | (extra_paths or set())
    assert set(paths) == expected, (
        f"accessible_paths mismatch.\n  missing: {expected - set(paths)}\n"
        + f"  unexpected: {set(paths) - expected}"
    )


def policy_resources(policy: dict) -> set[str]:
    """Extract all resource ARN strings from a PolicyModel dict."""
    resources: set[str] = set()
    for stmt in policy["policy_document"]["statement"]:
        r = stmt["resource"]
        if isinstance(r, list):
            resources.update(r)
        else:
            resources.add(r)
    return resources


def check_user_policy(policy: dict, username: str) -> None:
    """Assert the user home policy has exactly the expected resource ARNs."""
    sql_base = f"{USERS_SQL_PREFIX}/{username}"
    gen_base = f"{USERS_GENERAL_PREFIX}/{username}"
    gov = f"u_{username}__"
    expected = {
        f"{S3_ARN}{BUCKET}",
        f"{S3_ARN}{BUCKET}/{sql_base}/{gov}*",
        f"{S3_ARN}{BUCKET}/{sql_base}/{gov}*/*",
        f"{S3_ARN}{BUCKET}/{sql_base}",
        f"{S3_ARN}{BUCKET}/{sql_base}/*",
        f"{S3_ARN}{BUCKET}/{gen_base}",
        f"{S3_ARN}{BUCKET}/{gen_base}/*",
    }
    resources = policy_resources(policy)
    assert resources == expected, (
        f"user home policy resource mismatch.\n"
        f"  missing: {expected - resources}\n"
        f"  unexpected: {resources - expected}"
    )


def check_system_policy(policy: dict, username: str) -> None:
    """Assert the user system policy has exactly the expected resource ARNs."""
    spark_base = f"{SPARK_LOGS_PREFIX}/{username}"
    expected = {
        f"{S3_ARN}{SPARK_LOGS_BUCKET}",
        f"{S3_ARN}{SPARK_LOGS_BUCKET}/{spark_base}",
        f"{S3_ARN}{SPARK_LOGS_BUCKET}/{spark_base}/*",
        f"{S3_ARN}{TASK_SERVICE_BUCKET}",
        f"{S3_ARN}{TASK_SERVICE_BUCKET}/logs",
        f"{S3_ARN}{TASK_SERVICE_BUCKET}/logs/*",
        f"{S3_ARN}{TASK_SERVICE_BUCKET}/io",
        f"{S3_ARN}{TASK_SERVICE_BUCKET}/io/*",
    }
    resources = policy_resources(policy)
    assert resources == expected, (
        f"system policy resource mismatch.\n"
        f"  missing: {expected - resources}\n"
        f"  unexpected: {resources - expected}"
    )


def check_group_policy(policy: dict, group_name: str) -> None:
    """Assert the group policy has exactly the expected resource ARNs."""
    sql_base = f"{TENANT_SQL_PREFIX}/{group_name}"
    gen_base = f"{TENANT_GENERAL_PREFIX}/{group_name}"
    gov = f"{group_name}_"
    expected = {
        f"{S3_ARN}{BUCKET}",
        f"{S3_ARN}{BUCKET}/{sql_base}/{gov}*",
        f"{S3_ARN}{BUCKET}/{sql_base}/{gov}*/*",
        f"{S3_ARN}{BUCKET}/{sql_base}",
        f"{S3_ARN}{BUCKET}/{sql_base}/*",
        f"{S3_ARN}{BUCKET}/{gen_base}",
        f"{S3_ARN}{BUCKET}/{gen_base}/*",
    }
    resources = policy_resources(policy)
    assert resources == expected, (
        f"group policy resource mismatch for {group_name!r}.\n"
        f"  missing: {expected - resources}\n"
        f"  unexpected: {resources - expected}"
    )


def assert_user_entry(
    user: dict, username: str, *, expect_globalusersro: bool = False
) -> None:
    """Assert a UserModel entry from GET /management/users has all expected fields.

    Assumes no group memberships beyond globalusers variants (i.e. called before
    test_management_groups adds users to GROUP_NAME).

    expect_globalusersro: True for the user who triggered globalusers creation
        (admin_user, always first), who is added to both globalusers and
        globalusersro by create_group.
    """
    assert user["username"] == username
    assert user["access_key"], "access_key must be non-empty"
    assert user["secret_key"] == "<redacted>", (
        f"expected secret_key '<redacted>', got {user['secret_key']!r}"
    )
    assert set(user["home_paths"]) == {
        f"s3a://{BUCKET}/{USERS_GENERAL_PREFIX}/{username}/",
        f"s3a://{BUCKET}/{USERS_SQL_PREFIX}/{username}/",
    }, f"unexpected home_paths for {username!r}: {user['home_paths']}"
    if expect_globalusersro:
        expected_groups = [GLOBALUSERS, f"{GLOBALUSERS}ro"]
        expected_group_policy_count = 2
        expected_total_policies = 4
    else:
        expected_groups = [GLOBALUSERS]
        expected_group_policy_count = 1
        expected_total_policies = 3
    assert sorted(user["groups"]) == sorted(expected_groups), (
        f"expected groups {expected_groups}, got {user['groups']}"
    )
    assert len(user["user_policies"]) == 2, (
        f"expected 2 user policies (home + system), got {len(user['user_policies'])}"
    )
    check_user_policy(user["user_policies"][0], username)
    check_system_policy(user["user_policies"][1], username)
    assert len(user["group_policies"]) == expected_group_policy_count, (
        f"expected {expected_group_policy_count} group policies, "
        f"got {len(user['group_policies'])}"
    )
    for policy in user["group_policies"]:
        check_group_policy(policy, GLOBALUSERS)
    assert user["total_policies"] == expected_total_policies, (
        f"expected total_policies {expected_total_policies}, got {user['total_policies']}"
    )
    assert_user_accessible_paths(user["accessible_paths"], username)


def assert_timestamp(value: str, name: str) -> None:
    """Assert that value is a parseable ISO 8601 datetime string."""
    try:
        datetime.fromisoformat(value)
    except (TypeError, ValueError) as e:
        raise AssertionError(f"{name} is not a valid timestamp: {value!r}") from e


def ok(name: str) -> None:
    print(f"  PASS  {name}")
    passed.append(name)


def fail(name: str, exc: Exception) -> None:
    print(f"  FAIL  {name}: {exc}")
    failed.append(name)
    traceback.print_exc()


def mms(
    method: str, path: str, token: str | None = None, **kwargs
) -> requests.Response:
    """Make a request to the MMS API."""
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.request(method, f"{MMS_URL}{path}", headers=headers, **kwargs)


def lookup_username(token: str) -> str:
    """Look up the KBase username for a token. Token is not logged."""
    resp = requests.get(AUTH_TOKEN_URL, headers={"Authorization": token})
    resp.raise_for_status()
    return resp.json()["user"]


def lookup_custom_roles(token: str) -> set[str]:
    """Return the custom roles for a token. Token is not logged."""
    resp = requests.get(AUTH_ME_URL, headers={"Authorization": token})
    resp.raise_for_status()
    return set(resp.json().get("customroles", []))


def home_path(username: str) -> str:
    return f"s3a://{BUCKET}/users-general-warehouse/{username}/"


def share_path(username: str) -> str:
    """A specific subpath within the user's home for sharing tests."""
    return f"s3a://{BUCKET}/users-general-warehouse/{username}/data/"


# ── Test sections ─────────────────────────────────────────────────────────────


def test_health() -> None:
    try:
        r = mms("GET", "/health")
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        assert r.json()["status"] == "healthy"
        ok("health check returns healthy")
    except Exception as e:
        fail("health check returns healthy", e)


def test_credentials(
    admin_token: str, admin_user: str, standard_token: str, standard_user: str
) -> None:
    # GET /credentials/ — creates each user on first call; save standard creds for rotate test
    standard_creds: dict = {}
    for label, token, expected_user in [
        ("admin", admin_token, admin_user),
        ("standard", standard_token, standard_user),
    ]:
        try:
            r = mms("GET", "/credentials/", token=token)
            assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
            body = r.json()
            assert body["username"] == expected_user, (
                f"expected username '{expected_user}', got '{body['username']}'"
            )
            assert body["access_key"], "access_key must be non-empty"
            assert body["secret_key"], "secret_key must be non-empty"
            if label == "standard":
                standard_creds = body
            ok(f"GET /credentials/ returns credentials ({label})")
        except Exception as e:
            fail(f"GET /credentials/ returns credentials ({label})", e)

    # POST /credentials/rotate — check rotated creds differ from the originals
    rotated_creds: dict = {}
    try:
        r = mms("POST", "/credentials/rotate", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        rotated_creds = r.json()
        assert rotated_creds["access_key"], "rotated access_key must be non-empty"
        assert rotated_creds["secret_key"], "rotated secret_key must be non-empty"
        assert rotated_creds["access_key"] != standard_creds["access_key"], (
            "rotated access_key must differ from original"
        )
        assert rotated_creds["secret_key"] != standard_creds["secret_key"], (
            "rotated secret_key must differ from original"
        )
        ok("POST /credentials/rotate returns new credentials")
    except Exception as e:
        fail("POST /credentials/rotate returns new credentials", e)

    # GET /credentials/ — check returned creds match the rotated ones
    try:
        r = mms("GET", "/credentials/", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["access_key"] == rotated_creds["access_key"], (
            "access_key after rotation must match rotated credentials"
        )
        assert body["secret_key"] == rotated_creds["secret_key"], (
            "secret_key after rotation must match rotated credentials"
        )
        ok("GET /credentials/ after rotation returns rotated credentials")
    except Exception as e:
        fail("GET /credentials/ after rotation returns rotated credentials", e)

    # Unauthenticated request
    try:
        r = mms("GET", "/credentials/")
        assert r.status_code == 401, f"expected 401, got {r.status_code}"
        ok("GET /credentials/ without token returns 401")
    except Exception as e:
        fail("GET /credentials/ without token returns 401", e)


def test_workspaces(standard_token: str, standard_user: str) -> None:
    # GET /workspaces/me
    try:
        r = mms("GET", "/workspaces/me", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert_user_entry(body, standard_user)
        ok("GET /workspaces/me returns user workspace")
    except Exception as e:
        fail("GET /workspaces/me returns user workspace", e)

    # GET /workspaces/me/groups
    try:
        r = mms("GET", "/workspaces/me/groups", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        assert body["groups"] == ["globalusers"], (
            f"expected groups ['globalusers'], got {body['groups']}"
        )
        assert body["group_count"] == 1
        ok("GET /workspaces/me/groups returns group list")
    except Exception as e:
        fail("GET /workspaces/me/groups returns group list", e)

    # GET /workspaces/me/policies
    try:
        r = mms("GET", "/workspaces/me/policies", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        check_user_policy(body["user_home_policy"], standard_user)
        check_system_policy(body["user_system_policy"], standard_user)
        assert len(body["group_policies"]) == 1, (
            f"expected 1 group policy (globalusers), got {len(body['group_policies'])}"
        )
        check_group_policy(body["group_policies"][0], GLOBALUSERS)
        assert body["total_policies"] == 3, (
            f"expected total_policies 3, got {body['total_policies']}"
        )
        ok("GET /workspaces/me/policies returns policy info")
    except Exception as e:
        fail("GET /workspaces/me/policies returns policy info", e)

    # GET /workspaces/me/accessible-paths
    try:
        r = mms("GET", "/workspaces/me/accessible-paths", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        assert_user_accessible_paths(body["accessible_paths"], standard_user)
        assert body["total_paths"] == 9, (
            f"expected total_paths 9, got {body['total_paths']}"
        )
        ok("GET /workspaces/me/accessible-paths returns paths including home")
    except Exception as e:
        fail("GET /workspaces/me/accessible-paths returns paths including home", e)

    # GET /workspaces/me/sql-warehouse-prefix
    try:
        r = mms("GET", "/workspaces/me/sql-warehouse-prefix", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        expected_prefix = f"s3a://{BUCKET}/{USERS_SQL_PREFIX}/{standard_user}/"
        assert body["sql_warehouse_prefix"] == expected_prefix, (
            f"expected sql_warehouse_prefix {expected_prefix!r}, "
            f"got {body['sql_warehouse_prefix']!r}"
        )
        ok("GET /workspaces/me/sql-warehouse-prefix returns prefix")
    except Exception as e:
        fail("GET /workspaces/me/sql-warehouse-prefix returns prefix", e)

    # GET /workspaces/me/namespace-prefix
    try:
        r = mms("GET", "/workspaces/me/namespace-prefix", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        assert body["user_namespace_prefix"] == f"u_{standard_user}__", (
            f"expected user_namespace_prefix 'u_{standard_user}__', "
            f"got {body['user_namespace_prefix']!r}"
        )
        assert body["tenant"] is None, f"expected tenant=None, got {body['tenant']!r}"
        assert body["tenant_namespace_prefix"] is None, (
            f"expected tenant_namespace_prefix=None, "
            f"got {body['tenant_namespace_prefix']!r}"
        )
        ok("GET /workspaces/me/namespace-prefix returns prefix")
    except Exception as e:
        fail("GET /workspaces/me/namespace-prefix returns prefix", e)


def test_management_users(
    admin_token: str, admin_user: str, standard_user: str
) -> None:
    # GET /management/users/names
    try:
        r = mms("GET", "/management/users/names", token=admin_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert set(body["usernames"]) == {admin_user, standard_user}, (
            f"expected usernames {{{admin_user!r}, {standard_user!r}}}, "
            f"got {body['usernames']}"
        )
        assert body["total_count"] == 2, (
            f"expected total_count 2, got {body['total_count']}"
        )
        ok("GET /management/users/names returns exact usernames")
    except Exception as e:
        fail("GET /management/users/names returns exact usernames", e)

    # GET /management/users
    try:
        r = mms("GET", "/management/users", token=admin_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["total_count"] == 2, (
            f"expected total_count 2, got {body['total_count']}"
        )
        assert body["retrieved_count"] == 2, (
            f"expected retrieved_count 2, got {body['retrieved_count']}"
        )
        assert body["page"] == 1
        assert body["page_size"] == 50  # default
        assert body["total_pages"] == 1
        assert body["has_next"] is False
        assert body["has_prev"] is False
        users_by_name = {u["username"]: u for u in body["users"]}
        assert set(users_by_name) == {admin_user, standard_user}, (
            f"expected users {{{admin_user!r}, {standard_user!r}}}, "
            f"got {set(users_by_name)}"
        )
        assert_user_entry(
            users_by_name[admin_user], admin_user, expect_globalusersro=True
        )
        assert_user_entry(users_by_name[standard_user], standard_user)
        ok("GET /management/users returns full paginated user list")
    except Exception as e:
        fail("GET /management/users returns full paginated user list", e)

    # GET /management/users — pagination
    try:
        r = mms("GET", "/management/users?page=1&page_size=1", token=admin_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["page"] == 1
        assert body["page_size"] == 1
        assert body["total_count"] == 2
        assert body["total_pages"] == 2
        assert body["retrieved_count"] == 1
        assert len(body["users"]) == 1
        assert body["has_next"] is True
        assert body["has_prev"] is False
        paged_user = body["users"][0]
        assert paged_user["username"] in {admin_user, standard_user}, (
            f"page 1 user {paged_user['username']!r} not one of the expected users"
        )
        assert_user_entry(
            paged_user,
            paged_user["username"],
            expect_globalusersro=paged_user["username"] == admin_user,
        )
        ok("GET /management/users respects page_size parameter")
    except Exception as e:
        fail("GET /management/users respects page_size parameter", e)

    # GET /management/users — pagination page 2
    try:
        r = mms("GET", "/management/users?page=2&page_size=1", token=admin_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["page"] == 2
        assert body["page_size"] == 1
        assert body["total_count"] == 2
        assert body["total_pages"] == 2
        assert body["retrieved_count"] == 1
        assert len(body["users"]) == 1
        assert body["has_next"] is False
        assert body["has_prev"] is True
        paged_user_p2 = body["users"][0]
        assert paged_user_p2["username"] in {admin_user, standard_user}, (
            f"page 2 user {paged_user_p2['username']!r} not one of the expected users"
        )
        assert_user_entry(
            paged_user_p2,
            paged_user_p2["username"],
            expect_globalusersro=paged_user_p2["username"] == admin_user,
        )
        ok("GET /management/users returns correct second page")
    except Exception as e:
        fail("GET /management/users returns correct second page", e)

    # POST /management/users/{username} — new user (not yet in MinIO)
    try:
        r = mms("POST", f"/management/users/{EPHEMERAL_USER}", token=admin_token)
        assert r.status_code == 201, f"expected 201, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == EPHEMERAL_USER
        assert body["access_key"], "access_key must be non-empty"
        assert body["secret_key"], "secret_key must be non-empty"
        assert set(body["home_paths"]) == {
            f"s3a://{BUCKET}/{USERS_GENERAL_PREFIX}/{EPHEMERAL_USER}/",
            f"s3a://{BUCKET}/{USERS_SQL_PREFIX}/{EPHEMERAL_USER}/",
        }, f"unexpected home_paths: {body['home_paths']}"
        # group membership is not reflected in the create response (same known bug
        # as the idempotent case below)
        assert body["groups"] == [], (
            f"expected groups [] (group membership not reflected on create), "
            f"got {body['groups']}"
        )
        assert body["total_policies"] == 2, (
            f"expected total_policies 2 (group policies not counted on create), "
            f"got {body['total_policies']}"
        )
        assert body["operation"] == "create"
        assert body["performed_by"] == admin_user
        assert_timestamp(body["timestamp"], "timestamp")
        ok("POST /management/users/{username} creates a genuinely new user")
    except Exception as e:
        fail("POST /management/users/{username} creates a genuinely new user", e)

    # DELETE the ephemeral user so test_migrate sees exactly 2 users
    try:
        r = mms("DELETE", f"/management/users/{EPHEMERAL_USER}", token=admin_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["resource_type"] == "user", (
            f"expected resource_type 'user', got {body['resource_type']!r}"
        )
        assert body["resource_name"] == EPHEMERAL_USER, (
            f"expected resource_name {EPHEMERAL_USER!r}, got {body['resource_name']!r}"
        )
        assert body["message"] == f"User {EPHEMERAL_USER} deleted successfully", (
            f"unexpected message: {body['message']!r}"
        )
        ok(f"DELETE /management/users/{EPHEMERAL_USER} removes ephemeral test user")
    except Exception as e:
        fail(
            f"DELETE /management/users/{EPHEMERAL_USER} removes ephemeral test user", e
        )

    # POST /management/users/{username} — idempotent; standard user already exists
    try:
        r = mms("POST", f"/management/users/{standard_user}", token=admin_token)
        assert r.status_code == 201, f"expected 201, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        assert body["access_key"], "access_key must be non-empty"
        assert body["secret_key"], "secret_key must be non-empty"
        assert set(body["home_paths"]) == {
            f"s3a://{BUCKET}/{USERS_GENERAL_PREFIX}/{standard_user}/",
            f"s3a://{BUCKET}/{USERS_SQL_PREFIX}/{standard_user}/",
        }
        # BUG: create_user returns groups=[] and total_policies=2 even though
        # the user was just added to globalusers — group membership is not
        # reflected in the create response (s3/managers/user_manager.py:170-180).
        assert body["groups"] == [], (
            f"expected groups [] (bug: groups not populated on create), "
            f"got {body['groups']}"
        )
        assert body["total_policies"] == 2, (
            f"expected total_policies 2 (bug: group policies not counted on "
            f"create), got {body['total_policies']}"
        )
        assert body["operation"] == "create"
        assert body["performed_by"] == admin_user
        assert_timestamp(body["timestamp"], "timestamp")
        ok("POST /management/users/{username} returns user info (idempotent)")
    except Exception as e:
        fail("POST /management/users/{username} returns user info (idempotent)", e)

    # POST /management/users/{username}/rotate-credentials
    try:
        r = mms(
            "POST",
            f"/management/users/{standard_user}/rotate-credentials",
            token=admin_token,
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        assert body["access_key"], "access_key must be non-empty"
        assert body["secret_key"], "secret_key must be non-empty"
        assert set(body["home_paths"]) == {
            f"s3a://{BUCKET}/{USERS_GENERAL_PREFIX}/{standard_user}/",
            f"s3a://{BUCKET}/{USERS_SQL_PREFIX}/{standard_user}/",
        }
        assert body["groups"] == [GLOBALUSERS], (
            f"expected groups [{GLOBALUSERS!r}], got {body['groups']}"
        )
        assert body["total_policies"] == 3, (
            f"expected total_policies 3, got {body['total_policies']}"
        )
        assert body["operation"] == "rotate"
        assert body["performed_by"] == admin_user
        assert_timestamp(body["timestamp"], "timestamp")
        ok("POST /management/users/{username}/rotate-credentials rotates key")
    except Exception as e:
        fail("POST /management/users/{username}/rotate-credentials rotates key", e)


def test_admin_only_endpoints(standard_token: str) -> None:
    """Confirm that all admin-only endpoints reject a regular authenticated user."""
    # Use placeholder path params — auth is enforced before any IAM lookup.
    _u = "someuser"
    _g = "somegroup"

    admin_only: list[tuple[str, str]] = [
        # management — users
        ("GET", "/management/users/names"),
        ("GET", "/management/users"),
        ("POST", f"/management/users/{_u}"),
        ("POST", f"/management/users/{_u}/rotate-credentials"),
        ("DELETE", f"/management/users/{_u}"),
        # management — groups
        ("GET", "/management/groups"),
        # note groups names does NOT need an admin, which is odd since all other mgmnt endpoints do
        ("POST", f"/management/groups/{_g}"),
        ("POST", f"/management/groups/{_g}/members/{_u}"),
        ("DELETE", f"/management/groups/{_g}/members/{_u}"),
        ("DELETE", f"/management/groups/{_g}"),
        # management — migration
        ("POST", "/management/migrate/regenerate-policies"),
        # tenants
        ("POST", f"/tenants/{_g}"),
        ("DELETE", f"/tenants/{_g}"),
        ("POST", f"/tenants/{_g}/stewards/{_u}"),
        ("DELETE", f"/tenants/{_g}/stewards/{_u}"),
    ]

    for method, path in admin_only:
        name = f"{method} {path} rejects non-admin"
        try:
            r = mms(method, path, token=standard_token)
            assert r.status_code in (401, 403), (
                f"expected 401/403 for non-admin, got {r.status_code}: {r.text}"
            )
            ok(name)
        except Exception as e:
            fail(name, e)


def test_management_groups(
    admin_token: str, admin_user: str, standard_token: str, standard_user: str
) -> None:
    # POST /management/groups/{group_name}
    try:
        r = mms("POST", f"/management/groups/{GROUP_NAME}", token=admin_token)
        assert r.status_code == 201, f"expected 201, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["group_name"] == GROUP_NAME
        assert body["ro_group_name"] == f"{GROUP_NAME}ro"
        assert body["members"] == [admin_user], (
            f"expected members [{admin_user!r}] (creator only), got {body['members']}"
        )
        assert body["member_count"] == 1
        assert body["operation"] == "create"
        assert body["performed_by"] == admin_user
        assert_timestamp(body["timestamp"], "timestamp")
        ok("POST /management/groups/{group_name} creates group and RO shadow")
    except Exception as e:
        fail("POST /management/groups/{group_name} creates group and RO shadow", e)

    # GET /management/groups
    try:
        r = mms("GET", "/management/groups", token=admin_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        expected_groups = {
            GLOBALUSERS,
            f"{GLOBALUSERS}ro",
            GROUP_NAME,
            f"{GROUP_NAME}ro",
        }
        groups_by_name = {g["group_name"]: g for g in body["groups"]}
        assert set(groups_by_name) == expected_groups, (
            f"expected groups {expected_groups}, got {set(groups_by_name)}"
        )
        assert body["total_count"] == 4
        # Both users were created before this point, so both are in globalusers.
        # Only admin_user is in globalusersro (added as creator when the group was
        # first created). GROUP_NAME and its RO shadow each have only admin_user
        # (the creator); standard_user has not yet been added.
        expected_members = {
            GLOBALUSERS: {admin_user, standard_user},
            f"{GLOBALUSERS}ro": {admin_user},
            GROUP_NAME: {admin_user},
            f"{GROUP_NAME}ro": {admin_user},
        }
        for group_name, expected in expected_members.items():
            entry = groups_by_name[group_name]
            assert set(entry["members"]) == expected, (
                f"expected {group_name!r} members {expected}, got {entry['members']}"
            )
            assert entry["member_count"] == len(expected), (
                f"expected {group_name!r} member_count {len(expected)}, "
                f"got {entry['member_count']}"
            )
        ok("GET /management/groups lists the created group")
    except Exception as e:
        fail("GET /management/groups lists the created group", e)

    # GET /management/groups/names (any authenticated user)
    try:
        r = mms("GET", "/management/groups/names", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        expected_names = {
            GLOBALUSERS,
            f"{GLOBALUSERS}ro",
            GROUP_NAME,
            f"{GROUP_NAME}ro",
        }
        assert set(body["group_names"]) == expected_names, (
            f"expected group_names {expected_names}, got {set(body['group_names'])}"
        )
        assert body["total_count"] == 4
        ok("GET /management/groups/names accessible to non-admin and includes group")
    except Exception as e:
        fail(
            "GET /management/groups/names accessible to non-admin and includes group", e
        )

    # POST /management/groups/{group_name}/members/{username}
    try:
        r = mms(
            "POST",
            f"/management/groups/{GROUP_NAME}/members/{standard_user}",
            token=admin_token,
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["group_name"] == GROUP_NAME
        assert body["ro_group_name"] is None
        assert set(body["members"]) == {admin_user, standard_user}, (
            f"expected members {{{admin_user!r}, {standard_user!r}}}, "
            f"got {body['members']}"
        )
        assert body["member_count"] == 2
        assert body["operation"] == "add_member"
        assert body["performed_by"] == admin_user
        assert_timestamp(body["timestamp"], "timestamp")
        ok("POST /management/groups/{group_name}/members/{username} adds member")
    except Exception as e:
        fail("POST /management/groups/{group_name}/members/{username} adds member", e)

    # GET /management/groups — verify membership persisted server-side
    try:
        r = mms("GET", "/management/groups", token=admin_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        groups_by_name = {g["group_name"]: g for g in body["groups"]}
        entry = groups_by_name[GROUP_NAME]
        assert set(entry["members"]) == {admin_user, standard_user}, (
            f"expected {GROUP_NAME!r} members {{{admin_user!r}, {standard_user!r}}} "
            f"after add, got {entry['members']}"
        )
        assert entry["member_count"] == 2, (
            f"expected member_count 2 after add, got {entry['member_count']}"
        )
        ok("GET /management/groups reflects added member")
    except Exception as e:
        fail("GET /management/groups reflects added member", e)

    # DELETE /management/groups/{group_name}/members/{username}
    try:
        r = mms(
            "DELETE",
            f"/management/groups/{GROUP_NAME}/members/{standard_user}",
            token=admin_token,
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["group_name"] == GROUP_NAME
        assert body["ro_group_name"] is None
        assert body["members"] == [admin_user], (
            f"expected members [{admin_user!r}] after remove, got {body['members']}"
        )
        assert body["member_count"] == 1
        assert body["operation"] == "remove_member"
        assert body["performed_by"] == admin_user
        assert_timestamp(body["timestamp"], "timestamp")
        ok("DELETE /management/groups/{group_name}/members/{username} removes member")
    except Exception as e:
        fail(
            "DELETE /management/groups/{group_name}/members/{username} removes member",
            e,
        )

    # Re-add standard user for subsequent tests
    mms(
        "POST",
        f"/management/groups/{GROUP_NAME}/members/{standard_user}",
        token=admin_token,
    )


def test_workspaces_group(
    admin_user: str, standard_token: str, standard_user: str
) -> None:
    # GET /workspaces/me/groups/{group_name}
    try:
        r = mms("GET", f"/workspaces/me/groups/{GROUP_NAME}", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["group_name"] == GROUP_NAME
        assert set(body["members"]) == {admin_user, standard_user}, (
            f"expected members {{{admin_user!r}, {standard_user!r}}}, "
            f"got {body['members']}"
        )
        assert body["member_count"] == 2
        # accessible_paths reflects the group policy only, not the user's full set
        assert set(body["accessible_paths"]) == {
            f"s3a://{BUCKET}/{TENANT_GENERAL_PREFIX}/{GROUP_NAME}/",
            f"s3a://{BUCKET}/{TENANT_SQL_PREFIX}/{GROUP_NAME}/",
            f"s3a://{BUCKET}/{TENANT_SQL_PREFIX}/{GROUP_NAME}/{GROUP_NAME}_*/",
        }, f"unexpected group accessible_paths: {body['accessible_paths']}"
        ok("GET /workspaces/me/groups/{group_name} returns group workspace")
    except Exception as e:
        fail("GET /workspaces/me/groups/{group_name} returns group workspace", e)

    # GET /workspaces/me/groups/{group_name}/sql-warehouse-prefix
    try:
        r = mms(
            "GET",
            f"/workspaces/me/groups/{GROUP_NAME}/sql-warehouse-prefix",
            token=standard_token,
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["group_name"] == GROUP_NAME
        expected_prefix = f"s3a://{BUCKET}/{TENANT_SQL_PREFIX}/{GROUP_NAME}/"
        assert body["sql_warehouse_prefix"] == expected_prefix, (
            f"expected sql_warehouse_prefix {expected_prefix!r}, "
            f"got {body['sql_warehouse_prefix']!r}"
        )
        ok("GET /workspaces/me/groups/{group_name}/sql-warehouse-prefix returns prefix")
    except Exception as e:
        fail(
            "GET /workspaces/me/groups/{group_name}/sql-warehouse-prefix returns prefix",
            e,
        )

    # GET /workspaces/me/namespace-prefix?tenant={GROUP_NAME}
    try:
        r = mms(
            "GET",
            f"/workspaces/me/namespace-prefix?tenant={GROUP_NAME}",
            token=standard_token,
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        assert body["user_namespace_prefix"] == f"u_{standard_user}__", (
            f"expected user_namespace_prefix 'u_{standard_user}__', "
            f"got {body['user_namespace_prefix']!r}"
        )
        assert body["tenant"] == GROUP_NAME
        assert body["tenant_namespace_prefix"] == f"{GROUP_NAME}_", (
            f"expected tenant_namespace_prefix '{GROUP_NAME}_', "
            f"got {body['tenant_namespace_prefix']!r}"
        )
        ok("GET /workspaces/me/namespace-prefix?tenant=... returns tenant prefix")
    except Exception as e:
        fail("GET /workspaces/me/namespace-prefix?tenant=... returns tenant prefix", e)

    # Non-member cannot access group workspace
    try:
        other_name = f"{GROUP_NAME}-nonexistent"
        r = mms("GET", f"/workspaces/me/groups/{other_name}", token=standard_token)
        assert r.status_code in (400, 404), (
            f"expected 400/404 for non-member group, got {r.status_code}"
        )
        ok("GET /workspaces/me/groups/{group_name} returns error for non-member")
    except Exception as e:
        fail("GET /workspaces/me/groups/{group_name} returns error for non-member", e)


def test_tenants(
    admin_token: str,
    admin_user: str,
    standard_token: str,
    standard_user: str,
) -> None:
    # POST /tenants/{tenant_name} — idempotent: group creation already pre-seeded metadata
    # via ensure_metadata (display_name=tenant_name). Fields in the body are ignored.
    try:
        r = mms(
            "POST",
            f"/tenants/{GROUP_NAME}",
            token=admin_token,
            json={
                "display_name": "Integration Test Group",
                "description": "Created by MMS API integration test",
                "organization": "Test Org",
            },
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["tenant_name"] == GROUP_NAME
        # Existing record is returned unchanged — body fields are not applied
        assert body["display_name"] == GROUP_NAME, (
            f"expected display_name='{GROUP_NAME}' (pre-seeded, not updated), "
            f"got '{body['display_name']}'"
        )
        assert body["description"] is None
        assert body["website"] is None
        assert body["organization"] is None
        assert body["created_by"] == admin_user, (
            f"expected created_by {admin_user!r}, got {body['created_by']!r}"
        )
        assert_timestamp(body["created_at"], "created_at")
        # updated_at is set to the creation time on insert (not NULL), even
        # though no update has occurred — updated_by remains NULL
        assert_timestamp(body["updated_at"], "updated_at")
        assert body["updated_by"] is None
        ok(
            "POST /tenants/{tenant_name} is idempotent and does not update existing fields"
        )
    except Exception as e:
        fail("POST /tenants/{tenant_name} creates tenant metadata", e)

    # GET /tenants
    try:
        r = mms("GET", "/tenants", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        # Tenants are all non-RO groups sorted alphabetically. At this point that is
        # globalusers and GROUP_NAME. standard_user is in both (re-added to GROUP_NAME
        # at the end of test_management_groups). RO group members are included in
        # member_count but both tenants have 2 unique members (admin + standard).
        # display_name defaults to tenant_name; description/website/org are all None
        # (PATCH hasn't run yet).
        expected_entries = [
            {
                "tenant_name": GLOBALUSERS,
                "display_name": None,  # no POST /tenants/globalusers ever called
                "description": None,
                "website": None,
                "organization": None,
                "member_count": 2,
                "is_member": True,
                "is_steward": False,
            },
            {
                "tenant_name": GROUP_NAME,
                "display_name": GROUP_NAME,
                "description": None,
                "website": None,
                "organization": None,
                "member_count": 2,
                "is_member": True,
                "is_steward": False,
            },
        ]
        assert body == expected_entries
        ok("GET /tenants lists the created tenant")
    except Exception as e:
        fail("GET /tenants lists the created tenant", e)

    # GET /tenants/{tenant_name}
    try:
        r = mms("GET", f"/tenants/{GROUP_NAME}", token=standard_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        meta = body["metadata"]
        assert meta["tenant_name"] == GROUP_NAME
        assert meta["display_name"] == GROUP_NAME
        assert meta["description"] is None  # no update yet
        assert meta["website"] is None
        assert meta["organization"] is None
        assert meta["created_by"] == admin_user
        assert_timestamp(meta["created_at"], "created_at")
        assert_timestamp(meta["updated_at"], "updated_at")
        assert meta["updated_by"] is None
        # Both users are RW members (standard_user re-added at end of
        # test_management_groups); admin_user is also in the RO shadow but RW
        # takes precedence. RW members are emitted sorted alphabetically, RO-only
        # members after — there are none here.
        assert body["member_count"] == 2
        assert [m["username"] for m in body["members"]] == sorted(
            [admin_user, standard_user]
        ), (
            f"expected members sorted as {sorted([admin_user, standard_user])}, "
            + f"got {[m['username'] for m in body['members']]}"
        )
        for m in body["members"]:
            assert m["access_level"] == "read_write", (
                f"expected access_level 'read_write' for {m['username']!r}, "
                f"got {m['access_level']!r}"
            )
            assert m["is_steward"] is False, (
                f"expected is_steward False for {m['username']!r}"
            )
            assert "display_name" in m  # from KBase profile; may be None
            assert "email" in m  # from KBase profile; may be None
        assert body["stewards"] == []
        assert body["storage_paths"] == {
            "general_warehouse": f"s3a://{BUCKET}/{TENANT_GENERAL_PREFIX}/{GROUP_NAME}/",
            "sql_warehouse": f"s3a://{BUCKET}/{TENANT_SQL_PREFIX}/{GROUP_NAME}/",
            "namespace_prefix": f"{GROUP_NAME}_",
        }
        ok("GET /tenants/{tenant_name} returns full tenant detail")
    except Exception as e:
        fail("GET /tenants/{tenant_name} returns full tenant detail", e)

    # PATCH /tenants/{tenant_name}
    try:
        r = mms(
            "PATCH",
            f"/tenants/{GROUP_NAME}",
            token=admin_token,
            json={"description": "Updated description"},
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["tenant_name"] == GROUP_NAME
        assert body["display_name"] == GROUP_NAME  # unchanged
        assert body["description"] == "Updated description"
        assert body["website"] is None
        assert body["organization"] is None
        assert body["created_by"] == admin_user
        assert body["updated_by"] == admin_user, (
            f"expected updated_by {admin_user!r}, got {body['updated_by']!r}"
        )
        assert_timestamp(body["updated_at"], "created_at")
        assert_timestamp(body["updated_at"], "updated_at")
        ok("PATCH /tenants/{tenant_name} updates metadata")
    except Exception as e:
        fail("PATCH /tenants/{tenant_name} updates metadata", e)

    # GET /tenants/{tenant_name}/members
    try:
        r = mms("GET", f"/tenants/{GROUP_NAME}/members", token=admin_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        members = r.json()
        # Same membership as the detail call above: both users in the RW group,
        # admin_user also in the RO shadow but RW takes precedence. Sorted alphabetically.
        assert [m["username"] for m in members] == sorted(
            [admin_user, standard_user]
        ), (
            f"expected members {sorted([admin_user, standard_user])}, "
            f"got {[m['username'] for m in members]}"
        )
        for m in members:
            assert m["access_level"] == "read_write", (
                f"expected access_level 'read_write' for {m['username']!r}, "
                f"got {m['access_level']!r}"
            )
            assert m["is_steward"] is False, (
                f"expected is_steward False for {m['username']!r}"
            )
            assert "display_name" in m  # from KBase profile; may be None
            assert "email" in m  # from KBase profile; may be None
        ok("GET /tenants/{tenant_name}/members returns member list")
    except Exception as e:
        fail("GET /tenants/{tenant_name}/members returns member list", e)

    # DELETE /tenants/{tenant_name}/members/{username}
    # Remove standard_user first so the POST below is a genuine add, not a no-op
    # (standard_user is already in GROUP_NAME from test_management_groups re-add).
    try:
        r = mms(
            "DELETE",
            f"/tenants/{GROUP_NAME}/members/{standard_user}",
            token=admin_token,
        )
        assert r.status_code == 204, f"expected 204, got {r.status_code}: {r.text}"
        ok(
            "DELETE /tenants/{tenant_name}/members/{username} removes member (pre-POST setup)"
        )
    except Exception as e:
        fail(
            "DELETE /tenants/{tenant_name}/members/{username} removes member (pre-POST setup)",
            e,
        )

    # POST /tenants/{tenant_name}/members/{username}
    try:
        r = mms(
            "POST",
            f"/tenants/{GROUP_NAME}/members/{standard_user}?permission=read_only",
            token=admin_token,
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        assert body["access_level"] == "read_only"
        assert body["is_steward"] is False
        assert "display_name" in body  # from KBase Auth; may be None
        assert "email" in body  # from KBase Auth; may be None
        ok("POST /tenants/{tenant_name}/members/{username} adds member")
    except Exception as e:
        fail("POST /tenants/{tenant_name}/members/{username} adds member", e)

    # GET /tenants/{tenant_name}/stewards
    try:
        r = mms("GET", f"/tenants/{GROUP_NAME}/stewards", token=admin_token)
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        stewards = r.json()
        # no stewards have been assigned yet
        assert stewards == [], f"expected empty steward list, got {stewards}"
        ok("GET /tenants/{tenant_name}/stewards returns steward list")
    except Exception as e:
        fail("GET /tenants/{tenant_name}/stewards returns steward list", e)

    # POST /tenants/{tenant_name}/stewards/{username}
    try:
        r = mms(
            "POST",
            f"/tenants/{GROUP_NAME}/stewards/{standard_user}",
            token=admin_token,
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["username"] == standard_user
        assert body["assigned_by"] == admin_user
        assert_timestamp(body["assigned_at"], "assigned_at")
        assert "display_name" in body  # from KBase Auth; may be None
        assert "email" in body  # from KBase Auth; may be None
        ok("POST /tenants/{tenant_name}/stewards/{username} assigns steward")
    except Exception as e:
        fail("POST /tenants/{tenant_name}/stewards/{username} assigns steward", e)

    # DELETE /tenants/{tenant_name}/stewards/{username}
    try:
        r = mms(
            "DELETE",
            f"/tenants/{GROUP_NAME}/stewards/{standard_user}",
            token=admin_token,
        )
        assert r.status_code == 204, f"expected 204, got {r.status_code}: {r.text}"
        ok("DELETE /tenants/{tenant_name}/stewards/{username} removes steward")
    except Exception as e:
        fail("DELETE /tenants/{tenant_name}/stewards/{username} removes steward", e)

    # DELETE /tenants/{tenant_name}/members/{username}
    try:
        r = mms(
            "DELETE",
            f"/tenants/{GROUP_NAME}/members/{standard_user}",
            token=admin_token,
        )
        assert r.status_code == 204, f"expected 204, got {r.status_code}: {r.text}"
        ok("DELETE /tenants/{tenant_name}/members/{username} removes member")
    except Exception as e:
        fail("DELETE /tenants/{tenant_name}/members/{username} removes member", e)

    # POST /tenants/{tenant_name} — group does not exist → 404
    try:
        r = mms("POST", "/tenants/nonexistentgroup", token=admin_token)
        assert r.status_code == 404, (
            f"expected 404 for create on non-existent group, got {r.status_code}: {r.text}"
        )
        ok("POST /tenants/{tenant_name} returns 404 when group does not exist")
    except Exception as e:
        fail("POST /tenants/{tenant_name} returns 404 when group does not exist", e)

    # PATCH /tenants/{tenant_name} — group does not exist → 404
    try:
        r = mms(
            "PATCH",
            "/tenants/nonexistentgroup",
            token=admin_token,
            json={"description": "should not apply"},
        )
        assert r.status_code == 404, (
            f"expected 404 for update on non-existent group, got {r.status_code}: {r.text}"
        )
        ok("PATCH /tenants/{tenant_name} returns 404 when group does not exist")
    except Exception as e:
        fail("PATCH /tenants/{tenant_name} returns 404 when group does not exist", e)

    # Non-admin cannot update metadata
    try:
        r = mms(
            "PATCH",
            f"/tenants/{GROUP_NAME}",
            token=standard_token,
            json={"description": "Should be forbidden"},
        )
        assert r.status_code in (401, 403), (
            f"expected 401/403 for non-steward PATCH, got {r.status_code}"
        )
        ok("PATCH /tenants/{tenant_name} returns 401/403 for non-steward/admin")
    except Exception as e:
        fail("PATCH /tenants/{tenant_name} returns 401/403 for non-steward/admin", e)


def test_sharing(admin_token: str, admin_user: str, standard_user: str) -> None:
    path = share_path(admin_user)

    # POST /sharing/share
    try:
        r = mms(
            "POST",
            "/sharing/share",
            token=admin_token,
            json={"path": path, "with_users": [standard_user], "permission": "read"},
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["path"] == path
        assert body["shared_with_users"] == [standard_user], (
            f"expected shared_with_users [{standard_user!r}], "
            f"got {body['shared_with_users']}"
        )
        assert body["shared_with_groups"] == []
        assert body["success_count"] == 1
        assert body["errors"] == []
        assert body["shared_by"] == admin_user
        assert_timestamp(body["shared_at"], "shared_at")
        ok("POST /sharing/share shares path with user")
    except Exception as e:
        fail("POST /sharing/share shares path with user", e)

    # POST /sharing/get_path_access_info
    try:
        r = mms(
            "POST",
            "/sharing/get_path_access_info",
            token=admin_token,
            json={"path": path},
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["path"] == path
        # Both the owner (admin_user) and the newly-shared user appear: the endpoint
        # returns everyone whose home policy covers this path.
        assert set(body["users"]) == {admin_user, standard_user}, (
            f"expected users {{{admin_user!r}, {standard_user!r}}}, got {body['users']}"
        )
        assert body["groups"] == []
        assert body["public"] is False
        ok("POST /sharing/get_path_access_info reflects the share")
    except Exception as e:
        fail("POST /sharing/get_path_access_info reflects the share", e)

    # POST /sharing/unshare
    try:
        r = mms(
            "POST",
            "/sharing/unshare",
            token=admin_token,
            json={"path": path, "from_users": [standard_user]},
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["path"] == path
        assert body["unshared_from_users"] == [standard_user], (
            f"expected unshared_from_users [{standard_user!r}], "
            f"got {body['unshared_from_users']}"
        )
        assert body["unshared_from_groups"] == []
        assert body["success_count"] == 1
        assert body["errors"] == []
        assert body["unshared_by"] == admin_user
        assert_timestamp(body["unshared_at"], "unshared_at")
        ok("POST /sharing/unshare removes user access")
    except Exception as e:
        fail("POST /sharing/unshare removes user access", e)

    # POST /sharing/make-public
    try:
        r = mms(
            "POST",
            "/sharing/make-public",
            token=admin_token,
            json={"path": path},
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["path"] == path
        assert body["is_public"] is True
        ok("POST /sharing/make-public makes path public")
    except Exception as e:
        fail("POST /sharing/make-public makes path public", e)

    # POST /sharing/make-private
    try:
        r = mms(
            "POST",
            "/sharing/make-private",
            token=admin_token,
            json={"path": path},
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        assert body["path"] == path
        assert body["is_public"] is False
        ok("POST /sharing/make-private makes path private")
    except Exception as e:
        fail("POST /sharing/make-private makes path private", e)

    # Cannot share another user's path
    try:
        other_path = share_path(standard_user)
        r = mms(
            "POST",
            "/sharing/share",
            token=admin_token,
            json={
                "path": other_path,
                "with_users": [standard_user],
                "permission": "read",
            },
        )
        assert r.status_code in (400, 403), (
            f"expected 400/403 when sharing another user's path, got {r.status_code}"
        )
        ok("POST /sharing/share returns 400/403 when sharing another user's path")
    except Exception as e:
        fail("POST /sharing/share returns 400/403 when sharing another user's path", e)


def test_migrate(admin_token: str, admin_user: str) -> None:
    # TODO this doesn't actually check anything changed serverside. Not worth the trouble for now
    try:
        r = mms(
            "POST",
            "/management/migrate/regenerate-policies",
            token=admin_token,
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        body = r.json()
        # 2 users (admin + standard); 4 group policies (globalusers RW+RO,
        # GROUP_NAME RW+RO)
        assert body["users_updated"] == 2, (
            f"expected users_updated 2, got {body['users_updated']}"
        )
        assert body["groups_updated"] == 4, (
            f"expected groups_updated 4, got {body['groups_updated']}"
        )
        assert body["errors"] == [], f"regenerate-policies had errors: {body['errors']}"
        assert body["performed_by"] == admin_user, (
            f"expected performed_by {admin_user!r}, got {body['performed_by']!r}"
        )
        assert_timestamp(body["timestamp"], "timestamp")
        ok("POST /management/migrate/regenerate-policies succeeds with no errors")
    except Exception as e:
        fail("POST /management/migrate/regenerate-policies succeeds with no errors", e)


async def _verify_cleanup(admin_user: str, standard_user: str) -> list[str]:
    """Use direct IAM and S3 clients to confirm all resources are gone from Ceph."""
    errors = []

    iam = await S3IAMClient.create(
        endpoint_url=CEPH_ENDPOINT,
        access_key=CEPH_ACCESS_KEY,
        secret_key=CEPH_SECRET_KEY,
        path_prefix=IAM_PATH_PREFIX,
    )
    try:
        for username in [admin_user, standard_user]:
            if await iam.user_exists(username):
                errors.append(f"IAM user still exists after cleanup: {username!r}")
        for group in [GLOBALUSERS, f"{GLOBALUSERS}ro", GROUP_NAME, f"{GROUP_NAME}ro"]:
            if await iam.group_exists(group):
                errors.append(f"IAM group still exists after cleanup: {group!r}")
    finally:
        await iam.close()

    s3_config = S3Config(
        endpoint=CEPH_ENDPOINT,
        access_key=CEPH_ACCESS_KEY,
        secret_key=CEPH_SECRET_KEY,
        secure=False,
    )
    async with S3Client(s3_config) as s3:
        # User home and system directories
        for username in [admin_user, standard_user]:
            for prefix in [
                f"{USERS_GENERAL_PREFIX}/{username}/",
                f"{USERS_SQL_PREFIX}/{username}/",
            ]:
                objects = await s3.list_objects(BUCKET, prefix)
                if objects:
                    errors.append(f"S3 objects remain at {BUCKET}/{prefix}: {objects}")
            spark_prefix = f"{SPARK_LOGS_PREFIX}/{username}/"
            if await s3.bucket_exists(SPARK_LOGS_BUCKET):
                objects = await s3.list_objects(SPARK_LOGS_BUCKET, spark_prefix)
                if objects:
                    errors.append(
                        f"S3 objects remain at {SPARK_LOGS_BUCKET}/{spark_prefix}: {objects}"
                    )

        # Group tenant directories (both the test group and globalusers)
        for group in [GLOBALUSERS, GROUP_NAME]:
            for prefix in [
                f"{TENANT_GENERAL_PREFIX}/{group}/",
                f"{TENANT_SQL_PREFIX}/{group}/",
            ]:
                objects = await s3.list_objects(BUCKET, prefix)
                if objects:
                    errors.append(f"S3 objects remain at {BUCKET}/{prefix}: {objects}")

    return errors


def cleanup(admin_token: str, admin_user: str, standard_user: str) -> None:
    errors = []

    def check_delete_response(
        r: requests.Response,
        path: str,
        resource_type: str,
        resource_name: str,
    ) -> None:
        if r.status_code != 200:
            errors.append(f"DELETE {path}: expected 200, got {r.status_code} {r.text}")
            return
        body = r.json()
        if body.get("resource_type") != resource_type:
            errors.append(
                f"DELETE {path}: expected resource_type {resource_type!r}, "
                f"got {body.get('resource_type')!r}"
            )
        if body.get("resource_name") != resource_name:
            errors.append(
                f"DELETE {path}: expected resource_name {resource_name!r}, "
                f"got {body.get('resource_name')!r}"
            )
        expected_msg = (
            f"{resource_type.capitalize()} {resource_name} deleted successfully"
        )
        if body.get("message") != expected_msg:
            errors.append(
                f"DELETE {path}: expected message {expected_msg!r}, "
                f"got {body.get('message')!r}"
            )

    # Delete tenant metadata (204 no content)
    r = mms("DELETE", f"/tenants/{GROUP_NAME}", token=admin_token)
    if r.status_code != 204:
        errors.append(
            f"DELETE /tenants/{GROUP_NAME}: expected 204, got {r.status_code} {r.text}"
        )

    # Delete group (also deletes RO shadow and S3 workspace)
    r = mms("DELETE", f"/management/groups/{GROUP_NAME}", token=admin_token)
    check_delete_response(r, f"/management/groups/{GROUP_NAME}", "group", GROUP_NAME)

    # Delete globalusers (and its RO shadow, which delete_group handles automatically)
    # so the next run starts from a clean state. Without this, globalusers persists
    # between runs and create_group is skipped in create_user, meaning the admin user
    # is not added to globalusersro (group_manager.py:126).
    r = mms("DELETE", f"/management/groups/{GLOBALUSERS}", token=admin_token)
    check_delete_response(r, f"/management/groups/{GLOBALUSERS}", "group", GLOBALUSERS)

    # Delete both users
    for username in [admin_user, standard_user]:
        r = mms("DELETE", f"/management/users/{username}", token=admin_token)
        check_delete_response(r, f"/management/users/{username}", "user", username)

    errors.extend(asyncio.run(_verify_cleanup(admin_user, standard_user)))

    if errors:
        fail("cleanup", Exception("\n  ".join(errors)))
    else:
        ok("cleanup")


def pre_cleanup(admin_token: str, admin_user: str, standard_user: str) -> None:
    """Best-effort removal of any state left over from a previous interrupted run."""
    mms("DELETE", f"/tenants/{GROUP_NAME}", token=admin_token)
    mms("DELETE", f"/management/groups/{GROUP_NAME}", token=admin_token)
    mms("DELETE", f"/management/groups/{GLOBALUSERS}", token=admin_token)
    for username in [admin_user, standard_user, EPHEMERAL_USER]:
        mms("DELETE", f"/management/users/{username}", token=admin_token)


# ── Entry point ───────────────────────────────────────────────────────────────


def resolve_tokens() -> tuple[str, str, str, str]:
    """Fetch tokens from environment, resolve usernames, and validate roles.

    Returns (admin_token, standard_token, admin_user, standard_user). Exits
    with an error message on any failure: missing env vars, auth lookup
    failure, same-user tokens, or incorrect role assignments.
    """
    standard_token = os.environ.get("INTEG_TEST_KBASE_TOKEN_STANDARD")
    admin_token = os.environ.get("INTEG_TEST_KBASE_TOKEN_ADMIN")

    if not standard_token:
        print("ERROR: INTEG_TEST_KBASE_TOKEN_STANDARD is not set")
        sys.exit(1)
    if not admin_token:
        print("ERROR: INTEG_TEST_KBASE_TOKEN_ADMIN is not set")
        sys.exit(1)

    try:
        admin_user = lookup_username(admin_token)
        standard_user = lookup_username(standard_token)
        admin_roles = lookup_custom_roles(admin_token)
        standard_roles = lookup_custom_roles(standard_token)
    except Exception as e:
        print(f"ERROR: Failed to look up user info from KBase auth: {e}")
        sys.exit(1)

    if admin_user == standard_user:
        print(
            f"ERROR: both tokens resolve to the same user ({admin_user}); "
            "INTEG_TEST_KBASE_TOKEN_STANDARD and INTEG_TEST_KBASE_TOKEN_ADMIN "
            "must belong to different accounts"
        )
        sys.exit(1)

    errors = []
    if ADMIN_ROLE not in admin_roles:
        errors.append(
            f"admin token (user: {admin_user}) is missing required role {ADMIN_ROLE!r}"
        )
    if REQUIRED_ROLE not in admin_roles:
        errors.append(
            f"admin token (user: {admin_user}) is missing required role {REQUIRED_ROLE!r}"
        )
    if REQUIRED_ROLE not in standard_roles:
        errors.append(
            f"standard token (user: {standard_user}) is missing required role {REQUIRED_ROLE!r}"
        )
    if ADMIN_ROLE in standard_roles:
        errors.append(
            f"standard token (user: {standard_user}) has admin role {ADMIN_ROLE!r}; "
            "use a non-admin account for INTEG_TEST_KBASE_TOKEN_STANDARD"
        )
    if errors:
        for msg in errors:
            print(f"ERROR: {msg}")
        sys.exit(1)

    return admin_token, standard_token, admin_user, standard_user


def main() -> None:
    admin_token, standard_token, admin_user, standard_user = resolve_tokens()

    print(f"\nMMS API integration test — {MMS_URL}")
    print(f"  admin user:    {admin_user}")
    print(f"  standard user: {standard_user}\n")

    pre_cleanup(admin_token, admin_user, standard_user)

    test_health()

    # /credentials/ must run first — creates both users as IAM accounts
    test_credentials(admin_token, admin_user, standard_token, standard_user)

    test_workspaces(standard_token, standard_user)
    test_management_users(admin_token, admin_user, standard_user)
    test_admin_only_endpoints(standard_token)

    # Groups must be created before group workspace and tenant tests
    test_management_groups(admin_token, admin_user, standard_token, standard_user)
    test_workspaces_group(admin_user, standard_token, standard_user)
    test_tenants(admin_token, admin_user, standard_token, standard_user)

    test_sharing(admin_token, admin_user, standard_user)
    test_migrate(admin_token, admin_user)

    cleanup(admin_token, admin_user, standard_user)

    print(f"\n{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("Failed tests:")
        for name in failed:
            print(f"  - {name}")
        sys.exit(1)


main()
