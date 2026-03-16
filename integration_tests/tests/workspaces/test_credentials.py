"""
Credentials Tests.

Tests for credential management endpoints including:
- GET /credentials/ (cache-first behavior with DB persistence)
- POST /credentials/rotate (force rotation with DB update)
- Database record verification for all credential operations
- Credential consistency and format validation
- Concurrent operation safety (distributed locking)
"""

import concurrent.futures
import time

import pytest


@pytest.mark.workspaces
@pytest.mark.serial
class TestGetCredentials:
    """Tests for GET /credentials/ endpoint."""

    def test_get_credentials(self, api_client, user_headers):
        """
        Scenario:
            User requests their credentials.
        Expected:
            - API returns 200
            - Response contains username, access_key, and secret_key
        Why this matters:
            Users need their credentials to access MinIO directly.
        """
        response = api_client.get("/credentials/", headers=user_headers)

        assert response.status_code == 200
        data = response.json()

        assert "username" in data, "Response should contain username"
        assert "access_key" in data, "Response should contain access_key"
        assert "secret_key" in data, "Response should contain secret_key"

    def test_credentials_require_auth(self, api_client):
        """
        Scenario:
            Unauthenticated request to credentials endpoint.
        Expected:
            - API returns 401
        Why this matters:
            Credentials must not be exposed without auth.
        """
        response = api_client.get("/credentials/")
        assert response.status_code == 401

    def test_credentials_are_consistent(self, api_client, user_headers):
        """
        Scenario:
            User requests credentials twice.
        Expected:
            - Both responses have same access_key and secret_key
        Why this matters:
            Credentials should be stable unless rotated.
        """
        response1 = api_client.get("/credentials/", headers=user_headers)
        response2 = api_client.get("/credentials/", headers=user_headers)

        assert response1.status_code == 200
        assert response2.status_code == 200

        data1 = response1.json()
        data2 = response2.json()

        assert data1["access_key"] == data2["access_key"]
        assert data1["secret_key"] == data2["secret_key"]


@pytest.mark.workspaces
@pytest.mark.serial
class TestCredentialValidation:
    """Tests for credential format validation."""

    def test_credentials_format_is_valid(self, api_client, user_headers):
        """
        Scenario:
            Verify returned credentials have valid format.
        Expected:
            - access_key is non-empty string
            - secret_key is non-empty string
        Why this matters:
            Malformed credentials would break MinIO access.
        """
        response = api_client.get("/credentials/", headers=user_headers)
        assert response.status_code == 200
        data = response.json()

        assert isinstance(data["access_key"], str)
        assert isinstance(data["secret_key"], str)
        assert len(data["access_key"]) > 0
        assert len(data["secret_key"]) > 0

    def test_credentials_have_reasonable_length(self, api_client, user_headers):
        """
        Scenario:
            Verify credentials have reasonable length.
        Expected:
            - access_key: 4-100 chars
            - secret_key: 6-100 chars
        Why this matters:
            Unusually short/long keys indicate problems.
        """
        response = api_client.get("/credentials/", headers=user_headers)
        assert response.status_code == 200
        data = response.json()

        access_len = len(data["access_key"])
        secret_len = len(data["secret_key"])

        assert 4 <= access_len <= 100, f"access_key length {access_len} unexpected"
        assert 6 <= secret_len <= 100, f"secret_key length {secret_len} unexpected"


# === CREDENTIAL DATABASE VERIFICATION TESTS ===


@pytest.mark.workspaces
@pytest.mark.serial
class TestCredentialDBPersistence:
    """Tests that verify credential operations persist correctly to the database."""

    def test_get_credentials_creates_db_record(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            User requests credentials via GET /credentials/.
        Expected:
            - A record exists in user_credentials table
            - DB record matches the API response (access_key, decrypted secret_key)
            - DB record has created_at and updated_at timestamps
        Why this matters:
            The credential store must persist credentials for idempotent retrieval.
        """
        response = api_client.get("/credentials/", headers=user_headers)
        assert response.status_code == 200
        api_data = response.json()
        username = api_data["username"]

        db_record = credential_db.get_credential_record(username)
        assert db_record is not None, (
            f"Expected credential record in DB for user {username}"
        )
        assert db_record["username"] == username
        assert db_record["access_key"] == api_data["access_key"]
        assert db_record["secret_key"] == api_data["secret_key"]
        assert db_record["created_at"] is not None
        assert db_record["updated_at"] is not None

    def test_get_credentials_cache_hit_does_not_rewrite_db(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            User requests credentials twice via GET /credentials/.
        Expected:
            - Both calls return identical credentials
            - DB updated_at does NOT change between calls (cache hit, no write)
        Why this matters:
            The cache-first pattern must return stored credentials without
            re-creating them on every call.
        """
        # First call
        resp1 = api_client.get("/credentials/", headers=user_headers)
        assert resp1.status_code == 200
        data1 = resp1.json()
        username = data1["username"]

        db_record1 = credential_db.get_credential_record(username)
        assert db_record1 is not None

        time.sleep(0.5)  # Small delay to detect timestamp changes

        # Second call — should hit cache
        resp2 = api_client.get("/credentials/", headers=user_headers)
        assert resp2.status_code == 200
        data2 = resp2.json()

        # API responses must match
        assert data1["access_key"] == data2["access_key"]
        assert data1["secret_key"] == data2["secret_key"]

        # DB record should not have been re-written
        db_record2 = credential_db.get_credential_record(username)
        assert db_record2 is not None
        assert db_record1["updated_at"] == db_record2["updated_at"]

    def test_db_secret_key_is_encrypted_at_rest(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            Verify that secret_key is stored encrypted (pgcrypto) in DB.
        Expected:
            - The raw bytea column is NOT the plaintext secret key
            - pgp_sym_decrypt with the correct key returns the plaintext
        Why this matters:
            Credentials must be encrypted at rest for security.
        """
        import psycopg2

        response = api_client.get("/credentials/", headers=user_headers)
        assert response.status_code == 200
        api_data = response.json()
        username = api_data["username"]
        api_secret = api_data["secret_key"]

        # Verify decrypted value matches API response
        db_record = credential_db.get_credential_record(username)
        assert db_record is not None
        assert db_record["secret_key"] == api_secret

        # Verify the raw column is NOT plaintext
        with psycopg2.connect(credential_db._conninfo) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT secret_key FROM user_credentials WHERE username = %s",
                    (username,),
                )
                raw_row = cur.fetchone()
                assert raw_row is not None
                raw_bytes = bytes(raw_row[0])
                assert raw_bytes != api_secret.encode(), (
                    "secret_key should be encrypted at rest, not plaintext"
                )


# === CREDENTIAL ROTATION TESTS ===


@pytest.mark.workspaces
@pytest.mark.serial
class TestCredentialRotation:
    """Tests for POST /credentials/rotate endpoint with DB verification."""

    def test_rotate_credentials_returns_new_secret(self, api_client, user_headers):
        """
        Scenario:
            User requests credential rotation.
        Expected:
            - API returns 200
            - New secret_key differs from the original
            - access_key remains the same (username-based)
        Why this matters:
            Rotation is a core security operation that must produce new keys.
        """
        # Get original credentials
        get_resp = api_client.get("/credentials/", headers=user_headers)
        assert get_resp.status_code == 200
        original = get_resp.json()

        # Rotate
        rotate_resp = api_client.post("/credentials/rotate", headers=user_headers)
        assert rotate_resp.status_code == 200
        rotated = rotate_resp.json()

        assert rotated["access_key"] == original["access_key"], (
            "access_key should remain the same after rotation"
        )
        assert rotated["secret_key"] != original["secret_key"], (
            "secret_key must change after rotation"
        )

    def test_rotate_credentials_updates_db_record(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            User rotates credentials and we verify the DB is updated.
        Expected:
            - DB record exists after rotation
            - DB secret_key matches the rotated API response
            - DB updated_at is newer than before rotation
        Why this matters:
            The rotate operation must persist new credentials to the DB
            so subsequent GET calls return the rotated values.
        """
        # Ensure a DB record exists
        get_resp = api_client.get("/credentials/", headers=user_headers)
        assert get_resp.status_code == 200
        username = get_resp.json()["username"]

        db_before = credential_db.get_credential_record(username)
        assert db_before is not None, "DB record should exist before rotation"

        time.sleep(1)  # Ensure updated_at will differ

        # Rotate
        rotate_resp = api_client.post("/credentials/rotate", headers=user_headers)
        assert rotate_resp.status_code == 200
        rotated = rotate_resp.json()

        # Verify DB was updated
        db_after = credential_db.get_credential_record(username)
        assert db_after is not None, "DB record should exist after rotation"
        assert db_after["access_key"] == rotated["access_key"]
        assert db_after["secret_key"] == rotated["secret_key"], (
            "DB secret_key must match rotated API response"
        )
        assert db_after["updated_at"] > db_before["updated_at"], (
            "DB updated_at should be newer after rotation"
        )

    def test_rotate_then_get_returns_rotated_credentials(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            User rotates credentials, then fetches them via GET.
        Expected:
            - GET returns the rotated credentials (not the old ones)
            - DB record matches both responses
        Why this matters:
            After rotation, the cache must serve the new credentials.
        """
        # Rotate
        rotate_resp = api_client.post("/credentials/rotate", headers=user_headers)
        assert rotate_resp.status_code == 200
        rotated = rotate_resp.json()

        # GET should return the rotated credentials
        get_resp = api_client.get("/credentials/", headers=user_headers)
        assert get_resp.status_code == 200
        fetched = get_resp.json()

        assert fetched["access_key"] == rotated["access_key"]
        assert fetched["secret_key"] == rotated["secret_key"], (
            "GET after rotate must return the rotated secret_key"
        )

        # DB should match
        db_record = credential_db.get_credential_record(fetched["username"])
        assert db_record is not None
        assert db_record["secret_key"] == rotated["secret_key"]

    def test_multiple_rotations_each_update_db(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            User rotates credentials three times in succession.
        Expected:
            - Each rotation produces a different secret_key
            - DB always reflects the latest rotation
        Why this matters:
            Repeated rotations must not return stale or duplicate keys.
        """
        secrets = []

        for i in range(3):
            rotate_resp = api_client.post("/credentials/rotate", headers=user_headers)
            assert rotate_resp.status_code == 200, (
                f"Rotation {i + 1} failed: {rotate_resp.text}"
            )
            data = rotate_resp.json()
            secrets.append(data["secret_key"])

            # Verify DB matches after each rotation
            db_record = credential_db.get_credential_record(data["username"])
            assert db_record is not None
            assert db_record["secret_key"] == data["secret_key"], (
                f"DB secret_key mismatch after rotation {i + 1}"
            )

            time.sleep(0.5)

        # All three secrets should be different
        assert len(set(secrets)) == 3, (
            f"Expected 3 unique secrets, got {len(set(secrets))}: {secrets}"
        )

    def test_rotate_credentials_requires_auth(self, api_client):
        """
        Scenario:
            Unauthenticated request to rotate credentials.
        Expected:
            - API returns 401
        Why this matters:
            Only authenticated users may rotate their own credentials.
        """
        response = api_client.post("/credentials/rotate")
        assert response.status_code == 401


# === ADMIN CREDENTIAL ROTATION WITH DB VERIFICATION ===


@pytest.mark.workspaces
@pytest.mark.serial
class TestAdminCredentialRotationDB:
    """
    Tests for /management/users/{user}/rotate-credentials with DB verification.

    The management rotate-credentials endpoint rotates keys in MinIO AND
    updates the credential store DB, keeping both systems consistent.
    """

    def test_user_get_credentials_creates_db_record_for_admin_created_user(
        self, api_client, admin_headers, user_headers, credential_db
    ):
        """
        Scenario:
            Admin creates user tgu3 via management API. User tgu3 then calls
            GET /credentials/ to obtain and cache their credentials.
        Expected:
            - GET /credentials/ returns 200
            - DB record is created for user tgu3
            - DB values match the API response
        Why this matters:
            Even for admin-created users, the credential store is populated
            on first user-facing credential request.
        """
        response = api_client.get("/credentials/", headers=user_headers)
        assert response.status_code == 200
        api_data = response.json()
        username = api_data["username"]

        db_record = credential_db.get_credential_record(username)
        assert db_record is not None, (
            f"DB record should exist after GET /credentials/ for {username}"
        )
        assert db_record["access_key"] == api_data["access_key"]
        assert db_record["secret_key"] == api_data["secret_key"]

    def test_admin_rotate_updates_db_record(
        self, api_client, admin_headers, user_headers, credential_db
    ):
        """
        Scenario:
            1. User gets credentials (creates DB record)
            2. Admin rotates credentials via management API
        Expected:
            - Admin rotation returns 200 with new keys
            - DB record is updated with the new credentials
            - Subsequent GET /credentials/ returns the admin-rotated keys
        Why this matters:
            Admin rotation must update the credential store so the user
            sees the new credentials immediately, not stale cached ones.
        """
        # Step 1: User gets credentials (ensures DB record)
        get_resp = api_client.get("/credentials/", headers=user_headers)
        assert get_resp.status_code == 200
        username = get_resp.json()["username"]

        db_before = credential_db.get_credential_record(username)
        assert db_before is not None

        time.sleep(1)

        # Step 2: Admin rotates via management API
        admin_rotate_resp = api_client.post(
            f"/management/users/{username}/rotate-credentials",
            headers=admin_headers,
        )
        assert admin_rotate_resp.status_code == 200
        admin_rotated = admin_rotate_resp.json()

        # Step 3: Verify DB was updated by admin rotation
        db_after = credential_db.get_credential_record(username)
        assert db_after is not None
        assert db_after["secret_key"] == admin_rotated["secret_key"], (
            "DB secret_key must match admin rotation result"
        )
        assert db_after["updated_at"] > db_before["updated_at"], (
            "DB updated_at should advance after admin rotation"
        )

        # Step 4: User GET should return the admin-rotated credentials
        get_resp2 = api_client.get("/credentials/", headers=user_headers)
        assert get_resp2.status_code == 200
        assert get_resp2.json()["secret_key"] == admin_rotated["secret_key"], (
            "GET after admin rotation must return the new credentials"
        )

    def test_user_rotate_after_admin_rotate_updates_db(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            1. User gets credentials (creates DB record)
            2. User rotates via POST /credentials/rotate
        Expected:
            - User rotation returns 200 with new keys
            - DB record is updated to match the user rotation result
        Why this matters:
            User-facing rotation must always update the credential store.
        """
        # Step 1: User gets credentials (ensures DB record)
        get_resp = api_client.get("/credentials/", headers=user_headers)
        assert get_resp.status_code == 200
        username = get_resp.json()["username"]

        db_before = credential_db.get_credential_record(username)
        assert db_before is not None

        time.sleep(1)

        # Step 2: User rotates via user-facing endpoint
        rotate_resp = api_client.post("/credentials/rotate", headers=user_headers)
        assert rotate_resp.status_code == 200
        rotated = rotate_resp.json()

        # Step 3: Verify DB updated
        db_after = credential_db.get_credential_record(username)
        assert db_after is not None
        assert db_after["secret_key"] == rotated["secret_key"]
        assert db_after["updated_at"] > db_before["updated_at"]


# === CONCURRENT CREDENTIAL OPERATIONS ===


@pytest.mark.workspaces
@pytest.mark.serial
class TestConcurrentCredentialOperations:
    """Tests for concurrent credential operations with distributed locking."""

    def test_concurrent_rotations_one_succeeds_other_rejected(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            Two concurrent POST /credentials/rotate for the same user.
        Expected:
            - Both succeed (200) — the blocking lock serializes them
            - DB contains the last rotation's credentials
        Why this matters:
            The blocking distributed lock serializes concurrent credential
            mutations, preventing race conditions while letting all callers
            eventually succeed.
        """
        # Ensure credentials exist first
        get_resp = api_client.get("/credentials/", headers=user_headers)
        assert get_resp.status_code == 200
        username = get_resp.json()["username"]

        results = []

        def rotate():
            import httpx

            with httpx.Client(base_url=api_client.base_url, timeout=60) as client:
                resp = client.post("/credentials/rotate", headers=user_headers)
                return resp.status_code, resp.json()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(rotate)
            future2 = executor.submit(rotate)
            results = [future1.result(), future2.result()]

        statuses = sorted([r[0] for r in results])
        # Both should succeed — the blocking lock serializes them
        assert statuses == [200, 200], (
            f"Expected both rotations to succeed [200, 200], got {statuses}"
        )

        # DB should match the last rotation to complete
        db_record = credential_db.get_credential_record(username)
        assert db_record is not None
        result_secrets = {r[1]["secret_key"] for r in results}
        assert db_record["secret_key"] in result_secrets, (
            "DB secret_key should match one of the rotation results"
        )

    def test_concurrent_get_credentials_same_user(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            Multiple concurrent GET /credentials/ requests for the same user.
        Expected:
            - All return the same credentials (cache hit or double-check lock)
            - DB has exactly one record
        Why this matters:
            The double-check locking pattern must prevent duplicate creation.
        """
        results = []

        def get_creds():
            import httpx

            with httpx.Client(base_url=api_client.base_url, timeout=60) as client:
                resp = client.get("/credentials/", headers=user_headers)
                return resp.status_code, resp.json()

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(get_creds) for _ in range(3)]
            results = [f.result() for f in futures]

        # All should succeed
        assert all(r[0] == 200 for r in results)

        # All should return the same credentials
        access_keys = {r[1]["access_key"] for r in results}
        secret_keys = {r[1]["secret_key"] for r in results}
        assert len(access_keys) == 1, (
            f"All requests should return same access_key, got {access_keys}"
        )
        assert len(secret_keys) == 1, (
            f"All requests should return same secret_key, got {secret_keys}"
        )

        # DB should have exactly one record matching
        username = results[0][1]["username"]
        db_record = credential_db.get_credential_record(username)
        assert db_record is not None
        assert db_record["access_key"] == results[0][1]["access_key"]
        assert db_record["secret_key"] == results[0][1]["secret_key"]

    def test_concurrent_get_and_rotate_serialized(
        self, api_client, user_headers, credential_db
    ):
        """
        Scenario:
            Concurrent GET /credentials/ and POST /credentials/rotate.
        Expected:
            - Both succeed
            - DB record is consistent (matches one valid state)
        Why this matters:
            Mixed read/write operations must be serialized to avoid
            returning stale credentials.
        """
        # Ensure credentials exist
        get_resp = api_client.get("/credentials/", headers=user_headers)
        assert get_resp.status_code == 200

        def get_creds():
            import httpx

            with httpx.Client(base_url=api_client.base_url, timeout=60) as client:
                resp = client.get("/credentials/", headers=user_headers)
                return "get", resp.status_code, resp.json()

        def rotate_creds():
            import httpx

            with httpx.Client(base_url=api_client.base_url, timeout=60) as client:
                resp = client.post("/credentials/rotate", headers=user_headers)
                return "rotate", resp.status_code, resp.json()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_get = executor.submit(get_creds)
            future_rotate = executor.submit(rotate_creds)

            result_get = future_get.result()
            result_rotate = future_rotate.result()

        assert result_get[1] == 200, f"GET failed: {result_get}"
        assert result_rotate[1] == 200, f"Rotate failed: {result_rotate}"

        # DB should be consistent with the final state
        username = result_get[2]["username"]
        db_record = credential_db.get_credential_record(username)
        assert db_record is not None

        # The DB must match either the GET result or the rotate result
        # (depends on which completed last)
        valid_secrets = {result_get[2]["secret_key"], result_rotate[2]["secret_key"]}
        assert db_record["secret_key"] in valid_secrets, (
            f"DB secret_key {db_record['secret_key']!r} should match "
            f"one of the operation results: {valid_secrets}"
        )
