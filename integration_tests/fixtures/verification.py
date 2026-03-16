"""
MinIO verification fixtures for integration tests.

Provides access to MinIO state verification through the
MinIOVerifier in utils/minio_admin.py, which uses ``mc admin`` CLI commands.
"""

from typing import Any, Dict

import pytest

from utils.minio_admin import MinIOVerifier


@pytest.fixture(scope="session")
def minio_verifier(test_config):
    """
    MinIO state verification helper.

    Session-scoped as the verifier is stateless and thread-safe.

    Returns:
        MinIOVerifier: Verifier backed by ``mc admin`` CLI

    Example:
        def test_user_created(minio_verifier, temp_user):
            assert minio_verifier.user_exists(temp_user["username"])
    """
    return MinIOVerifier(
        endpoint=test_config["minio_endpoint"],
        root_user=test_config["minio_root_user"],
        root_password=test_config["minio_root_password"],
    )


@pytest.fixture(scope="function")
def verify_user_state(minio_verifier):
    """
    Helper fixture for verifying user state.

    Returns a callable that performs comprehensive user verification.

    Example:
        def test_user(verify_user_state, temp_user):
            state = verify_user_state(temp_user["username"])
            assert state["exists"]
            assert state["has_home_policy"]
    """

    def _verify(username: str) -> Dict[str, Any]:
        return {
            "exists": minio_verifier.user_exists(username),
            "info": minio_verifier.get_user_info(username),
            "groups": minio_verifier.get_user_groups(username),
            "policies": minio_verifier.get_user_policies(username),
            "accessible_paths": minio_verifier.get_user_accessible_paths(username),
        }

    return _verify


@pytest.fixture(scope="function")
def verify_group_state(minio_verifier):
    """
    Helper fixture for verifying group state.

    Returns a callable that performs comprehensive group verification.

    Example:
        def test_group(verify_group_state, temp_group):
            state = verify_group_state(temp_group["group_name"])
            assert state["exists"]
    """

    def _verify(group_name: str) -> Dict[str, Any]:
        return {
            "exists": minio_verifier.group_exists(group_name),
            "info": minio_verifier.get_group_info(group_name),
            "members": minio_verifier.get_group_members(group_name),
            "policies": minio_verifier.get_group_policies(group_name),
        }

    return _verify


@pytest.fixture(scope="function")
def verify_sharing_state(minio_verifier):
    """
    Helper fixture for verifying sharing/policy state.

    Returns a callable that checks if a path is accessible to a user.

    Example:
        def test_sharing(verify_sharing_state, temp_user):
            accessible = verify_sharing_state(
                username=temp_user["username"],
                path="s3a://bucket/path/"
            )
            assert accessible
    """

    def _verify(username: str, path: str) -> bool:
        accessible_paths = minio_verifier.get_user_accessible_paths(username)
        # Check if the path or any parent is accessible
        for accessible_path in accessible_paths:
            if path.startswith(accessible_path) or accessible_path.startswith(path):
                return True
        return False

    return _verify
