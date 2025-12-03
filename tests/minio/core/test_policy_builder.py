"""
Comprehensive tests for the minio.core.policy_builder module.

PolicyBuilder provides pure transformation logic for MinIO policy documents.
No mocks needed - tests use real PolicyModel objects.
"""

import pytest

from src.minio.core.policy_builder import PolicyBuilder
from src.minio.models.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
)
from src.service.exceptions import PolicyOperationError, PolicyValidationError


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def empty_policy_model():
    """Create an empty policy model for testing."""
    return PolicyModel(
        policy_name="test-policy",
        policy_document=PolicyDocument(version="2012-10-17", statement=[]),
    )


@pytest.fixture
def policy_with_list_bucket():
    """Create a policy with a ListBucket statement."""
    return PolicyModel(
        policy_name="test-policy",
        policy_document=PolicyDocument(
            version="2012-10-17",
            statement=[
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.LIST_BUCKET,
                    resource=["arn:aws:s3:::test-bucket"],
                    condition={"StringLike": {"s3:prefix": []}},
                )
            ],
        ),
    )


@pytest.fixture
def policy_with_existing_access():
    """Create a policy with existing path access."""
    return PolicyModel(
        policy_name="test-policy",
        policy_document=PolicyDocument(
            version="2012-10-17",
            statement=[
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.GET_BUCKET_LOCATION,
                    resource=["arn:aws:s3:::test-bucket"],
                ),
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.LIST_BUCKET,
                    resource=["arn:aws:s3:::test-bucket"],
                    condition={
                        "StringLike": {
                            "s3:prefix": [
                                "existing/path",
                                "existing/path/*",
                            ]
                        }
                    },
                ),
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.GET_OBJECT,
                    resource=[
                        "arn:aws:s3:::test-bucket/existing/path",
                        "arn:aws:s3:::test-bucket/existing/path/*",
                    ],
                ),
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.PUT_OBJECT,
                    resource=[
                        "arn:aws:s3:::test-bucket/existing/path",
                        "arn:aws:s3:::test-bucket/existing/path/*",
                    ],
                ),
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=PolicyAction.DELETE_OBJECT,
                    resource=["arn:aws:s3:::test-bucket/existing/path/*"],
                ),
            ],
        ),
    )


# =============================================================================
# TestPolicyBuilderInit - Initialization
# =============================================================================


class TestPolicyBuilderInit:
    """Tests for PolicyBuilder initialization."""

    def test_init_with_valid_policy(self, empty_policy_model):
        """Test initialization with valid policy model."""
        builder = PolicyBuilder(empty_policy_model, "test-bucket")

        assert builder.policy_model is not None
        assert builder.bucket_name == "test-bucket"
        # Should be a deep copy
        assert builder.policy_model is not empty_policy_model

    def test_init_preserves_original_policy(self, empty_policy_model):
        """Test that initialization doesn't modify the original policy."""
        original_stmt_count = len(empty_policy_model.policy_document.statement)
        builder = PolicyBuilder(empty_policy_model, "test-bucket")

        # Modify builder's policy
        builder.policy_model.policy_document.statement.append(
            PolicyStatement(
                effect=PolicyEffect.ALLOW,
                action=PolicyAction.GET_OBJECT,
                resource=["arn:aws:s3:::test-bucket/test/*"],
            )
        )

        # Original should be unchanged
        assert len(empty_policy_model.policy_document.statement) == original_stmt_count


# =============================================================================
# TestPathValidation - Path normalization and validation
# =============================================================================


class TestPathValidation:
    """Tests for path extraction and validation."""

    def test_extract_path_with_s3a_scheme(self, policy_with_list_bucket):
        """Test path extraction from s3a:// URL."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        path = builder._extract_and_validate_path("s3a://test-bucket/path/to/data")
        assert path == "path/to/data"

    def test_extract_path_with_s3_scheme(self, policy_with_list_bucket):
        """Test path extraction from s3:// URL."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        path = builder._extract_and_validate_path("s3://test-bucket/path/to/data")
        assert path == "path/to/data"

    def test_extract_path_with_trailing_slash(self, policy_with_list_bucket):
        """Test path normalization removes trailing slash."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        path = builder._extract_and_validate_path("s3a://test-bucket/path/to/data/")
        assert path == "path/to/data"

    def test_extract_path_with_wildcard_suffix(self, policy_with_list_bucket):
        """Test path normalization removes /* suffix."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        path = builder._extract_and_validate_path("s3a://test-bucket/path/to/data/*")
        assert path == "path/to/data"

    def test_extract_path_preserves_governance_wildcard(self, policy_with_list_bucket):
        """Test that governance wildcard patterns (ending with *) are preserved."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        path = builder._extract_and_validate_path(
            "s3a://test-bucket/users-sql-warehouse/user1/u_user1__*"
        )
        assert path == "users-sql-warehouse/user1/u_user1__*"

    def test_extract_path_wrong_bucket_raises_error(self, policy_with_list_bucket):
        """Test that mismatched bucket name raises error."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")

        with pytest.raises(
            PolicyOperationError, match="does not match configured bucket"
        ):
            builder._extract_and_validate_path("s3a://wrong-bucket/path/to/data")

    def test_extract_path_no_path_component_raises_error(self, policy_with_list_bucket):
        """Test that path without path component raises error."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")

        # Path without any path component after bucket name - validate_s3_path will catch this
        with pytest.raises(PolicyValidationError, match="must include an object key"):
            builder._extract_and_validate_path("s3a://test-bucket")

    def test_extract_path_empty_after_normalization_raises_error(
        self, policy_with_list_bucket
    ):
        """Test that empty path after normalization raises error."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")

        # Trailing slash with no actual path - validate_s3_path will catch this
        with pytest.raises(PolicyValidationError, match="must include an object key"):
            builder._extract_and_validate_path("s3a://test-bucket/")


# =============================================================================
# TestAddPathAccess - Adding path access with different permission levels
# =============================================================================


class TestAddPathAccess:
    """Tests for adding path access to policies."""

    def test_add_read_only_access(self, policy_with_list_bucket):
        """Test adding READ_ONLY access to a path."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        new_builder = builder.add_path_access(
            "s3a://test-bucket/data/read-only",
            PolicyPermissionLevel.READ,
        )

        policy = new_builder.build()

        # Should have GetBucketLocation
        assert any(
            stmt.action == PolicyAction.GET_BUCKET_LOCATION
            for stmt in policy.policy_document.statement
        )

        # Should have ListBucket with prefixes
        list_bucket_stmt = next(
            (
                stmt
                for stmt in policy.policy_document.statement
                if stmt.action == PolicyAction.LIST_BUCKET
            ),
            None,
        )
        assert list_bucket_stmt is not None
        assert "data/read-only" in list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        assert (
            "data/read-only/*" in list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        )

        # Should have GET_OBJECT but not PUT_OBJECT or DELETE_OBJECT
        assert any(
            stmt.action == PolicyAction.GET_OBJECT
            for stmt in policy.policy_document.statement
        )
        assert not any(
            stmt.action == PolicyAction.PUT_OBJECT
            for stmt in policy.policy_document.statement
        )
        assert not any(
            stmt.action == PolicyAction.DELETE_OBJECT
            for stmt in policy.policy_document.statement
        )

    def test_add_read_write_access(self, policy_with_list_bucket):
        """Test adding READ_WRITE access to a path."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        new_builder = builder.add_path_access(
            "s3a://test-bucket/data/read-write",
            PolicyPermissionLevel.WRITE,
        )

        policy = new_builder.build()

        # Should have all three object operations
        assert any(
            stmt.action == PolicyAction.GET_OBJECT
            for stmt in policy.policy_document.statement
        )
        assert any(
            stmt.action == PolicyAction.PUT_OBJECT
            for stmt in policy.policy_document.statement
        )
        assert any(
            stmt.action == PolicyAction.DELETE_OBJECT
            for stmt in policy.policy_document.statement
        )

    def test_add_admin_access(self, policy_with_list_bucket):
        """Test adding ADMIN access to a path."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        new_builder = builder.add_path_access(
            "s3a://test-bucket/data/admin",
            PolicyPermissionLevel.ADMIN,
        )

        policy = new_builder.build()

        # Admin should have all permissions (same as WRITE for now)
        assert any(
            stmt.action == PolicyAction.GET_OBJECT
            for stmt in policy.policy_document.statement
        )
        assert any(
            stmt.action == PolicyAction.PUT_OBJECT
            for stmt in policy.policy_document.statement
        )
        assert any(
            stmt.action == PolicyAction.DELETE_OBJECT
            for stmt in policy.policy_document.statement
        )

    def test_add_multiple_paths(self, policy_with_list_bucket):
        """Test adding multiple paths sequentially."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        builder = builder.add_path_access(
            "s3a://test-bucket/path1", PolicyPermissionLevel.READ
        )
        builder = builder.add_path_access(
            "s3a://test-bucket/path2", PolicyPermissionLevel.WRITE
        )

        policy = builder.build()

        list_bucket_stmt = next(
            (
                stmt
                for stmt in policy.policy_document.statement
                if stmt.action == PolicyAction.LIST_BUCKET
            ),
            None,
        )
        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]

        assert "path1" in prefixes
        assert "path1/*" in prefixes
        assert "path2" in prefixes
        assert "path2/*" in prefixes

    def test_add_path_with_governance_wildcard(self, policy_with_list_bucket):
        """Test adding governance path with wildcard pattern."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        new_builder = builder.add_path_access(
            "s3a://test-bucket/users-sql-warehouse/user1/u_user1__*",
            PolicyPermissionLevel.READ,
        )

        policy = new_builder.build()

        list_bucket_stmt = next(
            (
                stmt
                for stmt in policy.policy_document.statement
                if stmt.action == PolicyAction.LIST_BUCKET
            ),
            None,
        )
        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]

        # Should include parent directory for navigation
        assert "users-sql-warehouse/user1" in prefixes
        assert "users-sql-warehouse/user1/*" in prefixes
        # And the wildcard pattern itself
        assert "users-sql-warehouse/user1/u_user1__*" in prefixes
        assert "users-sql-warehouse/user1/u_user1__*/*" in prefixes

    def test_add_path_updates_existing_permission(self, policy_with_existing_access):
        """Test that adding path with different permission level updates it."""
        builder = PolicyBuilder(policy_with_existing_access, "test-bucket")

        # Original has WRITE access to existing/path
        # Change to READ_ONLY
        new_builder = builder.add_path_access(
            "s3a://test-bucket/existing/path",
            PolicyPermissionLevel.READ,
        )

        policy = new_builder.build()

        # Should have GET_OBJECT
        assert any(
            stmt.action == PolicyAction.GET_OBJECT
            for stmt in policy.policy_document.statement
        )
        # Should NOT have PUT_OBJECT or DELETE_OBJECT anymore
        assert not any(
            stmt.action == PolicyAction.PUT_OBJECT
            for stmt in policy.policy_document.statement
        )
        assert not any(
            stmt.action == PolicyAction.DELETE_OBJECT
            for stmt in policy.policy_document.statement
        )

    def test_add_path_immutability(self, policy_with_list_bucket):
        """Test that add_path_access returns new builder and doesn't mutate original."""
        builder1 = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        original_stmt_count = len(builder1.policy_model.policy_document.statement)

        builder2 = builder1.add_path_access(
            "s3a://test-bucket/new/path",
            PolicyPermissionLevel.READ,
        )

        # builder1 should be unchanged
        assert (
            len(builder1.policy_model.policy_document.statement) == original_stmt_count
        )
        # builder2 should have new statements
        assert (
            len(builder2.policy_model.policy_document.statement) > original_stmt_count
        )


# =============================================================================
# TestRemovePathAccess - Removing path access
# =============================================================================


class TestRemovePathAccess:
    """Tests for removing path access from policies."""

    def test_remove_path_access(self, policy_with_existing_access):
        """Test removing a path completely."""
        builder = PolicyBuilder(policy_with_existing_access, "test-bucket")
        new_builder = builder.remove_path_access("s3a://test-bucket/existing/path")

        policy = new_builder.build()

        # Should remove from ListBucket prefixes
        list_bucket_stmt = next(
            (
                stmt
                for stmt in policy.policy_document.statement
                if stmt.action == PolicyAction.LIST_BUCKET
            ),
            None,
        )
        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        assert "existing/path" not in prefixes
        assert "existing/path/*" not in prefixes

        # Should remove all object-level statements for this path
        for stmt in policy.policy_document.statement:
            if stmt.action in [
                PolicyAction.GET_OBJECT,
                PolicyAction.PUT_OBJECT,
                PolicyAction.DELETE_OBJECT,
            ]:
                resources = (
                    stmt.resource
                    if isinstance(stmt.resource, list)
                    else [stmt.resource]
                )
                assert "arn:aws:s3:::test-bucket/existing/path" not in resources
                assert "arn:aws:s3:::test-bucket/existing/path/*" not in resources

    def test_remove_nonexistent_path_no_error(self, policy_with_existing_access):
        """Test that removing nonexistent path doesn't raise error."""
        builder = PolicyBuilder(policy_with_existing_access, "test-bucket")
        # Should not raise error
        new_builder = builder.remove_path_access("s3a://test-bucket/nonexistent/path")

        policy = new_builder.build()
        # Existing path should still be there
        list_bucket_stmt = next(
            (
                stmt
                for stmt in policy.policy_document.statement
                if stmt.action == PolicyAction.LIST_BUCKET
            ),
            None,
        )
        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        assert "existing/path" in prefixes

    def test_remove_path_preserves_other_paths(self, policy_with_existing_access):
        """Test that removing one path preserves others."""
        # Add a second path
        builder = PolicyBuilder(policy_with_existing_access, "test-bucket")
        builder = builder.add_path_access(
            "s3a://test-bucket/other/path",
            PolicyPermissionLevel.READ,
        )

        # Remove the original path
        builder = builder.remove_path_access("s3a://test-bucket/existing/path")
        policy = builder.build()

        # other/path should still be present
        list_bucket_stmt = next(
            (
                stmt
                for stmt in policy.policy_document.statement
                if stmt.action == PolicyAction.LIST_BUCKET
            ),
            None,
        )
        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        assert "other/path" in prefixes
        assert "other/path/*" in prefixes

        # existing/path should be gone
        assert "existing/path" not in prefixes
        assert "existing/path/*" not in prefixes

    def test_remove_path_immutability(self, policy_with_existing_access):
        """Test that remove_path_access returns new builder and doesn't mutate original."""
        builder1 = PolicyBuilder(policy_with_existing_access, "test-bucket")
        original_stmt_count = len(builder1.policy_model.policy_document.statement)

        builder2 = builder1.remove_path_access("s3a://test-bucket/existing/path")

        # builder1 should be unchanged
        assert (
            len(builder1.policy_model.policy_document.statement) == original_stmt_count
        )
        # builder2 might have fewer statements (if statements become empty)
        assert (
            len(builder2.policy_model.policy_document.statement) <= original_stmt_count
        )


# =============================================================================
# TestBuild - Building final policy
# =============================================================================


class TestBuild:
    """Tests for building the final policy model."""

    def test_build_returns_deep_copy(self, policy_with_list_bucket):
        """Test that build returns a deep copy of the policy."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        policy1 = builder.build()
        policy2 = builder.build()

        # Should be different objects
        assert policy1 is not policy2
        assert policy1.policy_document is not policy2.policy_document

        # But with same content
        assert policy1.policy_name == policy2.policy_name
        assert len(policy1.policy_document.statement) == len(
            policy2.policy_document.statement
        )

    def test_build_after_modifications(self, policy_with_list_bucket):
        """Test building after multiple modifications."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        builder = builder.add_path_access(
            "s3a://test-bucket/path1", PolicyPermissionLevel.READ
        )
        builder = builder.add_path_access(
            "s3a://test-bucket/path2", PolicyPermissionLevel.WRITE
        )

        policy = builder.build()

        # Should have GetBucketLocation
        assert any(
            stmt.action == PolicyAction.GET_BUCKET_LOCATION
            for stmt in policy.policy_document.statement
        )

        # Should have ListBucket
        assert any(
            stmt.action == PolicyAction.LIST_BUCKET
            for stmt in policy.policy_document.statement
        )

        # Should have object operations
        assert any(
            stmt.action == PolicyAction.GET_OBJECT
            for stmt in policy.policy_document.statement
        )


# =============================================================================
# TestHelperMethods - Internal helper method testing
# =============================================================================


class TestHelperMethods:
    """Tests for internal helper methods."""

    def test_create_list_bucket_prefixes_simple_path(self, policy_with_list_bucket):
        """Test creating prefixes for simple path."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        prefixes = builder._create_list_bucket_prefixes("path/to/data")

        assert "path/to/data" in prefixes
        assert "path/to/data/*" in prefixes
        assert len(prefixes) == 2

    def test_create_list_bucket_prefixes_governance_wildcard(
        self, policy_with_list_bucket
    ):
        """Test creating prefixes for governance wildcard path."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        prefixes = builder._create_list_bucket_prefixes(
            "users-sql-warehouse/user1/u_user1__*"
        )

        assert "users-sql-warehouse/user1/u_user1__*" in prefixes
        assert "users-sql-warehouse/user1/u_user1__*/*" in prefixes
        # Should also include parent directory
        assert "users-sql-warehouse/user1" in prefixes
        assert "users-sql-warehouse/user1/*" in prefixes

    def test_find_list_bucket_statement(self, policy_with_list_bucket):
        """Test finding ListBucket statement."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        stmt = builder._find_list_bucket_statement()

        assert stmt is not None
        assert stmt.action == PolicyAction.LIST_BUCKET

    def test_find_list_bucket_statement_returns_none_when_missing(
        self, empty_policy_model
    ):
        """Test that finding ListBucket returns None when not present."""
        builder = PolicyBuilder(empty_policy_model, "test-bucket")
        stmt = builder._find_list_bucket_statement()

        assert stmt is None

    def test_statement_matches_resource_single_resource(self, policy_with_list_bucket):
        """Test matching statement with single resource."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")

        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource="arn:aws:s3:::test-bucket/path/*",
        )

        assert builder._statement_matches_resource(
            stmt, "arn:aws:s3:::test-bucket/path/*"
        )
        assert not builder._statement_matches_resource(
            stmt, "arn:aws:s3:::test-bucket/other/*"
        )

    def test_statement_matches_resource_list_of_resources(
        self, policy_with_list_bucket
    ):
        """Test matching statement with list of resources."""
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")

        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource=[
                "arn:aws:s3:::test-bucket/path1/*",
                "arn:aws:s3:::test-bucket/path2/*",
            ],
        )

        assert builder._statement_matches_resource(
            stmt, "arn:aws:s3:::test-bucket/path1/*"
        )
        assert builder._statement_matches_resource(
            stmt, "arn:aws:s3:::test-bucket/path2/*"
        )
        assert not builder._statement_matches_resource(
            stmt, "arn:aws:s3:::test-bucket/path3/*"
        )


# =============================================================================
# TestEdgeCases - Edge cases and error conditions
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_add_path_to_policy_without_list_bucket_creates_statement(
        self, empty_policy_model
    ):
        """Test adding path to policy without existing ListBucket statement."""
        builder = PolicyBuilder(empty_policy_model, "test-bucket")
        # Use new_policy=True to avoid trying to remove from non-existent ListBucket
        new_builder = builder.add_path_access(
            "s3a://test-bucket/new/path",
            PolicyPermissionLevel.READ,
            new_policy=True,
        )

        policy = new_builder.build()

        # Should create ListBucket statement
        list_bucket_stmt = next(
            (
                stmt
                for stmt in policy.policy_document.statement
                if stmt.action == PolicyAction.LIST_BUCKET
            ),
            None,
        )
        assert list_bucket_stmt is not None
        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        assert "new/path" in prefixes

    def test_remove_statement_when_all_resources_removed(
        self, policy_with_existing_access
    ):
        """Test that statements are removed when all resources are removed."""
        builder = PolicyBuilder(policy_with_existing_access, "test-bucket")

        # Remove the only path
        new_builder = builder.remove_path_access("s3a://test-bucket/existing/path")
        policy = new_builder.build()

        # PUT_OBJECT and DELETE_OBJECT statements should be completely removed
        # (since they only had resources for existing/path)
        put_stmts = [
            stmt
            for stmt in policy.policy_document.statement
            if stmt.action == PolicyAction.PUT_OBJECT
        ]
        delete_stmts = [
            stmt
            for stmt in policy.policy_document.statement
            if stmt.action == PolicyAction.DELETE_OBJECT
        ]

        assert len(put_stmts) == 0
        assert len(delete_stmts) == 0

    def test_add_path_with_new_policy_flag(self, policy_with_list_bucket):
        """Test adding path with new_policy flag (doesn't remove existing)."""
        # First add a path
        builder = PolicyBuilder(policy_with_list_bucket, "test-bucket")
        builder = builder.add_path_access(
            "s3a://test-bucket/path1", PolicyPermissionLevel.READ
        )

        # Add another path with new_policy=True (shouldn't remove path1)
        builder = builder.add_path_access(
            "s3a://test-bucket/path2",
            PolicyPermissionLevel.READ,
            new_policy=True,
        )

        policy = builder.build()

        list_bucket_stmt = next(
            (
                stmt
                for stmt in policy.policy_document.statement
                if stmt.action == PolicyAction.LIST_BUCKET
            ),
            None,
        )
        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]

        # Both paths should be present
        assert "path1" in prefixes
        assert "path2" in prefixes
