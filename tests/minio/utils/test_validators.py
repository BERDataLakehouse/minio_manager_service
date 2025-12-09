"""Comprehensive tests for the minio.utils.validators module."""

import pytest

from src.minio.utils.validators import (
    validate_username,
    validate_group_name,
    validate_bucket_name,
    validate_s3_path,
    validate_path_prefix,
    validate_policy_name,
    BUILT_IN_POLICIES,
    DATA_GOVERNANCE_POLICY_PREFIXES,
    USER_HOME_POLICY_PREFIX,
    USER_SYSTEM_POLICY_PREFIX,
    GROUP_POLICY_PREFIX,
)
from src.service.exceptions import (
    UserOperationError,
    GroupOperationError,
    BucketValidationError,
    PolicyValidationError,
    ValidationError,
)


# =============================================================================
# TEST USERNAME VALIDATION
# =============================================================================


class TestValidateUsername:
    """Tests for validate_username function."""

    # Valid username tests
    def test_valid_simple_username(self):
        """Test simple alphanumeric username."""
        assert validate_username("testuser") == "testuser"

    def test_valid_username_with_numbers(self):
        """Test username with numbers."""
        assert validate_username("user123") == "user123"

    def test_valid_username_with_underscore(self):
        """Test username with underscore."""
        assert validate_username("test_user") == "test_user"

    def test_valid_username_with_hyphen(self):
        """Test username with hyphen."""
        assert validate_username("test-user") == "test-user"

    def test_valid_username_with_dot(self):
        """Test username with dot."""
        assert validate_username("test.user") == "test.user"

    def test_valid_username_min_length(self):
        """Test username at minimum length."""
        assert validate_username("ab") == "ab"

    def test_valid_username_max_length(self):
        """Test username at maximum length."""
        username = "a" * 64
        assert validate_username(username) == username

    def test_username_strips_whitespace(self):
        """Test username strips leading/trailing whitespace."""
        assert validate_username("  testuser  ") == "testuser"

    # Invalid username tests
    def test_invalid_username_too_short(self):
        """Test username too short."""
        with pytest.raises(UserOperationError) as exc_info:
            validate_username("a")
        assert "between 2 and 64" in str(exc_info.value)

    def test_invalid_username_too_long(self):
        """Test username too long."""
        with pytest.raises(UserOperationError) as exc_info:
            validate_username("a" * 65)
        assert "between 2 and 64" in str(exc_info.value)

    def test_invalid_username_special_chars(self):
        """Test username with invalid special characters."""
        invalid_chars = ["@", "#", "$", "%", "^", "&", "*", "!", "?"]
        for char in invalid_chars:
            with pytest.raises(UserOperationError):
                validate_username(f"user{char}name")

    def test_invalid_username_starts_with_special(self):
        """Test username starting with special character."""
        with pytest.raises(UserOperationError):
            validate_username("-username")

    def test_invalid_username_ends_with_special(self):
        """Test username ending with special character."""
        with pytest.raises(UserOperationError):
            validate_username("username-")

    def test_invalid_username_consecutive_specials(self):
        """Test username with consecutive special characters."""
        with pytest.raises(UserOperationError):
            validate_username("user--name")

    def test_invalid_username_empty(self):
        """Test empty username."""
        with pytest.raises((UserOperationError, ValueError)):
            validate_username("")

    def test_invalid_username_whitespace_only(self):
        """Test whitespace-only username."""
        with pytest.raises((UserOperationError, ValueError)):
            validate_username("   ")

    # Reserved username tests
    def test_reserved_usernames(self):
        """Test all reserved usernames are rejected."""
        reserved = [
            "admin",
            "root",
            "system",
            "minio",
            "service",
            "backup",
            "guest",
            "anonymous",
            "public",
            "shared",
            "warehouse",
        ]
        for username in reserved:
            with pytest.raises(UserOperationError) as exc_info:
                validate_username(username)
            assert "reserved" in str(exc_info.value).lower()

    def test_reserved_usernames_case_insensitive(self):
        """Test reserved usernames are case-insensitive."""
        with pytest.raises(UserOperationError):
            validate_username("ADMIN")
        with pytest.raises(UserOperationError):
            validate_username("Admin")


# =============================================================================
# TEST GROUP NAME VALIDATION
# =============================================================================


class TestValidateGroupName:
    """Tests for validate_group_name function."""

    # Valid group name tests
    def test_valid_simple_group_name(self):
        """Test simple lowercase group name."""
        assert validate_group_name("testgroup") == "testgroup"

    def test_valid_group_name_with_numbers(self):
        """Test group name with numbers."""
        assert validate_group_name("group123") == "group123"

    def test_valid_group_name_min_length(self):
        """Test group name at minimum length."""
        assert validate_group_name("ab") == "ab"

    def test_valid_group_name_max_length(self):
        """Test group name at maximum length."""
        group_name = "a" * 64
        assert validate_group_name(group_name) == group_name

    def test_group_name_strips_whitespace(self):
        """Test group name strips leading/trailing whitespace."""
        assert validate_group_name("  testgroup  ") == "testgroup"

    # Invalid group name tests
    def test_invalid_group_name_uppercase(self):
        """Test group name with uppercase (not allowed)."""
        with pytest.raises(GroupOperationError) as exc_info:
            validate_group_name("TestGroup")
        assert (
            "lowercase" in str(exc_info.value).lower()
            or "uppercase" in str(exc_info.value).lower()
        )

    def test_invalid_group_name_underscore(self):
        """Test group name with underscore (not allowed - reserved for namespace separator)."""
        with pytest.raises(GroupOperationError) as exc_info:
            validate_group_name("test_group")
        assert (
            "lowercase letters and numbers" in str(exc_info.value).lower()
            or "underscore" in str(exc_info.value).lower()
        )

    def test_invalid_group_name_hyphen(self):
        """Test group name with hyphen (not allowed)."""
        with pytest.raises(GroupOperationError):
            validate_group_name("test-group")

    def test_invalid_group_name_dot(self):
        """Test group name with dot (not allowed)."""
        with pytest.raises(GroupOperationError):
            validate_group_name("test.group")

    def test_invalid_group_name_starts_with_number(self):
        """Test group name starting with number."""
        with pytest.raises(GroupOperationError) as exc_info:
            validate_group_name("123group")
        assert "start with a letter" in str(exc_info.value).lower()

    def test_invalid_group_name_too_short(self):
        """Test group name too short."""
        with pytest.raises(GroupOperationError):
            validate_group_name("a")

    def test_invalid_group_name_too_long(self):
        """Test group name too long."""
        with pytest.raises(GroupOperationError):
            validate_group_name("a" * 65)

    def test_invalid_group_name_empty(self):
        """Test empty group name."""
        with pytest.raises((GroupOperationError, ValueError)):
            validate_group_name("")

    # Reserved group name tests
    def test_reserved_group_names(self):
        """Test all reserved group names are rejected."""
        reserved = [
            "admin",
            "root",
            "system",
            "all",
            "everyone",
            "public",
            "default",
            "minio",
            "service",
            "backup",
            "warehouse",
        ]
        for group in reserved:
            with pytest.raises(GroupOperationError) as exc_info:
                validate_group_name(group)
            assert "reserved" in str(exc_info.value).lower()


# =============================================================================
# TEST BUCKET NAME VALIDATION
# =============================================================================


class TestValidateBucketName:
    """Tests for validate_bucket_name function."""

    # Valid bucket name tests
    def test_valid_simple_bucket_name(self):
        """Test simple bucket name."""
        assert validate_bucket_name("mybucket") == "mybucket"

    def test_valid_bucket_with_hyphen(self):
        """Test bucket name with hyphen."""
        assert validate_bucket_name("my-bucket") == "my-bucket"

    def test_valid_bucket_with_numbers(self):
        """Test bucket name with numbers."""
        assert validate_bucket_name("bucket123") == "bucket123"

    def test_valid_bucket_min_length(self):
        """Test bucket at minimum length (3)."""
        assert validate_bucket_name("abc") == "abc"

    def test_valid_bucket_max_length(self):
        """Test bucket at maximum length (63)."""
        bucket = "a" * 63
        assert validate_bucket_name(bucket) == bucket

    def test_bucket_strips_whitespace(self):
        """Test bucket name strips whitespace."""
        assert validate_bucket_name("  mybucket  ") == "mybucket"

    # Invalid bucket name tests
    def test_invalid_bucket_with_dot(self):
        """Test bucket name with dot (unsupported)."""
        with pytest.raises(BucketValidationError) as exc_info:
            validate_bucket_name("my.bucket")
        assert "." in str(exc_info.value)

    def test_invalid_bucket_too_short(self):
        """Test bucket name too short."""
        with pytest.raises(BucketValidationError):
            validate_bucket_name("ab")

    def test_invalid_bucket_too_long(self):
        """Test bucket name too long."""
        with pytest.raises(BucketValidationError):
            validate_bucket_name("a" * 64)

    def test_invalid_bucket_starts_with_hyphen(self):
        """Test bucket name starting with hyphen."""
        with pytest.raises(BucketValidationError):
            validate_bucket_name("-bucket")

    def test_invalid_bucket_ends_with_hyphen(self):
        """Test bucket name ending with hyphen."""
        with pytest.raises(BucketValidationError):
            validate_bucket_name("bucket-")

    def test_invalid_bucket_uppercase(self):
        """Test bucket name with uppercase."""
        with pytest.raises(BucketValidationError):
            validate_bucket_name("MyBucket")

    def test_invalid_bucket_empty(self):
        """Test empty bucket name."""
        with pytest.raises(BucketValidationError):
            validate_bucket_name("")

    def test_invalid_bucket_whitespace_only(self):
        """Test whitespace-only bucket name."""
        with pytest.raises(BucketValidationError):
            validate_bucket_name("   ")

    def test_bucket_with_index(self):
        """Test bucket validation with index in error message."""
        with pytest.raises(BucketValidationError) as exc_info:
            validate_bucket_name("ab", index=5)
        assert "index 5" in str(exc_info.value)


# =============================================================================
# TEST S3 PATH VALIDATION
# =============================================================================


class TestValidateS3Path:
    """Tests for validate_s3_path function."""

    # Valid S3 path tests
    def test_valid_s3_path(self):
        """Test valid S3 path with s3://."""
        assert (
            validate_s3_path("s3://mybucket/path/to/object")
            == "s3://mybucket/path/to/object"
        )

    def test_valid_s3a_path(self):
        """Test valid S3 path with s3a://."""
        assert (
            validate_s3_path("s3a://mybucket/path/to/object")
            == "s3a://mybucket/path/to/object"
        )

    def test_s3_path_strips_whitespace(self):
        """Test S3 path strips whitespace."""
        assert validate_s3_path("  s3://mybucket/path  ") == "s3://mybucket/path"

    def test_valid_s3_path_with_special_chars(self):
        """Test S3 path with allowed special characters."""
        path = "s3://mybucket/path/to/file-name_test.txt"
        assert validate_s3_path(path) == path

    # Invalid S3 path tests
    def test_invalid_s3_path_no_protocol(self):
        """Test S3 path without protocol."""
        with pytest.raises(PolicyValidationError) as exc_info:
            validate_s3_path("mybucket/path/to/object")
        assert (
            "s3://" in str(exc_info.value).lower()
            or "s3a://" in str(exc_info.value).lower()
        )

    def test_invalid_s3_path_wrong_protocol(self):
        """Test S3 path with wrong protocol."""
        with pytest.raises(PolicyValidationError):
            validate_s3_path("http://mybucket/path")

    def test_invalid_s3_path_no_bucket(self):
        """Test S3 path without bucket."""
        with pytest.raises(PolicyValidationError):
            validate_s3_path("s3://")

    def test_invalid_s3_path_no_key(self):
        """Test S3 path without object key."""
        with pytest.raises(PolicyValidationError):
            validate_s3_path("s3://mybucket")

    def test_invalid_s3_path_empty_key(self):
        """Test S3 path with empty key."""
        with pytest.raises(PolicyValidationError):
            validate_s3_path("s3://mybucket/")

    def test_invalid_s3_path_traversal(self):
        """Test S3 path with path traversal."""
        with pytest.raises(PolicyValidationError) as exc_info:
            validate_s3_path("s3://mybucket/../etc/passwd")
        assert "traversal" in str(exc_info.value).lower()

    def test_invalid_s3_path_double_slash(self):
        """Test S3 path with double slash in key."""
        with pytest.raises(PolicyValidationError):
            validate_s3_path("s3://mybucket/path//object")

    def test_invalid_s3_path_control_chars(self):
        """Test S3 path with control characters."""
        with pytest.raises(PolicyValidationError):
            validate_s3_path("s3://mybucket/path\nobject")

    def test_invalid_s3_path_key_too_long(self):
        """Test S3 path with key exceeding 1024 characters."""
        long_key = "a" * 1025
        with pytest.raises(PolicyValidationError):
            validate_s3_path(f"s3://mybucket/{long_key}")

    def test_invalid_s3_path_url_encoded_traversal(self):
        """Test S3 path with URL-encoded path traversal."""
        with pytest.raises(PolicyValidationError):
            validate_s3_path("s3://mybucket/%2e%2e%2f/etc/passwd")

    def test_invalid_s3_path_non_ascii(self):
        """Test S3 path with non-ASCII characters."""
        with pytest.raises(PolicyValidationError, match="ASCII"):
            validate_s3_path("s3://mybucket/path/\u4e2d\u6587")

    def test_invalid_s3_path_suspicious_whitespace(self):
        """Test S3 path with zero-width and suspicious whitespace.

        Note: These characters are non-ASCII and will be caught by the ASCII check,
        which also serves to block zero-width and suspicious Unicode whitespace.
        """
        # Zero-width space - caught by ASCII check
        with pytest.raises(PolicyValidationError, match="ASCII"):
            validate_s3_path("s3://mybucket/path\u200b/object")

        # Zero-width no-break space/BOM - caught by ASCII check
        with pytest.raises(PolicyValidationError, match="ASCII"):
            validate_s3_path("s3://mybucket/path\ufeff/object")

    def test_invalid_s3_path_leading_whitespace(self):
        """Test S3 path with leading whitespace in key."""
        with pytest.raises(PolicyValidationError):
            validate_s3_path("s3://mybucket/ path/")

    def test_invalid_s3_path_multiple_dots(self):
        """Test S3 path with suspicious dot patterns."""
        with pytest.raises(PolicyValidationError):
            validate_s3_path("s3://mybucket/....//path")

        with pytest.raises(PolicyValidationError):
            validate_s3_path("s3://mybucket/path/..\\./etc")


# =============================================================================
# TEST PATH PREFIX VALIDATION
# =============================================================================


class TestValidatePathPrefix:
    """Tests for validate_path_prefix function."""

    def test_valid_simple_prefix(self):
        """Test simple valid prefix."""
        assert validate_path_prefix("myprefix") == "myprefix"

    def test_valid_prefix_with_slash(self):
        """Test prefix with forward slash."""
        assert validate_path_prefix("my/prefix") == "my/prefix"

    def test_prefix_strips_whitespace(self):
        """Test prefix strips whitespace."""
        assert validate_path_prefix("  myprefix  ") == "myprefix"

    def test_invalid_prefix_empty(self):
        """Test empty prefix."""
        with pytest.raises((ValidationError, ValueError)):
            validate_path_prefix("")

    def test_invalid_prefix_whitespace_only(self):
        """Test whitespace-only prefix returns empty string (after stripping)."""
        # The validator strips whitespace, so whitespace-only becomes empty string
        # This is currently allowed by the implementation (doesn't raise)
        result = validate_path_prefix("   ")
        assert result == ""

    def test_invalid_prefix_backslash(self):
        """Test prefix with backslash."""
        with pytest.raises(ValidationError):
            validate_path_prefix("my\\prefix")

    def test_invalid_prefix_dot_dot(self):
        """Test prefix with parent directory reference."""
        with pytest.raises(ValidationError):
            validate_path_prefix("my/../prefix")


# =============================================================================
# TEST POLICY NAME VALIDATION
# =============================================================================


class TestValidatePolicyName:
    """Tests for validate_policy_name function."""

    # Valid policy name tests
    def test_valid_user_home_policy_name(self):
        """Test valid user home policy name."""
        policy = f"{USER_HOME_POLICY_PREFIX}testuser"
        assert validate_policy_name(policy) == policy

    def test_valid_user_system_policy_name(self):
        """Test valid user system policy name."""
        policy = f"{USER_SYSTEM_POLICY_PREFIX}testuser"
        assert validate_policy_name(policy) == policy

    def test_valid_group_policy_name(self):
        """Test valid group policy name."""
        policy = f"{GROUP_POLICY_PREFIX}testgroup"
        assert validate_policy_name(policy) == policy

    def test_policy_name_strips_whitespace(self):
        """Test policy name strips whitespace."""
        policy = f"{USER_HOME_POLICY_PREFIX}testuser"
        assert validate_policy_name(f"  {policy}  ") == policy

    # Invalid policy name tests
    def test_invalid_policy_name_wrong_prefix(self):
        """Test policy name with wrong prefix."""
        with pytest.raises(PolicyValidationError) as exc_info:
            validate_policy_name("wrong-prefix-testuser")
        assert "should start with" in str(exc_info.value)

    def test_invalid_policy_name_too_short(self):
        """Test policy name too short."""
        with pytest.raises(PolicyValidationError):
            validate_policy_name("a")

    def test_invalid_policy_name_too_long(self):
        """Test policy name too long."""
        with pytest.raises(PolicyValidationError):
            validate_policy_name(f"{USER_HOME_POLICY_PREFIX}{'a' * 200}")

    def test_invalid_policy_name_special_chars(self):
        """Test policy name with invalid special characters."""
        with pytest.raises(PolicyValidationError):
            validate_policy_name(f"{USER_HOME_POLICY_PREFIX}user@name")

    def test_invalid_policy_name_starts_with_period(self):
        """Test policy name starting with period."""
        with pytest.raises(PolicyValidationError):
            validate_policy_name(".policy-name")

    def test_invalid_policy_name_builtin(self):
        """Test built-in policy names are rejected."""
        for builtin in BUILT_IN_POLICIES:
            with pytest.raises(PolicyValidationError) as exc_info:
                validate_policy_name(builtin)
            assert "reserved" in str(exc_info.value)

    def test_invalid_policy_name_arn_prefix(self):
        """Test policy name starting with arn:."""
        with pytest.raises(PolicyValidationError):
            validate_policy_name("arn:aws:iam::policy")

    def test_invalid_policy_name_empty(self):
        """Test empty policy name."""
        with pytest.raises((PolicyValidationError, ValueError)):
            validate_policy_name("")


# =============================================================================
# TEST CONSTANTS
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_builtin_policies_list(self):
        """Test BUILT_IN_POLICIES contains expected values."""
        expected = [
            "readonly",
            "readwrite",
            "writeonly",
            "diagnostics",
            "public",
            "consoleAdmin",
        ]
        for policy in expected:
            assert policy in BUILT_IN_POLICIES

    def test_data_governance_prefixes(self):
        """Test DATA_GOVERNANCE_POLICY_PREFIXES contains all prefixes."""
        assert USER_HOME_POLICY_PREFIX in DATA_GOVERNANCE_POLICY_PREFIXES
        assert USER_SYSTEM_POLICY_PREFIX in DATA_GOVERNANCE_POLICY_PREFIXES
        assert GROUP_POLICY_PREFIX in DATA_GOVERNANCE_POLICY_PREFIXES

    def test_policy_prefix_values(self):
        """Test policy prefix values."""
        assert USER_HOME_POLICY_PREFIX == "user-home-policy-"
        assert USER_SYSTEM_POLICY_PREFIX == "user-system-policy-"
        assert GROUP_POLICY_PREFIX == "group-policy-"
