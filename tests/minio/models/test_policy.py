"""
Comprehensive tests for the minio.models.policy module.

Tests Pydantic models for MinIO policy structures including:
- PolicyStatement with validation
- PolicyDocument with conversions
- PolicyModel with name validation
"""

import json
import pytest
from pydantic import ValidationError

from src.minio.models.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
    PolicyTarget,
    PolicyType,
    PERMISSION_LEVEL_ACTIONS,
)


# =============================================================================
# TestPolicyEnums - Enum values and constants
# =============================================================================


class TestPolicyEnums:
    """Tests for policy enum definitions."""

    def test_policy_effect_values(self):
        """Test PolicyEffect enum values."""
        assert PolicyEffect.ALLOW.value == "Allow"

    def test_policy_action_values(self):
        """Test PolicyAction enum values."""
        assert PolicyAction.GET_OBJECT.value == "s3:GetObject"
        assert PolicyAction.PUT_OBJECT.value == "s3:PutObject"
        assert PolicyAction.DELETE_OBJECT.value == "s3:DeleteObject"
        assert PolicyAction.LIST_BUCKET.value == "s3:ListBucket"
        assert PolicyAction.GET_BUCKET_LOCATION.value == "s3:GetBucketLocation"
        assert PolicyAction.ALL_ACTIONS.value == "s3:*"

    def test_policy_permission_level_values(self):
        """Test PolicyPermissionLevel enum values."""
        assert PolicyPermissionLevel.READ.value == "read"
        assert PolicyPermissionLevel.WRITE.value == "write"
        assert PolicyPermissionLevel.ADMIN.value == "admin"

    def test_policy_target_values(self):
        """Test PolicyTarget enum values."""
        assert PolicyTarget.USER.value == "user"
        assert PolicyTarget.GROUP.value == "group"

    def test_policy_type_values(self):
        """Test PolicyType enum values."""
        assert PolicyType.USER_HOME.value == "user_home"
        assert PolicyType.USER_SYSTEM.value == "user_system"
        assert PolicyType.GROUP_HOME.value == "group_home"

    def test_permission_level_actions_mapping(self):
        """Test permission level to action mappings."""
        assert PERMISSION_LEVEL_ACTIONS[PolicyPermissionLevel.READ] == [
            PolicyAction.GET_OBJECT
        ]
        assert PERMISSION_LEVEL_ACTIONS[PolicyPermissionLevel.WRITE] == [
            PolicyAction.GET_OBJECT,
            PolicyAction.PUT_OBJECT,
            PolicyAction.DELETE_OBJECT,
        ]
        assert PERMISSION_LEVEL_ACTIONS[PolicyPermissionLevel.ADMIN] == [
            PolicyAction.ALL_ACTIONS
        ]


# =============================================================================
# TestPolicyStatement - Statement creation and validation
# =============================================================================


class TestPolicyStatement:
    """Tests for PolicyStatement model."""

    def test_create_simple_statement(self):
        """Test creating a basic policy statement."""
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource="arn:aws:s3:::bucket/path/*",
        )
        assert stmt.effect == PolicyEffect.ALLOW
        assert stmt.action == PolicyAction.GET_OBJECT
        assert stmt.resource == "arn:aws:s3:::bucket/path/*"
        assert stmt.condition is None
        assert stmt.principal is None

    def test_statement_with_condition(self):
        """Test statement with conditional logic."""
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.LIST_BUCKET,
            resource="arn:aws:s3:::bucket",
            condition={"StringLike": {"s3:prefix": ["user/*"]}},
        )
        assert stmt.condition == {"StringLike": {"s3:prefix": ["user/*"]}}

    def test_statement_with_principal(self):
        """Test statement with principal."""
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource="arn:aws:s3:::bucket/*",
            principal="arn:aws:iam::123456789012:user/username",
        )
        assert stmt.principal == "arn:aws:iam::123456789012:user/username"

    def test_statement_with_list_resources(self):
        """Test statement with multiple resources."""
        resources = [
            "arn:aws:s3:::bucket/path1/*",
            "arn:aws:s3:::bucket/path2/*",
        ]
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource=resources,
        )
        assert stmt.resource == resources

    def test_statement_is_immutable(self):
        """Test that PolicyStatement is frozen (immutable)."""
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource="arn:aws:s3:::bucket/*",
        )
        with pytest.raises(ValidationError):
            stmt.action = PolicyAction.PUT_OBJECT

    def test_from_dict_single_action(self):
        """Test creating statement from dictionary with single action."""
        stmt_dict = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::bucket/*",
        }
        stmt = PolicyStatement.from_dict(stmt_dict)
        assert stmt.effect == PolicyEffect.ALLOW
        assert stmt.action == PolicyAction.GET_OBJECT
        assert stmt.resource == "arn:aws:s3:::bucket/*"

    def test_from_dict_action_as_list(self):
        """Test from_dict with action as list (single element)."""
        stmt_dict = {
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": "arn:aws:s3:::bucket/*",
        }
        stmt = PolicyStatement.from_dict(stmt_dict)
        assert stmt.action == PolicyAction.PUT_OBJECT

    def test_from_dict_with_condition(self):
        """Test from_dict with condition."""
        stmt_dict = {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::bucket",
            "Condition": {"StringLike": {"s3:prefix": ["user/*"]}},
        }
        stmt = PolicyStatement.from_dict(stmt_dict)
        assert stmt.condition == {"StringLike": {"s3:prefix": ["user/*"]}}

    def test_from_dict_multiple_actions_raises_error(self):
        """Test that multiple actions raise ValueError."""
        stmt_dict = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::bucket/*",
        }
        with pytest.raises(ValueError, match="multiple actions"):
            PolicyStatement.from_dict(stmt_dict)

    def test_from_dict_unsupported_action_raises_error(self):
        """Test that unsupported action raises ValueError."""
        stmt_dict = {
            "Effect": "Allow",
            "Action": "s3:UnsupportedAction",
            "Resource": "arn:aws:s3:::bucket/*",
        }
        with pytest.raises(ValueError, match="Unsupported policy action"):
            PolicyStatement.from_dict(stmt_dict)


# =============================================================================
# TestPolicyDocument - Document creation and conversions
# =============================================================================


class TestPolicyDocument:
    """Tests for PolicyDocument model."""

    def test_create_empty_document(self):
        """Test creating an empty policy document."""
        doc = PolicyDocument(statement=[])
        assert doc.version == "2012-10-17"
        assert doc.statement == []

    def test_create_document_with_statements(self):
        """Test creating document with statements."""
        stmt1 = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource="arn:aws:s3:::bucket/path1/*",
        )
        stmt2 = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.PUT_OBJECT,
            resource="arn:aws:s3:::bucket/path2/*",
        )
        doc = PolicyDocument(statement=[stmt1, stmt2])
        assert len(doc.statement) == 2
        assert doc.statement[0] == stmt1
        assert doc.statement[1] == stmt2

    def test_to_dict(self):
        """Test converting PolicyDocument to dictionary."""
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource="arn:aws:s3:::bucket/*",
        )
        doc = PolicyDocument(statement=[stmt])
        result = doc.to_dict()

        assert result["Version"] == "2012-10-17"
        assert len(result["Statement"]) == 1
        assert result["Statement"][0]["Effect"] == "Allow"
        assert result["Statement"][0]["Action"] == PolicyAction.GET_OBJECT
        assert result["Statement"][0]["Resource"] == "arn:aws:s3:::bucket/*"

    def test_to_dict_with_condition(self):
        """Test to_dict includes condition when present."""
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.LIST_BUCKET,
            resource="arn:aws:s3:::bucket",
            condition={"StringLike": {"s3:prefix": ["user/*"]}},
        )
        doc = PolicyDocument(statement=[stmt])
        result = doc.to_dict()

        assert "Condition" in result["Statement"][0]
        assert result["Statement"][0]["Condition"] == {
            "StringLike": {"s3:prefix": ["user/*"]}
        }

    def test_to_dict_excludes_none_condition(self):
        """Test to_dict excludes condition when None."""
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource="arn:aws:s3:::bucket/*",
        )
        doc = PolicyDocument(statement=[stmt])
        result = doc.to_dict()

        assert "Condition" not in result["Statement"][0]

    def test_from_dict(self):
        """Test creating PolicyDocument from dictionary."""
        doc_dict = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*",
                }
            ],
        }
        doc = PolicyDocument.from_dict(doc_dict)

        assert doc.version == "2012-10-17"
        assert len(doc.statement) == 1
        assert doc.statement[0].action == PolicyAction.GET_OBJECT

    def test_from_dict_empty_statements(self):
        """Test from_dict with no statements."""
        doc_dict = {"Version": "2012-10-17", "Statement": []}
        doc = PolicyDocument.from_dict(doc_dict)

        assert doc.version == "2012-10-17"
        assert doc.statement == []

    def test_from_dict_default_version(self):
        """Test from_dict uses default version if not provided."""
        doc_dict = {"Statement": []}
        doc = PolicyDocument.from_dict(doc_dict)

        assert doc.version == "2012-10-17"


# =============================================================================
# TestPolicyModel - Complete policy model with validation
# =============================================================================


class TestPolicyModel:
    """Tests for PolicyModel."""

    def test_create_policy_model(self):
        """Test creating a complete policy model."""
        doc = PolicyDocument(statement=[])
        policy = PolicyModel(policy_name="test-policy", policy_document=doc)

        assert policy.policy_name == "test-policy"
        assert policy.policy_document == doc

    def test_policy_name_validation_alphanumeric(self):
        """Test policy name accepts alphanumeric with hyphens, underscores, periods."""
        doc = PolicyDocument(statement=[])

        # Valid names
        valid_names = [
            "user-home-policy-testuser",
            "user_system_policy_testuser",
            "group.policy.testgroup",
            "policy123",
        ]
        for name in valid_names:
            policy = PolicyModel(policy_name=name, policy_document=doc)
            assert policy.policy_name == name

    def test_policy_name_validation_invalid_chars(self):
        """Test policy name rejects invalid characters."""
        doc = PolicyDocument(statement=[])

        invalid_names = [
            "policy with spaces",
            "policy@special",
            "policy#hash",
            "policy/slash",
        ]
        for name in invalid_names:
            with pytest.raises(ValidationError):
                PolicyModel(policy_name=name, policy_document=doc)

    def test_policy_name_length_validation(self):
        """Test policy name length constraints."""
        doc = PolicyDocument(statement=[])

        # Too short (empty)
        with pytest.raises(ValidationError):
            PolicyModel(policy_name="", policy_document=doc)

        # Too long (>128 chars)
        with pytest.raises(ValidationError):
            PolicyModel(policy_name="a" * 129, policy_document=doc)

    def test_to_minio_policy_json(self):
        """Test converting policy model to MinIO JSON format."""
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_OBJECT,
            resource="arn:aws:s3:::bucket/*",
        )
        doc = PolicyDocument(statement=[stmt])
        policy = PolicyModel(policy_name="test-policy", policy_document=doc)

        json_str = policy.to_minio_policy_json()
        parsed = json.loads(json_str)

        assert parsed["Version"] == "2012-10-17"
        assert len(parsed["Statement"]) == 1
        assert parsed["Statement"][0]["Action"] == "s3:GetObject"

    def test_policy_model_round_trip(self):
        """Test creating policy, converting to dict, and back."""
        stmt = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.LIST_BUCKET,
            resource="arn:aws:s3:::bucket",
            condition={"StringLike": {"s3:prefix": ["user/*"]}},
        )
        doc = PolicyDocument(statement=[stmt])
        policy = PolicyModel(policy_name="test-policy", policy_document=doc)

        # Convert to dict
        doc_dict = policy.policy_document.to_dict()

        # Recreate from dict
        doc2 = PolicyDocument.from_dict(doc_dict)
        policy2 = PolicyModel(policy_name="test-policy", policy_document=doc2)

        # Should be equivalent
        assert policy2.policy_name == policy.policy_name
        assert len(policy2.policy_document.statement) == len(
            policy.policy_document.statement
        )
        assert (
            policy2.policy_document.statement[0].action
            == policy.policy_document.statement[0].action
        )
