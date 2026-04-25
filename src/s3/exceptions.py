"""Exceptions for the s3 package."""


class IamPolicyNotFoundError(Exception):
    """Raised by the IAM client when a requested inline policy does not exist."""
