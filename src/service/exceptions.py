"""
Custom exceptions for the MinIO Manager Service.
"""


class MinIOError(Exception):
    """
    The super class of all MinIO Manager Service related errors.
    """


class AuthenticationError(MinIOError):
    """
    Super class for authentication related errors.
    """


class MissingTokenError(AuthenticationError):
    """
    An error thrown when a token is required but absent.
    """


class InvalidAuthHeaderError(AuthenticationError):
    """
    An error thrown when an authorization header is invalid.
    """


class InvalidTokenError(AuthenticationError):
    """
    An error thrown when a user's token is invalid.
    """


class MissingRoleError(AuthenticationError):
    """
    An error thrown when a user is missing a required role.
    """


# ----- MinIO specific exceptions -----


class MinIOManagerError(MinIOError):
    """Base exception for all MinIO Manager operations."""

    pass


class PolicyValidationError(MinIOManagerError):
    """Raised when MinIO policy content validation fails."""

    pass


class PolicyOperationError(MinIOManagerError):
    """Raised when MinIO policy operations fail."""

    pass


class BucketValidationError(MinIOManagerError):
    """Raised when bucket name or configuration validation fails."""

    pass


class BucketOperationError(MinIOManagerError):
    """Raised when MinIO bucket operations fail."""

    pass


class UserOperationError(MinIOManagerError):
    """Raised when MinIO user operations fail."""

    pass


class GroupOperationError(MinIOManagerError):
    """Raised when MinIO group operations fail."""

    pass


class DataGovernanceError(MinIOManagerError):
    """Raised when data governance validation fails."""

    pass


class ValidationError(MinIOManagerError):
    """Raised when general validation fails."""

    pass


class ConnectionError(MinIOManagerError):
    """Raised when MinIO server connection fails."""

    pass
