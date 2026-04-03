"""
Custom exceptions for the MinIO Manager Service.
"""


class S3Error(Exception):
    """
    The super class of all MinIO Manager Service related errors.
    """


class AuthenticationError(S3Error):
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


class S3ManagerError(S3Error):
    """Base exception for all MinIO Manager operations."""

    pass


class PolicyValidationError(S3ManagerError):
    """Raised when MinIO policy content validation fails."""

    pass


class PolicyOperationError(S3ManagerError):
    """Raised when MinIO policy operations fail."""

    pass


class BucketValidationError(S3ManagerError):
    """Raised when bucket name or configuration validation fails."""

    pass


class BucketOperationError(S3ManagerError):
    """Raised when MinIO bucket operations fail."""

    pass


class UserOperationError(S3ManagerError):
    """Raised when MinIO user operations fail."""

    pass


class GroupOperationError(S3ManagerError):
    """Raised when MinIO group operations fail."""

    pass


class DataGovernanceError(S3ManagerError):
    """Raised when data governance validation fails."""

    pass


class ValidationError(S3ManagerError):
    """Raised when general validation fails."""

    pass


class CredentialOperationError(S3ManagerError):
    """Raised when credential operations fail (e.g., lock contention)."""

    pass


class ConnectionError(S3ManagerError):
    """Raised when MinIO server connection fails."""

    pass


# ----- Tenant exceptions -----


class TenantError(S3Error):
    """Super class for tenant related errors."""


class TenantOperationError(TenantError):
    """Raised when a tenant operation fails due to invalid input."""

    pass


class TenantAuthorizationError(TenantError):
    """Raised when a user lacks permission for a tenant operation."""

    pass


class TenantNotFoundError(TenantError):
    """Raised when a tenant or tenant resource is not found."""

    pass
