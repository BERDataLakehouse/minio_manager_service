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


class PolicyValidationError(S3ManagerError):
    """Raised when MinIO policy content validation fails."""


class PolicyOperationError(S3ManagerError):
    """Raised when MinIO policy operations fail."""


class BucketValidationError(S3ManagerError):
    """Raised when bucket name or configuration validation fails."""


class BucketOperationError(S3ManagerError):
    """Raised when MinIO bucket operations fail."""


class UserOperationError(S3ManagerError):
    """Raised when MinIO user operations fail."""


class GroupOperationError(S3ManagerError):
    """Raised when MinIO group operations fail."""


class GroupNotFoundError(GroupOperationError):
    """Raised when a MinIO group does not exist."""


class DataGovernanceError(S3ManagerError):
    """Raised when data governance validation fails."""


class PolarisOperationError(S3ManagerError):
    """Raised when an Apache Polaris catalog operation fails."""

    # Polaris operations inspect upstream HTTP status for 404/409 control flow.
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class ValidationError(S3ManagerError):
    """Raised when general validation fails."""


class CredentialOperationError(S3ManagerError):
    """Raised when credential operations fail (e.g., lock contention)."""


class ConnectionError(S3ManagerError):
    """Raised when MinIO server connection fails."""


# ----- Tenant exceptions -----


class TenantError(S3Error):
    """Super class for tenant related errors."""


class TenantOperationError(TenantError):
    """Raised when a tenant operation fails due to invalid input."""


class TenantAuthorizationError(TenantError):
    """Raised when a user lacks permission for a tenant operation."""


class TenantNotFoundError(TenantError):
    """Raised when a tenant or tenant resource is not found."""
