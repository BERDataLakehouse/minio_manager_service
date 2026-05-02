"""
Custom error types for the MinIO Manager Service.
"""

# mostly copied from https://github.com/kbase/cdm-task-service/blob/main/cdmtaskservice/errors.py

from enum import Enum


class ErrorType(Enum):
    """
    The type of an error, consisting of an error code and a brief string describing the type.
    :ivar error_code: an integer error code.
    :ivar error_type: a brief string describing the error type.
    """

    # ----- Authentication error types -----
    AUTHENTICATION_FAILED = (10000, "Authentication failed")
    """ A general authentication error. """

    NO_TOKEN = (10010, "No authentication token")
    """ No token was provided when required. """

    INVALID_TOKEN = (10020, "Invalid token")
    """ The token provided is not valid. """

    INVALID_AUTH_HEADER = (10030, "Invalid authentication header")
    """ The authentication header is not valid. """

    MISSING_ROLE = (10040, "Missing required role")
    """ The user is missing a required role. """

    # ----- MinIO specific error types -----
    S3_ERROR = (20000, "S3 service error")
    """ A general error related to MinIO service. """

    S3_MANAGER_ERROR = (20010, "S3 manager error")
    """ A general error related to MinIO Manager operations. """

    POLICY_VALIDATION_ERROR = (20015, "MinIO policy validation error")
    """ MinIO policy content validation failed. """

    POLICY_OPERATION_ERROR = (20016, "MinIO policy operation error")
    """ MinIO policy operation failed. """

    BUCKET_OPERATION_ERROR = (20020, "MinIO bucket operation error")
    """ A MinIO bucket operation failed. """

    USER_OPERATION_ERROR = (20030, "MinIO user operation error")
    """ A MinIO user operation failed. """

    GROUP_OPERATION_ERROR = (20040, "MinIO group operation error")
    """ A MinIO group operation failed. """

    GROUP_NOT_FOUND_ERROR = (20041, "MinIO group not found")
    """ A MinIO group was not found. """

    DATA_GOVERNANCE_ERROR = (20042, "Data governance policy violation")
    """ A data governance policy was violated. """

    POLARIS_OPERATION_ERROR = (20043, "Polaris catalog operation error")
    """ An Apache Polaris catalog operation failed. """

    CREDENTIAL_OPERATION_ERROR = (20045, "Credential operation error")
    """ A credential operation failed (e.g., lock contention). """

    CONNECTION_ERROR = (20050, "MinIO connection error")
    """ MinIO server connection failed. """

    REQUEST_VALIDATION_FAILED = (30010, "Request validation failed")
    """ A request to a service failed validation of the request. """

    BUCKET_VALIDATION_ERROR = (30020, "Bucket validation error")
    """ Bucket name validation failed. """

    VALIDATION_ERROR = (30030, "Validation error")
    """ General validation error. """

    # ----- Tenant error types -----
    TENANT_OPERATION_ERROR = (40010, "Tenant operation error")
    """ A tenant operation failed due to invalid input. """

    TENANT_AUTHORIZATION_ERROR = (40020, "Tenant authorization error")
    """ The user lacks permission for a tenant operation. """

    TENANT_NOT_FOUND_ERROR = (40030, "Tenant not found")
    """ A tenant or tenant resource was not found. """

    def __init__(self, error_code, error_type):
        self.error_code = error_code
        self.error_type = error_type
