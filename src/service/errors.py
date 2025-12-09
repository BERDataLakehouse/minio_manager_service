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
    MINIO_ERROR = (20000, "MinIO service error")
    """ A general error related to MinIO service. """

    MINIO_MANAGER_ERROR = (20010, "MinIO manager error")
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

    DATA_GOVERNANCE_ERROR = (20042, "Data governance policy violation")
    """ A data governance policy was violated. """

    CONNECTION_ERROR = (20050, "MinIO connection error")
    """ MinIO server connection failed. """

    REQUEST_VALIDATION_FAILED = (30010, "Request validation failed")
    """ A request to a service failed validation of the request. """

    BUCKET_VALIDATION_ERROR = (30020, "Bucket validation error")
    """ Bucket name validation failed. """

    VALIDATION_ERROR = (30030, "Validation error")
    """ General validation error. """

    def __init__(self, error_code, error_type):
        self.error_code = error_code
        self.error_type = error_type
