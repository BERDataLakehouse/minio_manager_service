"""
Main application module for the MinIO Manager API.
"""

import logging

from fastapi import FastAPI, Request, Response
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import BaseHTTPMiddleware

from src.routes import credentials, health, management, sharing, workspaces
from src.service import app_state
from src.service.config import configure_logging, get_settings
from src.service.exception_handlers import universal_error_handler
from src.service.exceptions import InvalidAuthHeaderError
from src.service.models import ErrorResponse

# Configure logging
configure_logging()
logger = logging.getLogger(__name__)

# Middleware constants
_SCHEME = "Bearer"


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware to authenticate users and set them in the request state."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_user = None
        auth_header = request.headers.get("Authorization")

        if auth_header:
            scheme, credentials = get_authorization_scheme_param(auth_header)
            if not (scheme and credentials):
                raise InvalidAuthHeaderError(
                    f"Authorization header requires {_SCHEME} scheme followed by token"
                )
            if scheme.lower() != _SCHEME.lower():
                # don't put the received scheme in the error message, might be a token
                raise InvalidAuthHeaderError(
                    f"Authorization header requires {_SCHEME} scheme"
                )

            app_state_obj = app_state.get_app_state(request)
            request_user = await app_state_obj.auth.get_user(credentials)

        app_state.set_request_user(request, request_user)

        return await call_next(request)


def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        description=settings.app_description,
        version=settings.api_version,
        responses={
            "4XX": {"model": ErrorResponse},
            "5XX": {"model": ErrorResponse},
        },
    )

    # Add exception handlers
    app.add_exception_handler(Exception, universal_error_handler)

    # Add middleware
    app.add_middleware(GZipMiddleware)
    app.add_middleware(AuthMiddleware)

    # Include routers
    app.include_router(health.router, tags=["health"])
    app.include_router(credentials.router, tags=["credentials"])
    app.include_router(sharing.router, tags=["sharing"])
    app.include_router(workspaces.router, tags=["workspaces"])
    app.include_router(management.router, tags=["management"])

    # Add startup and shutdown event handlers
    async def startup_event():
        logger.info("Starting application")
        await app_state.build_app(app)
        logger.info("Application started")

    app.add_event_handler("startup", startup_event)

    async def shutdown_event():
        logger.info("Shutting down application")
        await app_state.destroy_app_state(app)
        logger.info("Application shut down")

    app.add_event_handler("shutdown", shutdown_event)

    return app
