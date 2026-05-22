"""
Health check routes for the API.
"""

from typing import Annotated

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel, Field

router = APIRouter(tags=["health"])


class DatabaseHealth(BaseModel):
    """Per-pool reachability for the dual-pool DatabasePool."""

    primary: Annotated[bool, Field(description="True when the rw pool answered SELECT 1")]
    replica: Annotated[bool, Field(description="True when the ro pool answered SELECT 1")]
    replica_enabled: Annotated[
        bool,
        Field(
            description=(
                "True when ro is a distinct pool. False means ro is aliased to "
                "primary (either by config or replica startup failure)."
            )
        ),
    ]


class HealthResponse(BaseModel):
    """Health check response model.

    The HTTP status code reflects readiness — 200 when the primary is
    reachable, 503 otherwise. Replica failure is reported as ``degraded`` in
    the body but does not change the status code, so Kubernetes readiness
    probes don't evict a pod whose ro pool is aliased to rw.
    """

    status: Annotated[
        str,
        Field(description="One of: healthy, degraded, unhealthy"),
    ]
    database: DatabaseHealth


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description=(
        "Reports per-pool database reachability. Returns 503 if the primary "
        "pool is unreachable; returns 200 with status='degraded' if only the "
        "replica is unreachable (the service still serves reads via the "
        "primary fallback)."
    ),
)
async def health_check(request: Request, response: Response):
    """Health check endpoint."""
    db_pool = getattr(request.app.state, "_db_pool", None)
    if db_pool is None:
        # Pool not yet initialized — startup race. Treat as unhealthy.
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthResponse(
            status="unhealthy",
            database=DatabaseHealth(
                primary=False, replica=False, replica_enabled=False
            ),
        )

    db_status = await db_pool.health_check()
    primary_ok = db_status["primary"]
    replica_ok = db_status["replica"]
    replica_enabled = db_pool.replica_enabled

    if not primary_ok:
        overall = "unhealthy"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif replica_enabled and not replica_ok:
        overall = "degraded"
    else:
        overall = "healthy"

    return HealthResponse(
        status=overall,
        database=DatabaseHealth(
            primary=primary_ok,
            replica=replica_ok,
            replica_enabled=replica_enabled,
        ),
    )
