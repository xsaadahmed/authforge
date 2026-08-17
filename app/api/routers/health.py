"""Liveness and readiness endpoints.

The two are separate on purpose. ``/health`` is what the ALB target group and the container
``HEALTHCHECK`` poll: it answers "is this process able to serve HTTP" and deliberately does not
touch Postgres or Redis. If it did, a brief RDS failover would fail every task's health check at
once and ECS would kill the entire fleet — turning a recoverable dependency blip into an outage.

``/ready`` does check dependencies, for deployment smoke tests and for a human asking whether a
task can actually do useful work.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Response, status

from app import __version__
from app.api.deps import ContainerDep

router = APIRouter(tags=["health"])


@router.get("/health", summary="Liveness probe")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/ready", summary="Readiness probe including datastore reachability")
async def ready(container: ContainerDep, response: Response) -> dict[str, Any]:
    database_ok, redis_ok = await asyncio.gather(
        container.database.healthcheck(), container.redis.healthcheck()
    )
    signing_key_ok = False
    if database_ok:
        try:
            signing_key_ok = bool((await container.keys.get_jwks())["keys"])
        except Exception:
            signing_key_ok = False

    ready_now = database_ok and redis_ok and signing_key_ok
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready_now else "not_ready",
        "version": __version__,
        "checks": {
            "postgres": "ok" if database_ok else "unavailable",
            "redis": "ok" if redis_ok else "unavailable",
            "signing_key": "ok" if signing_key_ok else "unavailable",
        },
    }
