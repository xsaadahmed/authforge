# Multi-stage build (§17).
#
# The builder installs dependencies into a virtualenv; the runtime copies that virtualenv and the
# application source and nothing else. Build tools, caches and the package index never reach the
# shipped image, which keeps it small and shrinks the vulnerability surface a scanner has to
# consider.

# ---------------------------------------------------------------------------- builder
FROM python:3.12-slim AS builder

# uv resolves and installs an order of magnitude faster than pip, which matters on every CI run.
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    VIRTUAL_ENV=/opt/venv

WORKDIR /build

# Dependencies are installed from the manifest alone, before the source is copied, so a change to
# application code reuses the cached dependency layer.
COPY pyproject.toml README.md ./
RUN uv venv "$VIRTUAL_ENV" \
 && uv pip install --python "$VIRTUAL_ENV/bin/python" --no-cache .

# ---------------------------------------------------------------------------- runtime
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="AuthForge" \
      org.opencontainers.image.description="OAuth 2.0 / OpenID Connect Identity Provider" \
      org.opencontainers.image.source="https://github.com/authforge/authforge"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Off by default: the app reads configuration from the environment, and ECS injects secrets from
    # Secrets Manager into the task at launch.
    AUTHFORGE_ENVIRONMENT=prod

# A dedicated unprivileged user with no login shell and no home directory to write into. Running as
# root inside a container turns any RCE into a container-root RCE for free.
RUN groupadd --system --gid 1001 authforge \
 && useradd --system --uid 1001 --gid authforge --no-create-home --shell /usr/sbin/nologin authforge

WORKDIR /srv/authforge

COPY --from=builder /opt/venv /opt/venv
COPY --chown=authforge:authforge app ./app
COPY --chown=authforge:authforge migrations ./migrations
COPY --chown=authforge:authforge alembic.ini ./

USER authforge

EXPOSE 8000

# Polls the liveness endpoint, which deliberately does not touch Postgres or Redis: a dependency blip
# should not make every container in the fleet report itself unhealthy at once (see app/api/routers/
# health.py).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

# One Uvicorn worker per container, scaled by ECS task count rather than in-process workers (§17):
# graceful shutdown is unambiguous, and ECS's health checks and deployment circuit breaker are the
# things that should be distributing load.
#
# --proxy-headers is required behind the ALB so the app sees the real client scheme and IP.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*", \
     "--no-access-log", \
     "--timeout-graceful-shutdown", "20"]
