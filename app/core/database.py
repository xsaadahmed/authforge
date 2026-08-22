"""Async SQLAlchemy engine and session management.

One engine per process, one session per request. The engine is created lazily at startup
and disposed at shutdown so a Fargate task's connection pool is released cleanly on
SIGTERM instead of leaving RDS to time the connections out.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import Settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class Database:
    """Owns the engine/sessionmaker lifecycle for one process."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None

    def connect(self) -> None:
        if self._engine is not None:
            return
        settings = self._settings
        connect_args: dict[str, object] = {}
        if settings.database_statement_timeout_ms > 0:
            # A hung query holding a row lock on refresh_tokens would stall every refresh for
            # that family; bounding it server-side is cheaper than detecting it client-side.
            connect_args["server_settings"] = {
                "statement_timeout": str(settings.database_statement_timeout_ms),
                "application_name": f"authforge-{settings.environment}",
            }
        self._engine = create_async_engine(
            str(settings.database_url),
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_timeout=settings.database_pool_timeout_seconds,
            # Recycle below any typical idle-timeout on the RDS/proxy side so the app never
            # hands out a socket the server already closed.
            pool_recycle=1800,
            pool_pre_ping=True,
            connect_args=connect_args,
            echo=False,
        )
        self._sessionmaker = async_sessionmaker(
            bind=self._engine,
            expire_on_commit=False,
            autoflush=False,
        )
        logger.info(
            "database engine created",
            extra={"pool_size": settings.database_pool_size, "event": "db_engine_created"},
        )

    async def disconnect(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._sessionmaker = None
            logger.info("database engine disposed", extra={"event": "db_engine_disposed"})

    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("database not connected; call connect() during startup")
        return self._engine

    @property
    def sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        if self._sessionmaker is None:
            raise RuntimeError("database not connected; call connect() during startup")
        return self._sessionmaker

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """A unit of work: commit on success, roll back on any exception."""
        if self._engine is None:
            raise RuntimeError("database not connected; call connect() during startup")
        async with self.sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    async def healthcheck(self) -> bool:
        from sqlalchemy import text

        try:
            async with self.sessionmaker() as session:
                await session.execute(text("SELECT 1"))
            return True
        except Exception:
            logger.warning("database healthcheck failed", exc_info=True)
            return False
