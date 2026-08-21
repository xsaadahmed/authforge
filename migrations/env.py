"""Alembic environment.

Migrations run synchronously (psycopg via the plain ``postgresql://`` URL) even though the
application is async: a migration is a one-shot administrative task, and a synchronous driver
keeps the tooling simple and its failures obvious. The URL comes from the app's ``Settings``
(``AUTHFORGE_DATABASE_URL``) so there is one source of truth for connection strings.

The URL is never written into Alembic's ConfigParser-backed config: passwords often contain
URL-encoded ``%XX`` sequences, and ConfigParser treats ``%`` as interpolation syntax.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from app.config import get_settings
from app.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Single source of truth — never passed through config.set_main_option / ConfigParser.
DATABASE_URL = get_settings().sync_database_url()


def run_migrations_offline() -> None:
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Pass the URL straight to the engine — do not round-trip through Alembic's ini/ConfigParser.
    connectable = create_engine(DATABASE_URL, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Both on, so a column type or default that drifts from the models shows up as a
            # diff instead of silently persisting.
            compare_type=True,
            compare_server_default=True,
            # One transaction per migration run: a failure rolls the whole thing back rather than
            # leaving the schema half-applied.
            transaction_per_migration=False,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
