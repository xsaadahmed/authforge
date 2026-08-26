"""``authforge-admin`` — the primary administrative interface.

Client and user registration is an authenticated admin operation by design (§31), and a CLI is
the right shape for it: no anonymous registration endpoint to abuse, no admin web UI to build and
secure, and every command is scriptable from a deployment pipeline or an ECS exec session.

Commands are grouped by noun (``clients``, ``users``, ``scopes``, ``keys``) and each opens the
container, does one unit of work, and shuts down cleanly.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated

import typer

from app.config import Settings, get_settings
from app.container import Container, build_container, shutdown, startup
from app.core.errors import DomainError
from app.models.audit import AuditEventType
from app.models.client import ClientType, TokenEndpointAuthMethod
from app.models.token import RevocationReason
from app.repositories.audit_repository import AuditRepository
from app.repositories.client_repository import ClientRepository
from app.repositories.scope_repository import ScopeRepository
from app.repositories.user_repository import UserRepository
from app.security.passwords import PasswordHasherService, PasswordPolicyError

app = typer.Typer(help="AuthForge administration.", no_args_is_help=True, add_completion=False)
clients_app = typer.Typer(help="Register and manage OAuth clients.", no_args_is_help=True)
users_app = typer.Typer(help="Manage end users.", no_args_is_help=True)
scopes_app = typer.Typer(help="Manage the scope catalogue.", no_args_is_help=True)
keys_app = typer.Typer(help="Manage signing keys.", no_args_is_help=True)
audit_app = typer.Typer(help="Inspect the audit trail.", no_args_is_help=True)
app.add_typer(clients_app, name="clients")
app.add_typer(users_app, name="users")
app.add_typer(scopes_app, name="scopes")
app.add_typer(keys_app, name="keys")
app.add_typer(audit_app, name="audit")

# The OIDC-defined scopes plus `offline_access`. Seeded rather than hard-coded into the protocol
# logic so a deployment can add its own API scopes without touching the code.
DEFAULT_SCOPES: tuple[tuple[str, str, bool, bool], ...] = (
    ("openid", "Confirm your identity", True, True),
    ("profile", "See your name and profile details", True, True),
    ("email", "See your email address", True, False),
    (
        "offline_access",
        "Stay signed in and refresh access without asking you again",
        True,
        False,
    ),
)


def _run[T](operation: Callable[[Container], Awaitable[T]]) -> T:
    """Boot the container, run one coroutine, tear it down."""

    async def _main() -> T:
        settings: Settings = get_settings()
        container = build_container(settings)
        # Signing-key bootstrap is skipped: a CLI invocation should not silently create key
        # material as a side effect of, say, listing clients. `keys rotate` does it explicitly.
        await startup(container, ensure_signing_key=False)
        try:
            return await operation(container)
        finally:
            await shutdown(container)

    try:
        return asyncio.run(_main())
    except DomainError as exc:
        typer.secho(f"error: {exc.description}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc


def _echo_json(payload: object) -> None:
    typer.echo(json.dumps(payload, indent=2, default=str))


# --------------------------------------------------------------------------- scopes
@scopes_app.command("seed")
def seed_scopes() -> None:
    """Create or update the standard OIDC scope catalogue. Idempotent."""

    async def operation(container: Container) -> list[str]:
        async with container.database.session() as session:
            repository = ScopeRepository(session)
            for name, description, is_oidc, is_default in DEFAULT_SCOPES:
                await repository.upsert(
                    name=name, description=description, is_oidc=is_oidc, is_default=is_default
                )
            return sorted(await repository.list_names())

    names = _run(operation)
    typer.secho(f"scope catalogue: {', '.join(names)}", fg=typer.colors.GREEN)


@scopes_app.command("add")
def add_scope(
    name: Annotated[str, typer.Argument(help="Scope name, e.g. reports:read")],
    description: Annotated[str, typer.Option(help="Shown to the user on the consent screen")],
) -> None:
    """Add a deployment-specific API scope."""

    async def operation(container: Container) -> None:
        async with container.database.session() as session:
            await ScopeRepository(session).upsert(name=name, description=description)

    _run(operation)
    typer.secho(f"scope {name!r} registered", fg=typer.colors.GREEN)


@scopes_app.command("list")
def list_scopes() -> None:
    async def operation(container: Container) -> list[dict[str, object]]:
        async with container.database.session() as session:
            return [
                {
                    "name": scope.name,
                    "description": scope.description,
                    "oidc": scope.is_oidc,
                    "default": scope.is_default,
                }
                for scope in await ScopeRepository(session).list_all()
            ]

    _echo_json(_run(operation))


# --------------------------------------------------------------------------- clients
@clients_app.command("create")
def create_client(
    name: Annotated[str, typer.Option(help="Human-readable client name")],
    redirect_uri: Annotated[list[str], typer.Option(help="Exact redirect URI; repeat for several")],
    scope: Annotated[list[str] | None, typer.Option(help="Scope the client may request")] = None,
    client_id: Annotated[str | None, typer.Option(help="Override the generated client_id")] = None,
    public: Annotated[
        bool, typer.Option("--public", help="Register a public client (no secret, PKCE only)")
    ] = False,
    skip_consent: Annotated[
        bool,
        typer.Option(
            "--skip-consent",
            help="First-party client: do not show a consent screen for this client",
        ),
    ] = False,
    no_refresh: Annotated[
        bool, typer.Option("--no-refresh", help="Never issue refresh tokens to this client")
    ] = False,
) -> None:
    """Register a client and print its credentials.

    The secret is displayed exactly once: only its SHA-256 hash is stored, so a lost secret has to
    be rotated rather than recovered.
    """

    async def operation(container: Container) -> dict[str, object]:
        async with container.database.session() as session:
            result = await container.clients.register_client(
                session,
                client_name=name,
                client_type=ClientType.PUBLIC if public else ClientType.CONFIDENTIAL,
                redirect_uris=redirect_uri,
                allowed_scopes=scope or [],
                client_id=client_id,
                require_consent=not skip_consent,
                allow_refresh_tokens=not no_refresh,
                token_endpoint_auth_method=(TokenEndpointAuthMethod.NONE if public else None),
            )
            await container.audit.record_in_transaction(
                session,
                AuditEventType.CLIENT_CREATED,
                client_id=result.client.client_id,
                detail={"client_name": name, "via": "cli"},
            )
            return {
                "client_id": result.client.client_id,
                "client_secret": result.client_secret,
                "client_type": result.client.client_type,
                "token_endpoint_auth_method": result.client.token_endpoint_auth_method,
                "redirect_uris": result.client.redirect_uri_values,
                "allowed_scopes": sorted(result.client.allowed_scope_names),
                "require_consent": result.client.require_consent,
            }

    payload = _run(operation)
    _echo_json(payload)
    if payload.get("client_secret"):
        typer.secho(
            "store client_secret now — it cannot be retrieved again", fg=typer.colors.YELLOW
        )


@clients_app.command("list")
def list_clients() -> None:
    async def operation(container: Container) -> list[dict[str, object]]:
        async with container.database.session() as session:
            return [
                {
                    "client_id": client.client_id,
                    "client_name": client.client_name,
                    "client_type": client.client_type,
                    "active": client.is_active,
                    "redirect_uris": client.redirect_uri_values,
                    "allowed_scopes": sorted(client.allowed_scope_names),
                }
                for client in await ClientRepository(session).list_clients()
            ]

    _echo_json(_run(operation))


@clients_app.command("rotate-secret")
def rotate_client_secret(client_id: Annotated[str, typer.Argument()]) -> None:
    async def operation(container: Container) -> dict[str, str]:
        async with container.database.session() as session:
            secret = await container.clients.rotate_client_secret(session, client_id=client_id)
            return {"client_id": client_id, "client_secret": secret}

    _echo_json(_run(operation))


@clients_app.command("disable")
def disable_client(client_id: Annotated[str, typer.Argument()]) -> None:
    """Disable a client and revoke every refresh token it holds."""

    async def operation(container: Container) -> int:
        async with container.database.session() as session:
            client = await container.clients.get_client_or_404(session, client_id)
            await ClientRepository(session).set_active(client_id=client.id, is_active=False)
            return await container.tokens.revoke_all_for_client(
                session, client=client, reason=RevocationReason.ADMIN_ACTION
            )

    revoked = _run(operation)
    typer.secho(
        f"client {client_id} disabled; {revoked} refresh token(s) revoked", fg=typer.colors.GREEN
    )


# --------------------------------------------------------------------------- users
@users_app.command("create")
def create_user(
    email: Annotated[str, typer.Option(help="Login email")],
    password: Annotated[
        str | None,
        typer.Option(
            "--password",
            help="Plaintext password. Prefer this over the prompt when running non-interactively "
            "(e.g. an ECS one-off task).",
        ),
    ] = None,
    full_name: Annotated[str | None, typer.Option()] = None,
    admin: Annotated[bool, typer.Option("--admin", help="Grant the admin flag")] = False,
    verified: Annotated[
        bool, typer.Option("--verified", help="Mark the email address as verified")
    ] = False,
) -> None:
    """Create a user with an Argon2id-hashed password.

    Interactive use prompts for the password. Pass ``--password`` for non-interactive
    admin tasks (ECS run-task); that value will appear in the task command list, so use
    it only for synthetic accounts.
    """

    if password is None:
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)

    async def operation(container: Container) -> dict[str, object]:
        hasher = PasswordHasherService(container.settings)
        async with container.database.session() as session:
            users = UserRepository(session)
            if await users.get_by_email(email) is not None:
                raise DomainError(f"a user with email {email} already exists")
            user = await users.create(
                email=email,
                password_hash=hasher.hash(password),
                full_name=full_name,
                email_verified=verified,
                is_admin=admin,
            )
            await container.audit.record_in_transaction(
                session, AuditEventType.USER_CREATED, user_id=user.id, detail={"via": "cli"}
            )
            return {"id": user.id, "email": user.email, "is_admin": user.is_admin}

    _echo_json(_run(operation))


@users_app.command("list")
def list_users() -> None:
    async def operation(container: Container) -> list[dict[str, object]]:
        async with container.database.session() as session:
            return [
                {
                    "id": user.id,
                    "email": user.email,
                    "active": user.is_active,
                    "admin": user.is_admin,
                    "mfa_enrolled": user.mfa_enrolled,
                    "locked_until": user.locked_until,
                }
                for user in await UserRepository(session).list_users()
            ]

    _echo_json(_run(operation))


@users_app.command("unlock")
def unlock_user(email: Annotated[str, typer.Argument()]) -> None:
    """Clear a lockout and its failure counter."""

    async def operation(container: Container) -> None:
        async with container.database.session() as session:
            users = UserRepository(session)
            user = await users.get_by_email(email)
            if user is None:
                raise DomainError(f"no user with email {email}")
            await users.clear_lockout(user.id)

    _run(operation)
    typer.secho(f"{email} unlocked", fg=typer.colors.GREEN)


@users_app.command("revoke-tokens")
def revoke_user_tokens(email: Annotated[str, typer.Argument()]) -> None:
    """Revoke every refresh token a user holds, across all clients."""

    async def operation(container: Container) -> int:
        async with container.database.session() as session:
            user = await UserRepository(session).get_by_email(email)
            if user is None:
                raise DomainError(f"no user with email {email}")
            return await container.tokens.revoke_all_for_user(
                session, user_id=user.id, reason=RevocationReason.ADMIN_ACTION
            )

    count = _run(operation)
    typer.secho(f"revoked {count} refresh token(s) for {email}", fg=typer.colors.GREEN)


# --------------------------------------------------------------------------- keys
@keys_app.command("list")
def list_keys() -> None:
    async def operation(container: Container) -> list[dict[str, str]]:
        return [
            {"kid": key.kid, "algorithm": key.algorithm, "status": key.status}
            for key in await container.keys.list_keys()
        ]

    _echo_json(_run(operation))


@keys_app.command("init")
def init_keys() -> None:
    """Create the first signing key if the deployment has none. Idempotent.

    Prefer this over ``keys rotate`` on a brand-new environment: it is a no-op when a
    current key already exists. ``keys rotate`` also works with zero keys (it simply
    creates the first ``current`` key), but is the wrong verb for bootstrap because a
    second call would demote the first key to ``retiring``.
    """

    async def operation(container: Container) -> str:
        return await container.keys.ensure_initialized()

    typer.secho(f"current signing key: {_run(operation)}", fg=typer.colors.GREEN)


@keys_app.command("bootstrap")
def bootstrap_keys() -> None:
    """Alias of ``keys init`` — create the first signing key when none exist."""

    async def operation(container: Container) -> str:
        return await container.keys.ensure_initialized()

    typer.secho(f"current signing key: {_run(operation)}", fg=typer.colors.GREEN)


@keys_app.command("rotate")
def rotate_keys(
    reason: Annotated[str, typer.Option(help="Recorded in the audit trail")] = "manual",
) -> None:
    """Rotate the signing key.

    The previous key moves to `retiring` and keeps verifying for its grace period, so tokens
    issued moments ago stay valid. No redeploy is needed: running tasks pick the new key up
    through their periodic metadata refresh.
    """

    async def operation(container: Container) -> str:
        kid = await container.keys.rotate(reason=reason)
        await container.audit.record_durable(
            AuditEventType.KEY_ROTATED, success=True, detail={"kid": kid, "reason": reason}
        )
        return kid

    typer.secho(f"rotated; new current key: {_run(operation)}", fg=typer.colors.GREEN)


@keys_app.command("sweep")
def sweep_keys() -> None:
    """Retire keys whose grace period has elapsed and destroy their private material."""

    async def operation(container: Container) -> list[str]:
        return await container.keys.sweep_retired_keys()

    retired = _run(operation)
    typer.secho(
        f"retired {len(retired)} key(s): {', '.join(retired) or 'none'}", fg=typer.colors.GREEN
    )


# --------------------------------------------------------------------------- audit
@audit_app.command("tail")
def tail_audit(
    limit: Annotated[int, typer.Option(help="Number of events to show")] = 25,
    event_type: Annotated[str | None, typer.Option(help="Filter by event type")] = None,
) -> None:
    """Show the most recent security events."""

    async def operation(container: Container) -> list[dict[str, object]]:
        async with container.database.session() as session:
            parsed = AuditEventType(event_type) if event_type else None
            events = await AuditRepository(session).list_events(event_type=parsed, limit=limit)
            return [
                {
                    "at": event.created_at.astimezone(UTC).isoformat(timespec="seconds"),
                    "event": event.event_type,
                    "success": event.success,
                    "user_id": event.user_id,
                    "client_id": event.client_id,
                    "ip": event.ip_address,
                    "request_id": event.request_id,
                    "detail": event.detail,
                }
                for event in events
            ]

    _echo_json(_run(operation))


@app.command("seed-loadtest")
def seed_loadtest(
    email: Annotated[str, typer.Option(help="Load-test user email")] = "loadtest@authforge.test",
    password: Annotated[
        str, typer.Option(help="Load-test user password (synthetic account only)")
    ] = "LoadtestPassw0rd!",  # noqa: S107 — synthetic k6 account, not a real credential
    client_id: Annotated[str, typer.Option(help="OAuth client_id for k6")] = "k6-loadtest",
    redirect_uri: Annotated[
        str, typer.Option(help="Registered redirect URI (must match k6 REDIRECT_URI)")
    ] = "https://rp.example.test/callback",
    client_name: Annotated[str, typer.Option()] = "k6 load test",
) -> None:
    """Create (or reset) a confidential client and a test user for k6.

    Idempotent: re-running rotates the client secret and resets the user password, then prints
    the values k6 needs. Intended for staging one-off tasks, not production.
    """

    async def operation(container: Container) -> dict[str, object]:
        hasher = PasswordHasherService(container.settings)
        try:
            hasher.validate_policy(password)
        except PasswordPolicyError as exc:
            raise DomainError(str(exc)) from exc
        scope_names = [name for name, *_ in DEFAULT_SCOPES]
        async with container.database.session() as session:
            scope_repo = ScopeRepository(session)
            for name, description, is_oidc, is_default in DEFAULT_SCOPES:
                await scope_repo.upsert(
                    name=name, description=description, is_oidc=is_oidc, is_default=is_default
                )

            clients = ClientRepository(session)
            existing = await clients.get_by_client_id(client_id)
            if existing is None:
                result = await container.clients.register_client(
                    session,
                    client_name=client_name,
                    client_type=ClientType.CONFIDENTIAL,
                    redirect_uris=[redirect_uri],
                    allowed_scopes=scope_names,
                    client_id=client_id,
                    require_consent=False,
                    allow_refresh_tokens=True,
                )
                issued_secret = result.client_secret
                await container.audit.record_in_transaction(
                    session,
                    AuditEventType.CLIENT_CREATED,
                    client_id=client_id,
                    detail={"client_name": client_name, "via": "cli-seed-loadtest"},
                )
            else:
                issued_secret = await container.clients.rotate_client_secret(
                    session, client_id=client_id
                )

            users = UserRepository(session)
            user = await users.get_by_email(email)
            if user is None:
                user = await users.create(
                    email=email,
                    password_hash=hasher.hash(password),
                    full_name="k6 load test",
                    email_verified=True,
                    is_admin=False,
                )
                await container.audit.record_in_transaction(
                    session,
                    AuditEventType.USER_CREATED,
                    user_id=user.id,
                    detail={"via": "cli-seed-loadtest"},
                )
            else:
                await users.set_password_hash(user.id, hasher.hash(password))
                await users.clear_lockout(user.id)

            return {
                "client_id": client_id,
                "client_secret": issued_secret,
                "user_email": user.email,
                "user_password": password,
                "redirect_uri": redirect_uri,
            }

    payload = _run(operation)
    _echo_json(payload)
    typer.echo("")
    typer.echo(
        "export "
        f"CLIENT_ID={payload['client_id']!s} "
        f"CLIENT_SECRET={payload['client_secret']!s} "
        f"USER_EMAIL={payload['user_email']!s} "
        f"USER_PASSWORD={payload['user_password']!s} "
        f"REDIRECT_URI={payload['redirect_uri']!s}"
    )
    typer.secho(
        "store these now — the client secret is not kept in plaintext",
        fg=typer.colors.YELLOW,
    )


@app.command("bootstrap")
def bootstrap(
    admin_email: Annotated[str, typer.Option(help="Email for the first admin user")],
    admin_password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, confirmation_prompt=True)
    ],
    demo_redirect_uri: Annotated[
        str, typer.Option(help="Redirect URI for the demo relying party")
    ] = "http://localhost:8100/callback",
) -> None:
    """One-shot local setup: scopes, a signing key, an admin user and the demo RP client.

    Exists so a clean checkout reaches a working end-to-end flow in one command; it is not
    intended for production, where users and clients are created individually and audited.
    """

    async def operation(container: Container) -> dict[str, object]:
        hasher = PasswordHasherService(container.settings)
        kid = await container.keys.ensure_initialized()
        async with container.database.session() as session:
            scope_repo = ScopeRepository(session)
            for name, description, is_oidc, is_default in DEFAULT_SCOPES:
                await scope_repo.upsert(
                    name=name, description=description, is_oidc=is_oidc, is_default=is_default
                )

            users = UserRepository(session)
            user = await users.get_by_email(admin_email)
            if user is None:
                user = await users.create(
                    email=admin_email,
                    password_hash=hasher.hash(admin_password),
                    full_name="AuthForge Admin",
                    email_verified=True,
                    is_admin=True,
                )

            existing = await ClientRepository(session).get_by_client_id("demo-web-client")
            if existing is not None:
                return {
                    "signing_key": kid,
                    "admin_user": user.email,
                    "client_id": existing.client_id,
                    "client_secret": None,
                    "note": "demo client already existed; secret unchanged",
                }
            result = await container.clients.register_client(
                session,
                client_name="AuthForge Demo Web Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=[demo_redirect_uri],
                allowed_scopes=[name for name, *_ in DEFAULT_SCOPES],
                client_id="demo-web-client",
            )
            return {
                "signing_key": kid,
                "admin_user": user.email,
                "client_id": result.client.client_id,
                "client_secret": result.client_secret,
                "created_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
            }

    _echo_json(_run(operation))


if __name__ == "__main__":  # pragma: no cover
    app()
