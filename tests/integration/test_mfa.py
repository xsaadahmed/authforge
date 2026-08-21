"""TOTP enrolment, MFA login challenge and recovery codes (§8F, §8G)."""

from __future__ import annotations

import time

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.container import Container
from app.models.audit import AuditEventType, AuditLog
from app.models.user import MfaCredential, RecoveryCode
from app.security import totp as totp_lib
from app.services.authentication import RECOVERY_CODE_COUNT
from tests.conftest import Seeded
from tests.helpers import login, redirect_params, submit_mfa

pytestmark = pytest.mark.integration


async def _enrol(app_client: AsyncClient, seeded: Seeded) -> tuple[str, list[str]]:
    """Complete enrolment through the real HTTP surface. Returns the secret and recovery codes."""
    await login(app_client, seeded)
    begin = await app_client.post("/account/mfa/enroll")
    assert begin.status_code == 200, begin.text
    secret = begin.json()["secret"]

    confirm = await app_client.post(
        "/account/mfa/confirm", json={"code": totp_lib.current_code(secret)}
    )
    assert confirm.status_code == 200, confirm.text
    return secret, confirm.json()["recovery_codes"]


async def test_enrolment_returns_a_secret_and_a_provisioning_uri(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    await login(app_client, seeded)
    response = await app_client.post("/account/mfa/enroll")
    assert response.status_code == 200
    payload = response.json()
    assert payload["digits"] == 6
    assert payload["period_seconds"] == 30
    assert payload["provisioning_uri"].startswith("otpauth://totp/")
    # A TOTP secret is a credential: it must never be cacheable.
    assert response.headers["cache-control"] == "no-store"


async def test_enrolment_requires_authentication(app_client: AsyncClient) -> None:
    """A second factor is an account-security operation, gated by the browser session rather than by
    an OAuth token: a third-party client with `profile` scope must not be able to replace a user's
    second factor."""
    response = await app_client.post("/account/mfa/enroll")
    assert response.status_code == 401


async def test_an_unconfirmed_secret_does_not_count_as_enrolled(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    """Otherwise a user who abandoned enrolment would be locked out by a factor they never set
    up."""
    await login(app_client, seeded)
    await app_client.post("/account/mfa/enroll")

    async with container.database.session() as session:
        credential = (
            (await session.execute(select(MfaCredential))).scalars().one()
        )
    assert credential.confirmed_at is None

    app_client.cookies.clear()
    response = await login(app_client, seeded)
    # Straight to a session, with no MFA challenge in between.
    assert response.status_code == 303
    assert not response.headers["location"].startswith("/mfa")


async def test_confirmation_with_a_wrong_code_is_rejected(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    await login(app_client, seeded)
    await app_client.post("/account/mfa/enroll")
    response = await app_client.post("/account/mfa/confirm", json={"code": "000000"})
    assert response.status_code == 400


async def test_confirmation_issues_recovery_codes_and_stores_only_hashes(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    _, codes = await _enrol(app_client, seeded)
    assert len(codes) == RECOVERY_CODE_COUNT
    assert len(set(codes)) == RECOVERY_CODE_COUNT

    async with container.database.session() as session:
        rows = (await session.execute(select(RecoveryCode))).scalars().all()
    stored = {row.code_hash for row in rows}
    assert len(rows) == RECOVERY_CODE_COUNT
    assert not stored & set(codes), "recovery codes must be stored hashed, never in plaintext"


async def test_enrolment_and_recovery_codes_are_one_atomic_transaction(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    """§12's requirement.

    Split across two transactions, a failure between them leaves either a confirmed factor with no
    recovery codes (a lockout waiting to happen) or codes for a factor that was never confirmed.
    """
    await _enrol(app_client, seeded)
    async with container.database.session() as session:
        credential = (await session.execute(select(MfaCredential))).scalars().one()
        codes = (await session.execute(select(RecoveryCode))).scalars().all()
    assert credential.confirmed_at is not None
    assert len(codes) == RECOVERY_CODE_COUNT


async def test_totp_secret_is_encrypted_at_rest(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    secret, _ = await _enrol(app_client, seeded)
    async with container.database.session() as session:
        credential = (await session.execute(select(MfaCredential))).scalars().one()
    assert secret not in credential.secret_encrypted
    assert credential.secret_encrypted.startswith("v1.")


async def test_login_requires_the_second_factor_once_enrolled(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    secret, _ = await _enrol(app_client, seeded)
    app_client.cookies.clear()

    password_step = await login(app_client, seeded)
    assert password_step.status_code == 303
    assert password_step.headers["location"].startswith("/mfa")
    # Crucially, no session cookie yet: a correct password alone authenticates nobody.
    assert app_client.cookies.get("authforge_session") is None

    pending_id = redirect_params(password_step)["pending_id"]
    completed = await submit_mfa(
        app_client, pending_id=pending_id, code=totp_lib.current_code(secret)
    )
    assert completed.status_code == 303
    assert app_client.cookies.get("authforge_session") is not None


async def test_a_wrong_totp_code_does_not_produce_a_session(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    await _enrol(app_client, seeded)
    app_client.cookies.clear()
    password_step = await login(app_client, seeded)
    pending_id = redirect_params(password_step)["pending_id"]

    response = await submit_mfa(app_client, pending_id=pending_id, code="000000")
    assert response.status_code == 200
    assert app_client.cookies.get("authforge_session") is None


async def test_a_totp_code_cannot_be_replayed(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """A valid code stays valid for ~90 seconds given the skew window, so single use matters.

    Without this, a code observed once — shoulder-surfed, phished, or captured by a proxy — is
    usable again inside that window.
    """
    secret, _ = await _enrol(app_client, seeded)
    code = totp_lib.current_code(secret)

    app_client.cookies.clear()
    first = await login(app_client, seeded)
    first_completed = await submit_mfa(
        app_client, pending_id=redirect_params(first)["pending_id"], code=code
    )
    assert first_completed.status_code == 303

    app_client.cookies.clear()
    second = await login(app_client, seeded)
    replay = await submit_mfa(
        app_client, pending_id=redirect_params(second)["pending_id"], code=code
    )
    assert replay.status_code == 200
    assert app_client.cookies.get("authforge_session") is None


async def test_a_forged_pending_id_cannot_complete_a_login(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """The pending-MFA record is the only bridge from a verified password to a session, so a guessed
    identifier must lead nowhere — there is no path to a session without a fresh password step."""
    from app.security.random_tokens import new_opaque_token

    secret, _ = await _enrol(app_client, seeded)
    app_client.cookies.clear()

    response = await submit_mfa(
        app_client, pending_id=new_opaque_token(), code=totp_lib.current_code(secret)
    )
    assert response.status_code == 200
    assert app_client.cookies.get("authforge_session") is None


async def test_a_recovery_code_completes_a_login_exactly_once(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    _, codes = await _enrol(app_client, seeded)
    app_client.cookies.clear()

    first = await login(app_client, seeded)
    used = await submit_mfa(
        app_client,
        pending_id=redirect_params(first)["pending_id"],
        code=codes[0],
        use_recovery_code=True,
    )
    assert used.status_code == 303
    assert app_client.cookies.get("authforge_session") is not None

    app_client.cookies.clear()
    second = await login(app_client, seeded)
    replay = await submit_mfa(
        app_client,
        pending_id=redirect_params(second)["pending_id"],
        code=codes[0],
        use_recovery_code=True,
    )
    assert replay.status_code == 200
    assert app_client.cookies.get("authforge_session") is None


async def test_recovery_codes_tolerate_user_formatting(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """These get written on paper and typed back in, so case and dashes must not matter."""
    _, codes = await _enrol(app_client, seeded)
    app_client.cookies.clear()
    challenge = await login(app_client, seeded)
    response = await submit_mfa(
        app_client,
        pending_id=redirect_params(challenge)["pending_id"],
        code=f"  {codes[1].lower().replace('-', ' ')}  ",
        use_recovery_code=True,
    )
    assert response.status_code == 303


async def test_regenerating_recovery_codes_invalidates_the_old_set(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """Codes are replaced, never added to, so a user who suspects an old printout leaked can
    end it."""
    _, original = await _enrol(app_client, seeded)
    response = await app_client.post("/account/mfa/recovery-codes")
    assert response.status_code == 200
    replacement = response.json()["recovery_codes"]
    assert not set(original) & set(replacement)

    app_client.cookies.clear()
    challenge = await login(app_client, seeded)
    rejected = await submit_mfa(
        app_client,
        pending_id=redirect_params(challenge)["pending_id"],
        code=original[0],
        use_recovery_code=True,
    )
    assert rejected.status_code == 200
    assert app_client.cookies.get("authforge_session") is None


async def test_repeated_mfa_failures_are_rate_limited(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """A 6-digit code is only strong if the number of guesses is bounded."""
    await _enrol(app_client, seeded)
    app_client.cookies.clear()
    challenge = await login(app_client, seeded)
    pending_id = redirect_params(challenge)["pending_id"]

    statuses = [
        (await submit_mfa(app_client, pending_id=pending_id, code=f"{index:06d}")).status_code
        for index in range(8)
    ]
    assert 429 in statuses
    assert app_client.cookies.get("authforge_session") is None


async def test_the_mfa_flow_resumes_the_original_authorization_request(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """The request the user was making must survive both the password and the MFA step."""
    secret, _ = await _enrol(app_client, seeded)
    app_client.cookies.clear()

    _, challenge_value = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge_value)
    initial = await app_client.get(f"/authorize?{query}")
    resume = redirect_params(initial)["next"]

    password_step = await login(app_client, seeded, next_query=resume)
    pending_id = redirect_params(password_step)["pending_id"]
    completed = await submit_mfa(
        app_client, pending_id=pending_id, code=totp_lib.current_code(secret)
    )
    assert completed.status_code == 303
    assert completed.headers["location"].startswith("/authorize?")
    assert "client_id" in completed.headers["location"]


async def test_mfa_verified_sessions_record_the_fact(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    secret, _ = await _enrol(app_client, seeded)
    app_client.cookies.clear()
    challenge = await login(app_client, seeded)
    await submit_mfa(
        app_client,
        pending_id=redirect_params(challenge)["pending_id"],
        code=totp_lib.current_code(secret),
    )
    session_id = app_client.cookies.get("authforge_session")
    assert session_id is not None
    state = await container.sessions.get(session_id)
    assert state is not None
    assert state.mfa_verified is True
    assert abs(state.auth_time - int(time.time())) < 60


async def test_mfa_events_are_audited(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    secret, _ = await _enrol(app_client, seeded)
    app_client.cookies.clear()
    challenge = await login(app_client, seeded)
    await submit_mfa(app_client, pending_id=redirect_params(challenge)["pending_id"], code="000000")
    await submit_mfa(
        app_client,
        pending_id=redirect_params(challenge)["pending_id"],
        code=totp_lib.current_code(secret),
    )

    async with container.database.session() as session:
        events = {
            row.event_type for row in (await session.execute(select(AuditLog))).scalars().all()
        }
    assert str(AuditEventType.MFA_ENROLLED) in events
    assert str(AuditEventType.MFA_CHALLENGE_ISSUED) in events
    assert str(AuditEventType.MFA_FAILURE) in events
    assert str(AuditEventType.MFA_SUCCESS) in events


async def test_re_enrolling_over_a_confirmed_factor_is_refused(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """Silently replacing a working factor would let an attacker with a hijacked session lock the
    real owner out; removing it has to be a deliberate, separate act."""
    await _enrol(app_client, seeded)
    response = await app_client.post("/account/mfa/enroll")
    assert response.status_code == 409
