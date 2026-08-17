"""JWT claim construction unit tests.

These assert the exact contents of every token the IdP issues, which is why the claim builders are
free of I/O: the shape of a token is the contract with every relying party, and it should be
checkable in milliseconds without a database.
"""

from __future__ import annotations

import base64
import hashlib

from app.services import claims

USER = claims.UserClaimSource(
    user_id="01HZUSER",
    email="user@example.test",
    email_verified=True,
    full_name="Test User",
    given_name="Test",
    family_name="User",
    picture_url="https://cdn.example.test/avatar.png",
    updated_at_epoch=1_700_000_000,
)


def test_access_token_carries_the_rfc_9068_claim_set() -> None:
    payload = claims.build_access_token_claims(
        issuer="https://idp.example.test",
        subject=USER.user_id,
        audiences=["https://idp.example.test", "https://api.example.test"],
        client_id="demo-client",
        scopes=["openid", "profile"],
        issued_at=1_700_000_000,
        expires_at=1_700_000_600,
        jti="01HZJTI",
        auth_time=1_699_999_000,
        session_id="sess-ref",
    )
    assert payload["iss"] == "https://idp.example.test"
    assert payload["sub"] == USER.user_id
    assert payload["client_id"] == "demo-client"
    assert payload["exp"] - payload["iat"] == 600
    assert payload["nbf"] == payload["iat"]
    assert payload["jti"] == "01HZJTI"
    assert payload["auth_time"] == 1_699_999_000
    assert payload["sid"] == "sess-ref"


def test_access_token_scope_is_a_space_delimited_string() -> None:
    """RFC 6749 §3.3 form. Resource-server middleware expects the string, not a JSON array."""
    payload = claims.build_access_token_claims(
        issuer="https://idp.example.test",
        subject="s",
        audiences=["a"],
        client_id="c",
        scopes=["openid", "profile", "reports:read"],
        issued_at=0,
        expires_at=600,
        jti="j",
    )
    assert payload["scope"] == "openid profile reports:read"


def test_single_audience_is_a_string_and_several_are_a_list() -> None:
    """Both forms are legal (RFC 7519 §4.1.3); some client libraries only handle one."""
    single = claims.build_access_token_claims(
        issuer="i",
        subject="s",
        audiences=["only"],
        client_id="c",
        scopes=[],
        issued_at=0,
        expires_at=1,
        jti="j",
    )
    several = claims.build_access_token_claims(
        issuer="i",
        subject="s",
        audiences=["one", "two"],
        client_id="c",
        scopes=[],
        issued_at=0,
        expires_at=1,
        jti="j",
    )
    assert single["aud"] == "only"
    assert several["aud"] == ["one", "two"]


def test_access_token_omits_identity_claims_entirely() -> None:
    """An access token is an authorization artifact, not a place to leak personal data.

    It goes to resource servers, which may be third parties; profile and email claims belong in the
    ID token and UserInfo, where the client is the audience.
    """
    payload = claims.build_access_token_claims(
        issuer="i",
        subject="s",
        audiences=["a"],
        client_id="c",
        scopes=["openid", "profile", "email"],
        issued_at=0,
        expires_at=600,
        jti="j",
    )
    assert "email" not in payload
    assert "name" not in payload


def test_id_token_audience_is_the_client_not_a_resource_server() -> None:
    payload = claims.build_id_token_claims(
        issuer="https://idp.example.test",
        subject=USER.user_id,
        client_id="demo-client",
        issued_at=1_700_000_000,
        expires_at=1_700_000_600,
        auth_time=1_699_999_000,
        nonce="nonce-value",
        granted_scopes=["openid"],
        user=USER,
    )
    assert payload["aud"] == "demo-client"
    assert payload["azp"] == "demo-client"
    assert payload["nonce"] == "nonce-value"
    assert payload["auth_time"] == 1_699_999_000


def test_id_token_omits_nonce_when_the_client_did_not_send_one() -> None:
    """Absent, not empty: OIDC Core says a client that sent no nonce must not receive one, and an
    empty string would look to a strict client like a mismatch."""
    payload = claims.build_id_token_claims(
        issuer="i",
        subject="s",
        client_id="c",
        issued_at=0,
        expires_at=600,
        auth_time=0,
        nonce=None,
        granted_scopes=["openid"],
        user=USER,
    )
    assert "nonce" not in payload


def test_at_hash_is_the_left_half_of_sha256_base64url() -> None:
    """OIDC Core §3.1.3.6, which binds the ID token to the access token issued with it."""
    access_token = "some.access.token"
    digest = hashlib.sha256(access_token.encode()).digest()
    expected = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()
    assert claims.compute_at_hash(access_token) == expected

    payload = claims.build_id_token_claims(
        issuer="i",
        subject="s",
        client_id="c",
        issued_at=0,
        expires_at=600,
        auth_time=0,
        nonce=None,
        granted_scopes=["openid"],
        user=USER,
        access_token=access_token,
    )
    assert payload["at_hash"] == expected


def test_profile_claims_appear_only_with_the_profile_scope() -> None:
    without = claims.build_id_token_claims(
        issuer="i",
        subject="s",
        client_id="c",
        issued_at=0,
        expires_at=600,
        auth_time=0,
        nonce=None,
        granted_scopes=["openid"],
        user=USER,
    )
    assert "name" not in without
    assert "given_name" not in without

    with_profile = claims.build_id_token_claims(
        issuer="i",
        subject="s",
        client_id="c",
        issued_at=0,
        expires_at=600,
        auth_time=0,
        nonce=None,
        granted_scopes=["openid", "profile"],
        user=USER,
    )
    assert with_profile["name"] == "Test User"
    assert with_profile["given_name"] == "Test"
    assert with_profile["picture"] == "https://cdn.example.test/avatar.png"


def test_email_claims_appear_only_with_the_email_scope() -> None:
    without = claims.build_userinfo_response(user=USER, granted_scopes=["openid", "profile"])
    assert "email" not in without

    with_email = claims.build_userinfo_response(user=USER, granted_scopes=["openid", "email"])
    assert with_email["email"] == "user@example.test"
    assert with_email["email_verified"] is True


def test_userinfo_always_includes_sub_even_with_no_identity_scopes() -> None:
    """OIDC Core §5.3.2 requires `sub`, and a client needs it to match the response to a session."""
    response = claims.build_userinfo_response(user=USER, granted_scopes=[])
    assert response == {"sub": USER.user_id}


def test_null_profile_fields_are_omitted_rather_than_sent_as_null() -> None:
    sparse = claims.UserClaimSource(user_id="u", email="u@example.test", email_verified=False)
    response = claims.build_userinfo_response(user=sparse, granted_scopes=["profile", "email"])
    assert "name" not in response
    assert "picture" not in response
    assert response["email_verified"] is False


def test_scope_parsing_drops_duplicates_and_preserves_order() -> None:
    assert claims.parse_scope_string("openid profile openid email") == [
        "openid",
        "profile",
        "email",
    ]


def test_scope_parsing_handles_plus_encoded_and_empty_input() -> None:
    """Some clients form-encode the scope parameter, turning spaces into `+`."""
    assert claims.parse_scope_string("openid+profile") == ["openid", "profile"]
    assert claims.parse_scope_string(None) == []
    assert claims.parse_scope_string("") == []
    assert claims.parse_scope_string("   ") == []
