"""Redirect-URI matching, client-credential parsing and registration policy.

Redirect-URI handling is the single highest-value piece of validation in an authorization server:
every relaxation of it has produced real code-exfiltration bugs in real products.
"""

from __future__ import annotations

import base64

import pytest

from app.config import Settings
from app.core.errors import DomainError
from app.models.client import ClientRedirectUri, OAuthClient
from app.services.clients import ClientService

REGISTERED = "https://rp.example.test/callback"


def _client(*uris: str) -> OAuthClient:
    client = OAuthClient(
        client_id="c",
        client_type="confidential",
        token_endpoint_auth_method="client_secret_basic",
        client_name="Test",
    )
    client.redirect_uris = [ClientRedirectUri(uri=uri) for uri in uris]
    return client


@pytest.fixture
def service() -> ClientService:
    return ClientService(settings=Settings(environment="test"))


def test_exact_match_is_accepted(service: ClientService) -> None:
    assert service.match_redirect_uri(_client(REGISTERED), REGISTERED) == REGISTERED


@pytest.mark.parametrize(
    "candidate",
    [
        "https://rp.example.test/callback/",  # trailing slash
        "https://rp.example.test/callback?extra=1",  # added query
        "https://rp.example.test/Callback",  # different case in the path
        "https://rp.example.test:443/callback",  # explicit default port
        "http://rp.example.test/callback",  # downgraded scheme
        "https://rp.example.test.evil.com/callback",  # suffix-attached host
        "https://evil.com/callback",  # unrelated host
        "https://rp.example.test/callback/../../evil",  # traversal
        "https://rp.example.test/callback#fragment",  # added fragment
        "//rp.example.test/callback",  # protocol-relative
        "https://rp.example.test/callbac",  # prefix of the registered path
        "https://rp.example.test/callbackk",  # registered path as a prefix
        "",
    ],
)
def test_everything_other_than_an_exact_match_is_rejected(
    service: ClientService, candidate: str
) -> None:
    """Byte-for-byte comparison, deliberately.

    Each of these is accepted by at least one real-world "smart" matcher. Normalising ports, case
    or trailing slashes means answering questions ("is /cb/../../evil the same as /cb?") that no two
    URL libraries answer identically — so the answer here is never to ask.
    """
    assert service.match_redirect_uri(_client(REGISTERED), candidate) is None


def test_a_client_may_register_several_uris_and_each_matches_exactly(
    service: ClientService,
) -> None:
    client = _client(REGISTERED, "https://rp.example.test/other")
    assert service.match_redirect_uri(client, REGISTERED) == REGISTERED
    assert service.match_redirect_uri(client, "https://rp.example.test/other") is not None
    assert service.match_redirect_uri(client, "https://rp.example.test/third") is None


# ---------------------------------------------------------------------- registration policy
def test_https_uris_are_accepted_at_registration(service: ClientService) -> None:
    service.validate_redirect_uri_registration("https://rp.example.test/callback")


def test_loopback_http_is_accepted_for_native_apps(service: ClientService) -> None:
    """RFC 8252 §7.3: a native app's loopback redirect cannot use https, and there is no network to
    intercept."""
    service.validate_redirect_uri_registration("http://127.0.0.1:8100/callback")
    service.validate_redirect_uri_registration("http://localhost:8100/callback")


def test_non_loopback_http_is_refused(service: ClientService) -> None:
    with pytest.raises(DomainError, match="https"):
        service.validate_redirect_uri_registration("http://rp.example.test/callback")


def test_loopback_is_refused_in_a_deployed_environment() -> None:
    """A loopback redirect registered against a production IdP points at the *user's* machine, which
    is not a redirect target a production client should have."""
    deployed = ClientService(
        settings=Settings(
            environment="prod",
            issuer="https://idp.example.com",
            signing_key_provider="aws_secrets_manager",
            totp_encryption_key="a-real-32-byte-random-value-here-ok",
        )
    )
    with pytest.raises(DomainError):
        deployed.validate_redirect_uri_registration("http://localhost:8100/callback")


def test_uris_with_a_fragment_are_refused(service: ClientService) -> None:
    """RFC 6749 §3.1.2: the fragment is where a response goes, so it cannot be pre-registered."""
    with pytest.raises(DomainError, match="fragment"):
        service.validate_redirect_uri_registration("https://rp.example.test/cb#frag")


def test_relative_uris_are_refused(service: ClientService) -> None:
    with pytest.raises(DomainError, match="absolute"):
        service.validate_redirect_uri_registration("/callback")


def test_private_use_schemes_must_be_reverse_dns(service: ClientService) -> None:
    """RFC 8252 §7.1. `myapp://` is squattable by any other app on the device; `com.example.app://`
    is tied to a domain the developer controls."""
    service.validate_redirect_uri_registration("com.example.app://oauth/callback")
    with pytest.raises(DomainError, match="reverse-DNS"):
        service.validate_redirect_uri_registration("myapp://oauth/callback")


# ---------------------------------------------------------------------- credential parsing
def test_basic_auth_credentials_are_decoded() -> None:
    header = "Basic " + base64.b64encode(b"my-client:my-secret").decode()
    credentials = ClientService.extract_credentials(
        authorization_header=header, form_client_id=None, form_client_secret=None
    )
    assert credentials.client_id == "my-client"
    assert credentials.client_secret == "my-secret"
    assert credentials.used_basic_auth


def test_basic_auth_halves_are_form_urldecoded() -> None:
    """RFC 6749 §2.3.1 requires form-encoding each half before base64, which matters for a secret
    containing `:`, `+` or non-ASCII characters."""
    header = "Basic " + base64.b64encode(b"my%2Bclient:secret%3Awith%3Acolons").decode()
    credentials = ClientService.extract_credentials(
        authorization_header=header, form_client_id=None, form_client_secret=None
    )
    assert credentials.client_id == "my+client"
    assert credentials.client_secret == "secret:with:colons"


def test_basic_auth_wins_over_body_parameters_without_merging() -> None:
    """Trying whichever set validates would let a caller probe two credentials in one request."""
    header = "Basic " + base64.b64encode(b"header-client:header-secret").decode()
    credentials = ClientService.extract_credentials(
        authorization_header=header,
        form_client_id="body-client",
        form_client_secret="body-secret",
    )
    assert credentials.client_id == "header-client"
    assert credentials.client_secret == "header-secret"


def test_body_credentials_are_used_when_no_basic_header_is_present() -> None:
    credentials = ClientService.extract_credentials(
        authorization_header=None,
        form_client_id="body-client",
        form_client_secret="body-secret",
    )
    assert credentials.client_id == "body-client"
    assert not credentials.used_basic_auth


@pytest.mark.parametrize(
    "header",
    ["Basic", "Basic !!!not-base64!!!", "Basic " + base64.b64encode(b"no-colon").decode()],
)
def test_malformed_basic_headers_yield_no_credentials(header: str) -> None:
    credentials = ClientService.extract_credentials(
        authorization_header=header, form_client_id=None, form_client_secret=None
    )
    assert credentials.client_id is None


def test_bearer_authorization_header_is_not_mistaken_for_client_auth() -> None:
    credentials = ClientService.extract_credentials(
        authorization_header="Bearer some-access-token",
        form_client_id="body-client",
        form_client_secret=None,
    )
    assert credentials.client_id == "body-client"
    assert not credentials.used_basic_auth
