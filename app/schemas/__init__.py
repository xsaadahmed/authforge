"""Pydantic request/response schemas for the non-OAuth surfaces.

The OAuth and OIDC endpoints deliberately use form parameters and hand-built dictionaries,
because their wire formats are fixed by RFC 6749/OIDC Core and must be byte-compatible with
clients rather than idiomatic for FastAPI. The admin and account APIs are ours to define, so they
get proper schemas and appear correctly in the generated OpenAPI document.
"""

from app.schemas.account import (
    MfaConfirmRequest,
    MfaEnrolmentResponse,
    RecoveryCodesResponse,
)
from app.schemas.admin import (
    ClientResponse,
    CreateClientRequest,
    CreateClientResponse,
    CreateUserRequest,
    RotateSecretResponse,
    ScopeResponse,
    SigningKeyResponse,
    UserResponse,
)

__all__ = [
    "ClientResponse",
    "CreateClientRequest",
    "CreateClientResponse",
    "CreateUserRequest",
    "MfaConfirmRequest",
    "MfaEnrolmentResponse",
    "RecoveryCodesResponse",
    "RotateSecretResponse",
    "ScopeResponse",
    "SigningKeyResponse",
    "UserResponse",
]
