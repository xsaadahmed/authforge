"""SQLAlchemy models.

Imported eagerly here so that ``Base.metadata`` is complete for Alembic autogenerate and
for the integration-test schema bootstrap.
"""

from app.models.audit import AuditEventType, AuditLog
from app.models.base import Base
from app.models.client import (
    ClientRedirectUri,
    ClientScope,
    ClientType,
    OAuthClient,
    Scope,
    TokenEndpointAuthMethod,
)
from app.models.consent import Consent
from app.models.signing_key import KeyStatus, SigningKey
from app.models.token import RefreshToken, RevocationReason
from app.models.user import MfaCredential, RecoveryCode, User

__all__ = [
    "AuditEventType",
    "AuditLog",
    "Base",
    "ClientRedirectUri",
    "ClientScope",
    "ClientType",
    "Consent",
    "KeyStatus",
    "MfaCredential",
    "OAuthClient",
    "RecoveryCode",
    "RefreshToken",
    "RevocationReason",
    "Scope",
    "SigningKey",
    "TokenEndpointAuthMethod",
    "User",
]
