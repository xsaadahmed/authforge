"""Where private signing keys actually live.

The database never holds private key material (§11), so something has to. This module
defines the one interface the rest of the app knows about and two implementations: a
gitignored local directory for development, and AWS Secrets Manager for deployed
environments. Swapping in KMS or Vault later means adding a third class here and changing
one setting.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from pathlib import Path

from app.config import Settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class PrivateKeyNotFoundError(RuntimeError):
    """The metadata row points at private material that is not there.

    Almost always a deployment-wiring mistake: a database restored from one environment
    against another environment's secret store.
    """


class PrivateKeyProvider(ABC):
    """Stores and retrieves PEM-encoded private keys by reference."""

    @abstractmethod
    async def store(self, *, kid: str, private_pem: str) -> str:
        """Persist the key and return the reference recorded in `signing_keys`."""

    @abstractmethod
    async def load(self, ref: str) -> str:
        """Retrieve PEM material by reference."""

    @abstractmethod
    async def delete(self, ref: str) -> None:
        """Destroy material for a fully retired key."""


class LocalDirectoryKeyProvider(PrivateKeyProvider):
    """Development-only: ``<local_key_directory>/<kid>.pem``, mode 0600.

    Refuses to be used in staging/prod — enforced both here and in `Settings`, because a
    private key on a container filesystem is a private key in an image layer or a volume
    snapshot away from disclosure.
    """

    def __init__(self, settings: Settings) -> None:
        if settings.is_deployed:
            raise RuntimeError("LocalDirectoryKeyProvider must not be used outside development")
        self._directory = Path(settings.local_key_directory)

    async def store(self, *, kid: str, private_pem: str) -> str:
        def _write() -> str:
            self._directory.mkdir(parents=True, exist_ok=True)
            path = self._directory / f"{kid}.pem"
            path.write_text(private_pem, encoding="ascii")
            path.chmod(0o600)
            return path.name

        return await asyncio.to_thread(_write)

    async def load(self, ref: str) -> str:
        def _read() -> str:
            path = self._directory / Path(ref).name
            if not path.is_file():
                raise PrivateKeyNotFoundError(f"no local private key at {path}")
            return path.read_text(encoding="ascii")

        return await asyncio.to_thread(_read)

    async def delete(self, ref: str) -> None:
        def _unlink() -> None:
            (self._directory / Path(ref).name).unlink(missing_ok=True)

        await asyncio.to_thread(_unlink)


class AwsSecretsManagerKeyProvider(PrivateKeyProvider):
    """Stores each private key as its own Secrets Manager secret.

    One secret per key (rather than one secret holding a JSON map of all keys) so that
    rotation is an independent create, retirement is an independent delete, and an IAM policy
    can grant access by name prefix without also granting the ability to overwrite live keys.

    boto3 is synchronous, so every call is pushed to a worker thread to keep the event loop
    responsive. Calls are rare: the KeyManagementService caches loaded keys in memory.
    """

    def __init__(self, settings: Settings) -> None:
        self._prefix = settings.aws_secret_name_prefix.rstrip("/")
        self._region = settings.aws_region
        self._client: object | None = None

    def _get_client(self) -> object:
        if self._client is None:
            import boto3  # imported lazily so local development needs no AWS SDK config

            self._client = boto3.client("secretsmanager", region_name=self._region)
        return self._client

    async def store(self, *, kid: str, private_pem: str) -> str:
        name = f"{self._prefix}/{kid}"

        def _create() -> str:
            client = self._get_client()
            client.create_secret(  # type: ignore[attr-defined]
                Name=name,
                SecretString=private_pem,
                Description=f"AuthForge RS256 signing key {kid}",
                Tags=[
                    {"Key": "app", "Value": "authforge"},
                    {"Key": "kid", "Value": kid},
                ],
            )
            return name

        return await asyncio.to_thread(_create)

    async def load(self, ref: str) -> str:
        def _get() -> str:
            client = self._get_client()
            try:
                response = client.get_secret_value(SecretId=ref)  # type: ignore[attr-defined]
            except Exception as exc:  # botocore raises dynamically-built exception classes
                raise PrivateKeyNotFoundError(f"could not read signing key {ref}") from exc
            secret = response.get("SecretString")
            if not secret:
                raise PrivateKeyNotFoundError(f"signing key {ref} has no string value")
            return str(secret)

        return await asyncio.to_thread(_get)

    async def delete(self, ref: str) -> None:
        def _delete() -> None:
            client = self._get_client()
            # A recovery window rather than ForceDeleteWithoutRecovery: if a key is deleted
            # while a token signed by it is still in flight, we want a way back.
            client.delete_secret(SecretId=ref, RecoveryWindowInDays=7)  # type: ignore[attr-defined]

        await asyncio.to_thread(_delete)


def build_key_provider(settings: Settings) -> PrivateKeyProvider:
    if settings.signing_key_provider == "aws_secrets_manager":
        return AwsSecretsManagerKeyProvider(settings)
    return LocalDirectoryKeyProvider(settings)
