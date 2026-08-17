"""Helpers shared by the Redis-backed stores."""

from __future__ import annotations


def as_text(value: str | bytes) -> str:
    """Normalise a Redis reply to ``str``.

    The client is configured with ``decode_responses=True``, so replies arrive as ``str`` at
    runtime; redis-py's annotations keep ``bytes`` in the union for clients configured the other
    way. This makes the coercion explicit instead of scattering casts through the stores.
    """
    return value.decode("utf-8") if isinstance(value, bytes) else value
