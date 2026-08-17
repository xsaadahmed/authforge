"""Security primitives.

Everything in this package wraps a vetted cryptographic library. The orchestration
decisions (*when* to sign, *what* to compare, *how long* something lives) belong to the
domain services; the mathematics belongs to `cryptography`, `argon2-cffi` and `pyotp`.
"""
