"""Generate signed RS256 JWT tokens for Omnetic DMS Service Account authentication."""

from __future__ import annotations

import time

import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

__all__ = ["generate_token"]

_ALGORITHM = "RS256"
_TOKEN_TYPE = "sa"
_MAX_LIFETIME = 3600
_MIN_KEY_BITS = 2048


def generate_token(private_key: str, kid: str, lifetime: int = _MAX_LIFETIME) -> str:
    """Build a signed RS256 JWT for authenticating a Service Account against the DMS API.

    :param private_key: RSA private key in PEM format (PKCS1 or PKCS8).
    :param kid: Key ID; carried in both the JWT header and the ``sub`` claim.
    :param lifetime: Token validity in seconds (1-3600). Defaults to 3600.
    :returns: Signed JWT ready for the ``Authorization: Bearer`` header.
    :raises ValueError: If ``kid`` is empty, ``lifetime`` is outside 1-3600, or the private
        key is empty / not valid PEM / not RSA / shorter than 2048 bits.
    """
    if kid == "":
        raise ValueError("The kid must not be empty.")

    if lifetime < 1 or lifetime > _MAX_LIFETIME:
        raise ValueError(
            f"The lifetime must be between 1 and {_MAX_LIFETIME} seconds, got {lifetime}."
        )

    key = _parse_rsa_private_key(private_key)

    issued_at = int(time.time())
    payload: dict[str, object] = {
        "type": _TOKEN_TYPE,
        "sub": kid,
        "iat": issued_at,
        "exp": issued_at + lifetime,
    }

    return jwt.encode(payload, key, algorithm=_ALGORITHM, headers={"kid": kid})


def _parse_rsa_private_key(private_key: str) -> RSAPrivateKey:
    if private_key == "":
        raise ValueError("The private key must not be empty.")

    try:
        key = load_pem_private_key(private_key.encode(), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as error:
        raise ValueError("The private key is not a valid PEM-encoded key.") from error

    if not isinstance(key, RSAPrivateKey):
        raise ValueError("The private key must be an RSA key.")

    if key.key_size < _MIN_KEY_BITS:
        raise ValueError(f"The RSA private key must be at least {_MIN_KEY_BITS} bits.")

    return key
