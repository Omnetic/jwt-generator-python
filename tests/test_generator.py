"""Tests for omnetic_jwt_generator.generate_token — mirrors the PHP reference suite."""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from omnetic_jwt_generator import generate_token

KID = "kid-uuid-1"


def _rsa_private_key_pem(bits: int = 2048) -> tuple[str, str]:
    """Return a freshly generated (private PEM, public PEM) RSA key pair."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


def _ec_private_key_pem() -> str:
    """Return a non-RSA (EC / prime256v1) private key PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def test_returns_compact_jwt_with_three_segments() -> None:
    private_pem, _ = _rsa_private_key_pem()

    token = generate_token(private_pem, KID)

    assert len(token.split(".")) == 3


def test_header_uses_rs256_and_carries_the_kid() -> None:
    private_pem, _ = _rsa_private_key_pem()

    token = generate_token(private_pem, KID)
    header = jwt.get_unverified_header(token)

    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"
    assert header["kid"] == KID


def test_payload_carries_service_account_claims() -> None:
    private_pem, _ = _rsa_private_key_pem()

    before = int(time.time())
    token = generate_token(private_pem, KID, 1800)
    after = int(time.time())
    payload = jwt.decode(token, options={"verify_signature": False})

    assert payload["type"] == "sa"
    assert payload["sub"] == KID
    assert "typ" not in payload
    assert before <= payload["iat"] <= after
    assert payload["exp"] == payload["iat"] + 1800


def test_default_lifetime_is_one_hour() -> None:
    private_pem, _ = _rsa_private_key_pem()

    token = generate_token(private_pem, KID)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert payload["exp"] - payload["iat"] == 3600


def test_signature_verifies_with_matching_public_key() -> None:
    private_pem, public_pem = _rsa_private_key_pem()

    token = generate_token(private_pem, KID)
    decoded = jwt.decode(token, public_pem, algorithms=["RS256"])

    assert decoded["type"] == "sa"


def test_signature_is_rejected_by_a_different_public_key() -> None:
    signing_private, _ = _rsa_private_key_pem()
    _, other_public = _rsa_private_key_pem()

    token = generate_token(signing_private, KID)

    with pytest.raises(jwt.exceptions.InvalidSignatureError):
        jwt.decode(token, other_public, algorithms=["RS256"])


def test_rejects_empty_private_key() -> None:
    with pytest.raises(ValueError):
        generate_token("", KID)


def test_rejects_malformed_private_key() -> None:
    with pytest.raises(ValueError):
        generate_token("not a pem key", KID)


def test_rejects_non_rsa_private_key() -> None:
    with pytest.raises(ValueError):
        generate_token(_ec_private_key_pem(), KID)


def test_rejects_rsa_key_shorter_than_2048_bits() -> None:
    private_pem, _ = _rsa_private_key_pem(1024)

    with pytest.raises(ValueError, match="at least 2048 bits"):
        generate_token(private_pem, KID)


def test_validates_kid_before_parsing_the_private_key() -> None:
    with pytest.raises(ValueError, match="The kid must not be empty."):
        generate_token("not a pem key", "")


def test_validates_lifetime_before_parsing_the_private_key() -> None:
    with pytest.raises(
        ValueError, match="The lifetime must be between 1 and 3600 seconds, got 3601."
    ):
        generate_token("not a pem key", KID, 3601)


def test_rejects_empty_kid() -> None:
    private_pem, _ = _rsa_private_key_pem()

    with pytest.raises(ValueError):
        generate_token(private_pem, "")


def test_rejects_lifetime_above_maximum() -> None:
    private_pem, _ = _rsa_private_key_pem()

    with pytest.raises(ValueError):
        generate_token(private_pem, KID, 3601)


def test_rejects_non_positive_lifetime() -> None:
    private_pem, _ = _rsa_private_key_pem()

    with pytest.raises(ValueError):
        generate_token(private_pem, KID, 0)
