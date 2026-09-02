"""Small shared helpers for inspecting public keys."""

from hashlib import sha256

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    dh,
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)


class UnsupportedPublicKeyError(ValueError):
    """Raised when a public-key type is not supported for inspection."""


def public_key_algorithm_and_size(public_key: object) -> tuple[str, int | None]:
    """Return a stable algorithm name and key size, where meaningful."""

    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", None
    if isinstance(public_key, x25519.X25519PublicKey):
        return "X25519", None
    if isinstance(public_key, x448.X448PublicKey):
        return "X448", None
    if isinstance(public_key, dh.DHPublicKey):
        return "DH", public_key.key_size
    raise UnsupportedPublicKeyError("unsupported public-key algorithm")


def subject_public_key_info_der(public_key: object) -> bytes:
    """Serialize a public key as DER SubjectPublicKeyInfo."""

    public_bytes = getattr(public_key, "public_bytes", None)
    if public_bytes is None:
        raise UnsupportedPublicKeyError("unsupported public-key algorithm")
    return public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def spki_sha256(public_key: object) -> str:
    """Return lowercase SHA-256 hex over DER SubjectPublicKeyInfo."""

    return sha256(subject_public_key_info_der(public_key)).hexdigest()
