"""Cryptographic primitives used by FairVote.

Only vetted libraries are used here — ``cryptography`` for HKDF/AES-GCM/SHA-256 and
``PyNaCl`` (libsodium) for X25519 sealed boxes and Ed25519 signatures. No primitive
is implemented in this repository (docs/01 N12).

Conventions
-----------
* Keys are raw ``bytes``; nothing in this module accepts or returns hex strings, so
  a key cannot be logged by accident as part of a formatted message.
* AEAD blobs are self-describing: ``b"FV1" || nonce(12) || ciphertext || tag(16)``.
  The version byte makes a future key/format migration explicit instead of silent.
* Every ``aad`` argument binds a ciphertext to its context (user id, poll id, ...);
  decrypting with a different ``aad`` fails, which is what turns a database dump
  into ciphertext without a usable link.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import signing
from nacl.exceptions import BadSignatureError, CryptoError as NaClCryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

AEAD_VERSION: Final = b"FV1"
AEAD_NONCE_SIZE: Final = 12
AEAD_TAG_SIZE: Final = 16
X25519_KEY_SIZE: Final = 32
ED25519_SEED_SIZE: Final = 32
HKDF_SALT: Final = b"fairvote/hkdf/v1"


class CryptoError(Exception):
    """Raised when a cryptographic operation fails (bad tag, bad point, ...)."""


def random_bytes(size: int) -> bytes:
    """``size`` cryptographically secure random bytes."""
    if size <= 0:
        raise ValueError("size must be positive")
    return secrets.token_bytes(size)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def blake2b_hex(data: bytes, digest_size: int = 32) -> str:
    return hashlib.blake2b(data, digest_size=digest_size).hexdigest()


def derive_key(master: bytes, label: str, length: int = 32) -> bytes:
    """HKDF-SHA256 sub-key derivation from the master key.

    ``label`` must be a stable ASCII identifier (``"fairvote/totp/v1"``). Using a
    distinct label per purpose means a leak of one sub-key does not compromise the
    others, and changing a purpose's format is a version bump.
    """
    if not isinstance(label, str) or not label.isascii() or not label:
        raise ValueError("label must be a non-empty ASCII string")
    if len(master) < 16:
        raise ValueError("master key is too short")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=HKDF_SALT,
        info=label.encode("ascii"),
    ).derive(master)


def aead_encrypt(key: bytes, plaintext: bytes, *, aad: bytes) -> bytes:
    """AES-256-GCM encrypt with a versioned, self-describing blob."""
    nonce = secrets.token_bytes(AEAD_NONCE_SIZE)
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return AEAD_VERSION + nonce + sealed


def aead_decrypt(key: bytes, blob: bytes, *, aad: bytes) -> bytes:
    """AES-256-GCM decrypt; raises :class:`CryptoError` on any mismatch."""
    if not blob.startswith(AEAD_VERSION):
        raise CryptoError("unknown AEAD format version")
    body = blob[len(AEAD_VERSION) :]
    if len(body) < AEAD_NONCE_SIZE + AEAD_TAG_SIZE:
        raise CryptoError("AEAD blob is truncated")
    nonce, sealed = body[:AEAD_NONCE_SIZE], body[AEAD_NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, sealed, aad)
    except InvalidTag as exc:
        raise CryptoError("AEAD authentication failed") from exc


def x25519_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_key, public_key)`` raw bytes for a new poll key."""
    private = PrivateKey.generate()
    return bytes(private), bytes(private.public_key)


def seal(plaintext: bytes, public_key: bytes) -> bytes:
    """``crypto_box_seal``: anonymous public-key encryption (libsodium)."""
    if len(public_key) != X25519_KEY_SIZE:
        raise ValueError("public key must be 32 bytes")
    return SealedBox(PublicKey(public_key)).encrypt(plaintext)


def x25519_public_from_private(private_key: bytes) -> bytes:
    """Derive the public key from a poll's private key (used to verify commitments)."""
    if len(private_key) != X25519_KEY_SIZE:
        raise ValueError("private key must be 32 bytes")
    return bytes(PrivateKey(private_key).public_key)


def unseal(ciphertext: bytes, private_key: bytes) -> bytes:
    """Open a sealed box; raises :class:`CryptoError` on failure."""
    if len(private_key) != X25519_KEY_SIZE:
        raise ValueError("private key must be 32 bytes")
    try:
        return SealedBox(PrivateKey(private_key)).decrypt(ciphertext)
    except NaClCryptoError as exc:
        raise CryptoError("sealed box cannot be opened") from exc


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Ed25519 signature with a 32-byte seed (the server's checkpoint key)."""
    if len(seed) != ED25519_SEED_SIZE:
        raise ValueError("ed25519 seed must be 32 bytes")
    return signing.SigningKey(seed).sign(message).signature


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        signing.VerifyKey(public_key).verify(message, signature)
    except (BadSignatureError, ValueError):
        return False
    return True


def ed25519_public_key(seed: bytes) -> bytes:
    return bytes(signing.SigningKey(seed).verify_key)


def constant_time_equal(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)
