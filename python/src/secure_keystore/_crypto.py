"""The cryptographic primitives, and nothing else.

Every AES call in this package goes through this module, so there is exactly one
place where an algorithm, an IV length or an encoding is chosen.

Two derivations, for two different jobs, which format 2.0 conflated:

``stretch_password``
    A *password* into a key. Deliberately slow. Used once per store, on the user
    key, and on every value token.

``derive_from_key``
    A key into another key. Fast, because the input is already high-entropy key
    material and stretching it buys nothing.

Running 600,000 PBKDF2 rounds on the master key once per value - which 2.0 did -
costs seconds on a store of any size and adds no security the master key did not
already have. That is the misuse HKDF exists to correct.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import _format as fmt
from .errors import ErrorCodes, KeystoreError


@dataclass(slots=True)
class Encrypted:
    """One AES-GCM result, as it appears in a store file. Every field is hex."""

    iv: str
    auth_tag: str
    data: str

    def to_json(self) -> dict[str, str]:
        return {"iv": self.iv, "authTag": self.auth_tag, "data": self.data}

    @staticmethod
    def from_json(raw: Any, what: str = "value") -> "Encrypted":
        if not isinstance(raw, dict):
            raise KeystoreError(
                ErrorCodes.STORE_CORRUPT, f"the encrypted {what} is not an object"
            )

        iv, auth_tag, data = raw.get("iv"), raw.get("authTag"), raw.get("data")
        if not isinstance(iv, str) or not isinstance(auth_tag, str) or not isinstance(data, str):
            raise KeystoreError(
                ErrorCodes.STORE_CORRUPT,
                f"the encrypted {what} is missing its iv, authTag or data",
            )

        return Encrypted(iv=iv, auth_tag=auth_tag, data=data)


def random_bytes(length: int) -> bytes:
    """Random bytes from the system source."""
    return os.urandom(length)


def stretch_password(password: str, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA256: a password, stretched.

    The count is a parameter rather than a constant because it is recorded
    alongside whatever it derives. Deriving with a count that does not match the
    one a record was written with produces a different key, and the GCM tag then
    rejects it - which is the failure you want rather than the one where it
    nearly works.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=fmt.KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_from_key(key: str, salt: bytes, info: str) -> bytes:
    """HKDF-SHA256: one key into another, bound to a context.

    The input is the master key, which is already a strong secret, so there is
    nothing to stretch - the job is separation, not hardening. ``info`` carries
    the context that separates them, and for a value that context contains the
    key name, which is half of what stops two value files being swapped. The
    other half is the same string passed as GCM additional data.
    """
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=fmt.KEY_LENGTH,
        salt=salt,
        info=info.encode("utf-8"),
    )
    return kdf.derive(key.encode("utf-8"))


def encrypt(plaintext: str, key: bytes, iv_length: int = fmt.IV_LENGTH, aad: str = "") -> Encrypted:
    """Seal a plaintext under a fresh random IV.

    The same plaintext under the same key never produces the same bytes twice.
    ``aad`` is empty for a format 2.0 record, which bound nothing.
    """
    iv = random_bytes(iv_length)
    associated = aad.encode("utf-8") if aad else None

    # AESGCM.encrypt returns ciphertext with the tag appended; the format stores
    # them as separate hex fields.
    sealed = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), associated)
    split = len(sealed) - fmt.AUTH_TAG_LENGTH

    return Encrypted(
        iv=iv.hex(),
        auth_tag=sealed[split:].hex(),
        data=sealed[:split].hex(),
    )


def decrypt(record: Encrypted, key: bytes, aad: str = "", what: str = "value") -> str:
    """Reverse :func:`encrypt`, and translate the failure.

    GCM cannot tell a wrong key from tampered bytes from mismatched additional
    data - all three are a tag that does not verify - and ``cryptography``
    reports any of them as :class:`InvalidTag`, which tells a caller nothing.
    All three become ``BAD_USER_KEY`` here.
    """
    try:
        iv = bytes.fromhex(record.iv)
        tag = bytes.fromhex(record.auth_tag)
        data = bytes.fromhex(record.data)
    except ValueError as cause:
        raise KeystoreError(
            ErrorCodes.STORE_CORRUPT, f"the encrypted {what} has a malformed hex field"
        ) from cause

    if not iv:
        raise KeystoreError(ErrorCodes.STORE_CORRUPT, f"the encrypted {what} has an empty iv")

    associated = aad.encode("utf-8") if aad else None

    try:
        plaintext = AESGCM(key).decrypt(iv, data + tag, associated)
    except (InvalidTag, ValueError) as cause:
        raise KeystoreError(
            ErrorCodes.BAD_USER_KEY,
            f"could not decrypt the {what}: the key is wrong, "
            "or the stored bytes have been altered",
        ) from cause

    return plaintext.decode("utf-8")


def safe_file_name(key: str) -> str:
    """A filesystem-safe, collision-resistant filename for a key.

    The stem is for humans, so it is the key with anything unsafe replaced -
    which neutralises ``../``, drive letters and the characters Windows refuses.
    Sanitising alone would map ``a/b`` and ``a_b`` onto one file, so the real
    identity is the hash suffix; the stem is only a label.

    The stem is built from UTF-8 *bytes* and truncated by bytes, matching every
    other implementation. A multi-byte character straddling the limit is cut, but
    the name is a label and the hash is the identity, so a mangled label costs
    nothing.
    """
    raw = key.encode("utf-8")
    allowed = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")

    stem = bytes(byte if byte in allowed else ord("_") for byte in raw[: fmt.FILENAME_STEM_LIMIT])
    digest = hashlib.sha256(raw).hexdigest()[: fmt.FILENAME_HASH_LENGTH]

    return f"{stem.decode('ascii')}-{digest}{fmt.VALUE_EXTENSION}"
