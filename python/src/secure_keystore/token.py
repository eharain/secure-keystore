"""Encryption with no store behind it.

:class:`~secure_keystore.keystore.Keystore` owns a directory. These functions own
nothing: they take a secret and a user key and give back a string, which the
caller puts wherever it already keeps things - a database column, a config row, a
queue message. There is no master key and no file, so there is also no keystore
to deploy alongside the application.

The token is self-describing, and says so in its first field::

    skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>     written and read
    skv1:<salt>:<iv>:<authTag>:<ciphertext>                  read only

What skv1 lacked was a field for its iteration count, which is why its count is
frozen at 100,000 forever and skv2's is not.
"""

from __future__ import annotations

from typing import Any

from . import _crypto, _format as fmt
from .errors import ErrorCodes, KeystoreError

__all__ = ["encrypt_value", "decrypt_value", "is_encrypted_value", "token_version"]


def is_encrypted_value(value: Any) -> bool:
    """True if the value is a token this format defines, of either version."""
    return isinstance(value, str) and (
        value.startswith(fmt.VALUE_TOKEN_PREFIX + ":")
        or value.startswith(fmt.VALUE_TOKEN_PREFIX_LEGACY + ":")
    )


def token_version(value: Any) -> str | None:
    """``"skv2"``, ``"skv1"``, or ``None`` if the value is not a token."""
    if not is_encrypted_value(value):
        return None
    return value[: value.index(":")]


def encrypt_value(plaintext: str | None, user_key: str, *, iterations: int | None = None) -> str | None:
    """Encrypt one string under a user key, with nothing on disk.

    A fresh random salt stretches the key and a fresh random IV feeds
    AES-256-GCM, so encrypting the same secret twice gives two different tokens -
    which is what stops a database column from revealing which rows share a
    value.

    ``None`` and the empty string are returned unchanged, so this can be mapped
    over a record without first sorting the empty fields out of it.

    Unlike a store, there is no master key here: every token is stretched
    straight from the user key, so the cost of the default 600,000 rounds is paid
    on every single value. Encrypting a whole column is the case where that
    matters, and ``iterations`` is there for it - the count is recorded in the
    token, so decryption follows whatever was chosen.
    """
    if plaintext is None or plaintext == "":
        return plaintext

    if not user_key:
        raise KeystoreError(ErrorCodes.INVALID_ARGUMENT, "encrypt_value requires a user_key")

    count = fmt.DEFAULT_ITERATIONS if iterations is None else iterations
    if not isinstance(count, int) or count < fmt.MIN_ITERATIONS:
        raise KeystoreError(
            ErrorCodes.INVALID_ARGUMENT,
            f"iterations must be a whole number of at least {fmt.MIN_ITERATIONS}, not {count}",
        )

    salt = _crypto.random_bytes(fmt.TOKEN_SALT_LENGTH)
    key = _crypto.stretch_password(user_key, salt, count)
    record = _crypto.encrypt(plaintext, key, fmt.IV_LENGTH, fmt.CONTEXT_TOKEN)

    return ":".join(
        [fmt.VALUE_TOKEN_PREFIX, str(count), salt.hex(), record.iv, record.auth_tag, record.data]
    )


def decrypt_value(token: Any, user_key: str) -> Any:
    """Reverse :func:`encrypt_value`, for either token version.

    Anything that is not a token is returned unchanged, so a column part way
    through being encrypted can be read with one call rather than a conditional
    at every site. A token that is malformed, altered, or written under a
    different user key raises - that case is never silently passed through,
    because doing so would hand the caller ciphertext it believed was plaintext.
    """
    if not is_encrypted_value(token):
        return token

    if not user_key:
        raise KeystoreError(ErrorCodes.INVALID_ARGUMENT, "decrypt_value requires a user_key")

    parts = token.split(":")
    legacy = parts[0] == fmt.VALUE_TOKEN_PREFIX_LEGACY
    expected = fmt.VALUE_TOKEN_PARTS_LEGACY if legacy else fmt.VALUE_TOKEN_PARTS

    if len(parts) != expected:
        raise KeystoreError(
            ErrorCodes.BAD_TOKEN,
            f"not a {parts[0]} token: expected {expected} colon-separated fields, "
            f"found {len(parts)}",
        )

    if legacy:
        # skv1 has no iteration field, and every one ever written used 100,000.
        # It also predates additional authenticated data and the 12-byte IV;
        # both are read as they were written.
        iterations = fmt.TOKEN_ITERATIONS_LEGACY
        salt_hex, iv, auth_tag, data = parts[1], parts[2], parts[3], parts[4]
        aad = ""
    else:
        raw_count = parts[1]
        if not raw_count.isdigit() or int(raw_count) < 1:
            raise KeystoreError(
                ErrorCodes.BAD_TOKEN,
                f"token iteration count is not a positive whole number: {raw_count!r}",
            )
        iterations = int(raw_count)
        salt_hex, iv, auth_tag, data = parts[2], parts[3], parts[4], parts[5]
        aad = fmt.CONTEXT_TOKEN

    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError as cause:
        raise KeystoreError(ErrorCodes.BAD_TOKEN, "token salt is not hex") from cause

    key = _crypto.stretch_password(user_key, salt, iterations)
    return _crypto.decrypt(
        _crypto.Encrypted(iv=iv, auth_tag=auth_tag, data=data), key, aad, "value"
    )
