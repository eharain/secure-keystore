"""One exception type, with a code.

The code is what the other five implementations agree on: ``BAD_USER_KEY`` means
the same thing in Python, Go, .NET, PHP, Rust and JavaScript, and a script that
greps for it keeps working when the team rewrites the service. The message may be
reworded between releases; the code will not be.

A wrong user key would otherwise surface as ``cryptography.exceptions.InvalidTag``,
which says nothing about which store or why.
"""

from __future__ import annotations

from typing import Final


class ErrorCodes:
    """Every code a :class:`KeystoreError` can carry.

    A class of constants rather than loose strings, so a typo in a caller's
    ``except`` clause is an :class:`AttributeError` rather than a branch that
    silently never runs.
    """

    #: The options given do not make sense.
    INVALID_OPTIONS: Final = "INVALID_OPTIONS"
    #: A required argument was missing or empty.
    INVALID_ARGUMENT: Final = "INVALID_ARGUMENT"
    #: No such store under this keystore directory.
    STORE_NOT_FOUND: Final = "STORE_NOT_FOUND"
    #: The directory exists but is not a store, or its metadata is unreadable.
    STORE_CORRUPT: Final = "STORE_CORRUPT"
    #: No such key - in the named store, or in any of them.
    KEY_NOT_FOUND: Final = "KEY_NOT_FOUND"
    #: Decryption failed: the key is wrong, or the bytes have been altered.
    BAD_USER_KEY: Final = "BAD_USER_KEY"
    #: A value token is not in the form this format defines.
    BAD_TOKEN: Final = "BAD_TOKEN"
    #: The input file is not readable as the format its extension claims.
    BAD_INPUT: Final = "BAD_INPUT"
    #: The bundle is missing, unreadable, or not a keystore bundle.
    BAD_BACKUP: Final = "BAD_BACKUP"
    #: The store or bundle is in a format version newer than this build reads.
    UNSUPPORTED_FORMAT: Final = "UNSUPPORTED_FORMAT"


class KeystoreError(Exception):
    """Raised by every operation that can fail in a way a caller might handle.

    :param code: a stable identifier from :class:`ErrorCodes`
    :param message: what happened, in words meant for a person
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"
