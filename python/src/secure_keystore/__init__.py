"""secure-keystore: encrypted secrets at rest, with no service to run.

Two ways in, for different things:

1. **A store.** A directory of encrypted values that one user key opens. The
   store owns a master key, one salt per value, and a catalogue - so an
   application deploys a directory and reads secrets out of it at run time. That
   is :class:`Keystore`.
2. **A token.** One string in, one string out, nothing on disk. The application
   already has somewhere to put it - a database column, a config row - and only
   wants the value unreadable while it sits there. That is :func:`encrypt_value`
   and :func:`decrypt_value`.

Both use the same primitives: AES-256-GCM to encrypt, PBKDF2-HMAC-SHA256 to
stretch the user key, HKDF-SHA256 to derive a value key from the master key. A
fresh random salt and IV every time.

.. code-block:: python

    from secure_keystore import Keystore

    store = Keystore()
    store.secure("./keys.env", os.environ["USER_KEY"], "production")
    api_key = store.get("api_key", os.environ["USER_KEY"], "production")

**Which KDF, and why two.** A user key is a password, so it is stretched:
deliberately slow, 600,000 rounds by default. A master key is not a password - it
is already a strong secret - so value keys come from HKDF, which is fast.
Stretching the master key once per value, which format 2.0 did, costs seconds on
a store of any size and buys nothing.

The on-disk format is specified in SPEC.md at the root of the repository, and
this implementation reads and writes the same bytes as the JavaScript, Go, .NET,
PHP and Rust ones - which is not a claim but a test, in ``tests/test_conformance.py``.
"""

from __future__ import annotations

from ._format import (
    BACKUP_VERSION,
    DEFAULT_ITERATIONS,
    STORE_FORMAT_LEGACY,
    STORE_FORMAT_VERSION,
    VALUE_TOKEN_PREFIX,
)
from .errors import ErrorCodes, KeystoreError
from .input_file import Entry, InputFormat, ParsedInput, format_for, parse_input, parse_text
from .keystore import Keystore, MigrateResult, SecureResult, SetResult, StoreInfo
from .token import decrypt_value, encrypt_value, is_encrypted_value, token_version

#: The version of this implementation, which is not the same thing as the
#: version of the store format (:data:`STORE_FORMAT_VERSION`).
__version__ = "3.0.1"

#: What this build actually does, in one mapping, so that a caller who has to
#: write it down in a compliance document does not have to read the source.
ALGORITHMS = {
    "cipher": "aes-256-gcm",
    "ivBytes": 12,
    # How the user key - a password - is stretched. Deliberately slow.
    "passwordKdf": "pbkdf2-hmac-sha256",
    "defaultIterations": DEFAULT_ITERATIONS,
    # How a value key comes from the master key. Fast, and correctly so.
    "keyKdf": "hkdf-sha256",
    "digest": "sha256",
    "keyBits": 256,
    # Whether a value is cryptographically bound to its key name.
    "bindsKeyName": True,
}

__all__ = [
    "Keystore",
    "KeystoreError",
    "ErrorCodes",
    "StoreInfo",
    "SecureResult",
    "SetResult",
    "MigrateResult",
    "encrypt_value",
    "decrypt_value",
    "is_encrypted_value",
    "token_version",
    "InputFormat",
    "Entry",
    "ParsedInput",
    "format_for",
    "parse_input",
    "parse_text",
    "ALGORITHMS",
    "STORE_FORMAT_VERSION",
    "STORE_FORMAT_LEGACY",
    "BACKUP_VERSION",
    "VALUE_TOKEN_PREFIX",
    "DEFAULT_ITERATIONS",
    "__version__",
]
