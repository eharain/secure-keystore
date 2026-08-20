"""Wire-format constants for the secure-keystore format.

Nothing here is a tuning knob. These are the values that define what a store
written by this package looks like, and changing one changes what the other five
implementations can read - which is why they live in one module rather than
scattered through the code that happens to use them.

Two format versions appear throughout. 3.0 is what this build writes; 2.0 is
what earlier releases wrote and what this build still reads. Everywhere the two
differ, the legacy value is named ``*_LEGACY`` and the difference is a parameter
rather than a separate code path.
"""

from __future__ import annotations

#: The store format stamped into every master.json this build writes.
STORE_FORMAT_VERSION = "3.0"

#: The older format this build still reads and, on a store already written that
#: way, still writes.
STORE_FORMAT_LEGACY = "2.0"

#: Identifies an export bundle, checked before anything is written to disk.
BACKUP_FORMAT = "secure-keystore-backup"

#: The bundle format this build writes and the highest it reads.
BACKUP_VERSION = 1

# Value token layouts. skv2 records its own iteration count, which is the one
# thing skv1 got wrong: a token that cannot say how it was derived is a token
# whose parameters can never change.
#
#   skv1:<salt>:<iv>:<authTag>:<ciphertext>
#   skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>
VALUE_TOKEN_PREFIX = "skv2"
VALUE_TOKEN_PARTS = 6
VALUE_TOKEN_PREFIX_LEGACY = "skv1"
VALUE_TOKEN_PARTS_LEGACY = 5

#: AES-256: a 32-byte key.
KEY_LENGTH = 32

#: 12 bytes, which is what NIST SP 800-38D recommends for GCM and the only
#: length several platforms accept at all - .NET's AesGcm refuses anything else.
IV_LENGTH = 12

#: The 16 bytes format 2.0 wrote.
IV_LENGTH_LEGACY = 16

#: The GCM tag length, and the only one this format uses.
AUTH_TAG_LENGTH = 16

#: What a new store stretches the user key with, following OWASP's 2023 guidance
#: for PBKDF2-HMAC-SHA256.
DEFAULT_ITERATIONS = 600_000

#: The floor below which the option is refused. Test suites run at this.
MIN_ITERATIONS = 10_000

#: Assumed for any 2.0 record written before the count was recorded.
LEGACY_ITERATIONS = 100_000

#: Fixed by the skv1 layout, which has no field to record a count in.
TOKEN_ITERATIONS_LEGACY = 100_000

STORE_SALT_LENGTH = 32
VALUE_SALT_LENGTH = 32

#: 16, because the token carries its salt inline, in hex, in every stored value.
TOKEN_SALT_LENGTH = 16

# Domain-separation contexts, used as GCM additional authenticated data and, for
# a value, as the HKDF info as well.
#
# This is what closes the gap 2.0 had: there, the tag covered the ciphertext and
# nothing else, so anyone who could write to a store could swap two value files
# and both would decrypt - under each other's names.
CONTEXT_MASTER = "secure-keystore:v3:master"
CONTEXT_VALUE_PREFIX = "secure-keystore:v3:value:"
CONTEXT_TOKEN = "secure-keystore:v3:token"


def value_context(key_name: str) -> str:
    """The full context string binding a value to its key name."""
    return CONTEXT_VALUE_PREFIX + key_name


#: Catalogue of stores: names and key names, no secrets.
INDEX_FILE = "index.json"

#: Per-store metadata and the encrypted master key.
MASTER_FILE = "master.json"

#: One authenticated-encrypted file per value.
VALUE_EXTENSION = ".enc"

#: Created under the working directory when no keystore directory is given.
DEFAULT_KEYSTORE_DIRNAME = ".keystore"

#: What ``export_store`` writes when given no path.
DEFAULT_BACKUP_EXTENSION = ".skb"

#: The name an input file uses for the master key, in every input format.
MASTER_ENTRY_KEY = "master"

# Value filenames are a readable stem plus a hash of the key. The stem may
# collide between two different keys; the hash is what keeps their files apart.
FILENAME_STEM_LIMIT = 64
FILENAME_HASH_LENGTH = 8


def major_of(version: str) -> int:
    """The major part of a version string, or 0 if it is not a number."""
    head = version.split(".", 1)[0]
    try:
        return int(head)
    except ValueError:
        return 0
