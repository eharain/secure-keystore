"""The store: a directory, and the operations on it.

Two layers of encryption, and it is worth being precise about what the second one
buys. A user key unlocks the master key; the master key unlocks each value. That
is not defence in depth against a leaked user key - anyone holding the user key
reaches everything - it is what lets every value carry its own salt and its own
derived key, so no two values on disk share any material and re-keying one value
touches one file.

The on-disk format is specified in SPEC.md at the root of the repository. This
build writes format 3.0 and reads 3.0 and 2.0. A store is never half one and half
the other: writing to a 2.0 store keeps writing 2.0 records until
:meth:`Keystore.migrate` moves the whole thing across.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import _crypto, _format as fmt
from .bundle import build_bundle, read_bundle, write_bundle
from .errors import ErrorCodes, KeystoreError
from .input_file import parse_input
from .token import decrypt_value, encrypt_value

__all__ = ["Keystore", "StoreInfo", "SecureResult", "SetResult", "MigrateResult"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"
    )


@dataclass(frozen=True, slots=True)
class SecureResult:
    """What :meth:`Keystore.secure` returns."""

    store_name: str
    store_dir: str
    total_keys: int
    keys: list[str]


@dataclass(frozen=True, slots=True)
class SetResult:
    """What :meth:`Keystore.set` returns."""

    key: str
    store_name: str
    #: True if the key was new, False if an existing value was replaced.
    added: bool
    #: The format the record was written in - a 2.0 store keeps taking 2.0 writes.
    store_format: str


@dataclass(frozen=True, slots=True)
class MigrateResult:
    """What :meth:`Keystore.migrate` returns."""

    store_name: str
    #: The format the store was in before.
    from_format: str
    #: The format it is in now.
    to_format: str
    keys: list[str]
    #: The PBKDF2 count it was rewritten with.
    iterations: int


@dataclass(frozen=True, slots=True)
class StoreInfo:
    """Everything about a store that can be known without decrypting anything."""

    name: str
    path: str
    #: The store format, ``"3.0"`` for anything this build writes.
    version: str
    #: False if the store is still on 2.0 and would benefit from a migrate.
    current: bool
    created: str
    updated: str
    #: The PBKDF2 count this store's user key is stretched with.
    iterations: int
    total_keys: int
    keys: list[str]
    source_file: str


@dataclass(slots=True)
class _Metadata:
    """A store's master.json.

    ``raw`` is kept whole so that a field this build does not know about survives
    a rewrite. An older reader that silently downgrades a store written by a
    newer implementation is worse than one that refuses it.
    """

    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def format_version(self) -> str:
        """Absent means 1.0, which is the same on-disk shape as 2.0."""
        return self.raw.get("version") or "1.0"

    @property
    def is_legacy(self) -> bool:
        return fmt.major_of(self.format_version) < 3

    @property
    def iterations(self) -> int:
        """Absent means the record predates the field, and every version that did so used 100,000."""
        value = self.raw.get("iterations")
        return value if isinstance(value, int) else fmt.LEGACY_ITERATIONS

    @property
    def iv_length(self) -> int:
        return fmt.IV_LENGTH_LEGACY if self.is_legacy else fmt.IV_LENGTH

    @property
    def master_aad(self) -> str:
        return "" if self.is_legacy else fmt.CONTEXT_MASTER

    def value_aad(self, key_name: str) -> str:
        return "" if self.is_legacy else fmt.value_context(key_name)

    @property
    def entries(self) -> list[dict[str, str]]:
        found = self.raw.get("entries")
        return found if isinstance(found, list) else []


class Keystore:
    """A secure key-value store backed by a directory.

    One instance binds one keystore directory and one set of options, validated
    once here rather than on every call. It holds no secret of its own - the user
    key is passed to each operation that needs it and is never retained - so one
    instance built at start-up is safe to keep for the life of the process.

    :param keystore_dir: where stores live. Default ``./.keystore``.
    :param iterations: PBKDF2 rounds the *user key* is stretched with, for new
        and migrated stores. Recorded in the store, so raising it never orphans
        one written before. Default 600,000. It does not apply to value keys,
        which are derived with HKDF and take no count.
    :param logger: called with one line of progress. ``None`` means the package
        prints nothing at all, which is the default and what a server wants.
    :param create_dir: create the keystore directory if it is absent.
    """

    def __init__(
        self,
        keystore_dir: str | Path | None = None,
        *,
        iterations: int = fmt.DEFAULT_ITERATIONS,
        logger: Callable[[str], None] | None = None,
        create_dir: bool = True,
    ) -> None:
        if not isinstance(iterations, int) or iterations < fmt.MIN_ITERATIONS:
            raise KeystoreError(
                ErrorCodes.INVALID_OPTIONS,
                f"iterations must be a whole number of at least {fmt.MIN_ITERATIONS}, "
                f"not {iterations}",
            )

        if logger is not None and not callable(logger):
            raise KeystoreError(
                ErrorCodes.INVALID_OPTIONS,
                "logger must be callable with one message, or None to stay silent",
            )

        self.keystore_dir = Path(keystore_dir or Path.cwd() / fmt.DEFAULT_KEYSTORE_DIRNAME)
        self.iterations = iterations
        self.logger = logger

        if create_dir:
            self.keystore_dir.mkdir(parents=True, exist_ok=True)

    # ----- internals -------------------------------------------------------

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger(message)

    def _store_dir(self, store_name: str) -> Path:
        return self.keystore_dir / store_name

    def _read_metadata(self, store_name: str) -> _Metadata:
        """Read and parse a store's master.json, or say which of the two is missing."""
        store_dir = self._store_dir(store_name)
        if not store_dir.is_dir():
            raise KeystoreError(ErrorCodes.STORE_NOT_FOUND, f'keystore "{store_name}" not found')

        master_path = store_dir / fmt.MASTER_FILE
        if not master_path.is_file():
            raise KeystoreError(
                ErrorCodes.STORE_CORRUPT,
                f'keystore "{store_name}" has no {fmt.MASTER_FILE} - '
                "the directory exists but is not a store",
            )

        try:
            raw = json.loads(master_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as cause:
            raise KeystoreError(
                ErrorCodes.STORE_CORRUPT,
                f'{fmt.MASTER_FILE} in keystore "{store_name}" is not readable JSON',
            ) from cause

        if not isinstance(raw, dict):
            raise KeystoreError(
                ErrorCodes.STORE_CORRUPT,
                f'{fmt.MASTER_FILE} in keystore "{store_name}" is not an object',
            )

        metadata = _Metadata(raw=raw)
        if fmt.major_of(metadata.format_version) > fmt.major_of(fmt.STORE_FORMAT_VERSION):
            raise KeystoreError(
                ErrorCodes.UNSUPPORTED_FORMAT,
                f'keystore "{store_name}" is in format {metadata.format_version}, '
                f"and this build reads up to {fmt.STORE_FORMAT_VERSION}",
            )

        return metadata

    def _write_metadata(self, store_name: str, metadata: _Metadata) -> None:
        metadata.raw["updated"] = _now()
        path = self._store_dir(store_name) / fmt.MASTER_FILE
        path.write_text(json.dumps(metadata.raw, indent=2, ensure_ascii=False), encoding="utf-8")

    def _unlock_master(self, metadata: _Metadata, user_key: str, store_name: str) -> str:
        """Stretch the user key and decrypt the store's master key."""
        if not user_key:
            raise KeystoreError(
                ErrorCodes.INVALID_ARGUMENT, "a user_key is required to read this store"
            )

        try:
            salt = bytes.fromhex(metadata.raw.get("salt", ""))
        except ValueError as cause:
            raise KeystoreError(
                ErrorCodes.STORE_CORRUPT, f'keystore "{store_name}" has a malformed salt'
            ) from cause

        user_derived = _crypto.stretch_password(user_key, salt, metadata.iterations)
        master = _crypto.Encrypted.from_json(metadata.raw.get("master"), "master key")

        try:
            return _crypto.decrypt(master, user_derived, metadata.master_aad, "master key")
        except KeystoreError as error:
            if error.code == ErrorCodes.BAD_USER_KEY:
                raise KeystoreError(
                    ErrorCodes.BAD_USER_KEY, f'wrong user key for keystore "{store_name}"'
                ) from error
            raise

    @staticmethod
    def _value_key(
        master_key: str, salt: bytes, key_name: str, metadata: _Metadata, record: dict[str, Any]
    ) -> bytes:
        """The key one value is encrypted under.

        In 3.0 that is HKDF from the master key, with the value's salt and a
        context naming the key - so a value file moved to another key's name
        derives a different key entirely. In 2.0 it was PBKDF2 over the master
        key, at the store's full iteration count, with nothing binding it to the
        name.
        """
        if metadata.is_legacy:
            count = record.get("iterations")
            return _crypto.stretch_password(
                master_key, salt, count if isinstance(count, int) else metadata.iterations
            )
        return _crypto.derive_from_key(master_key, salt, fmt.value_context(key_name))

    def _read_value(
        self, store_name: str, entry: dict[str, str], master_key: str, metadata: _Metadata
    ) -> str:
        value_path = self._store_dir(store_name) / entry["file"]
        if not value_path.is_file():
            raise KeystoreError(
                ErrorCodes.STORE_CORRUPT,
                f'key "{entry["key"]}" is listed in {fmt.MASTER_FILE} '
                f'but its file {entry["file"]} is missing',
            )

        try:
            record = json.loads(value_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as cause:
            raise KeystoreError(
                ErrorCodes.STORE_CORRUPT,
                f'the file for key "{entry["key"]}" is not readable JSON',
            ) from cause

        try:
            salt = bytes.fromhex(record.get("salt", ""))
        except ValueError as cause:
            raise KeystoreError(
                ErrorCodes.STORE_CORRUPT,
                f'the file for key "{entry["key"]}" has a malformed salt',
            ) from cause

        key = self._value_key(master_key, salt, entry["key"], metadata, record)
        return _crypto.decrypt(
            _crypto.Encrypted.from_json(record.get("data"), f'value for "{entry["key"]}"'),
            key,
            metadata.value_aad(entry["key"]),
            f'value for "{entry["key"]}"',
        )

    def _write_value(
        self,
        store_name: str,
        file_name: str,
        key_name: str,
        value: str,
        master_key: str,
        metadata: _Metadata,
    ) -> None:
        salt = _crypto.random_bytes(fmt.VALUE_SALT_LENGTH)

        record: dict[str, Any] = {"salt": salt.hex()}
        # The iteration count only means anything to a 2.0 value, where the value
        # key is stretched from the master key. A 3.0 value derives with HKDF,
        # which takes no count, so writing one would record a number nothing
        # reads.
        if metadata.is_legacy:
            record["iterations"] = metadata.iterations

        key = self._value_key(master_key, salt, key_name, metadata, record)
        record["data"] = _crypto.encrypt(
            value, key, metadata.iv_length, metadata.value_aad(key_name)
        ).to_json()

        path = self._store_dir(store_name) / file_name
        path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    # ----- the store -------------------------------------------------------

    def secure(
        self, input_file: str | Path, user_key: str, store_name: str | None = None
    ) -> SecureResult:
        """Encrypt a key-value file into a store, in format 3.0.

        The input format follows the extension: ``.json`` an object, ``.env``
        dotenv lines, anything else ``key:value`` lines with ``master:`` first.
        The store name defaults to the input file's base name.

        Re-securing an existing store replaces it. The old ``.enc`` files go
        first, so a key dropped from the input does not linger on disk as an
        encrypted orphan that nothing references any more.
        """
        if not user_key:
            raise KeystoreError(ErrorCodes.INVALID_ARGUMENT, "secure requires a user_key")

        parsed = parse_input(input_file)
        if not parsed.master_key:
            raise KeystoreError(
                ErrorCodes.BAD_INPUT,
                'input must define a master key (e.g. "master:..." in .txt, '
                '"master=..." in .env, or a "master" property in .json)',
            )

        if not parsed.entries:
            raise KeystoreError(ErrorCodes.BAD_INPUT, "no key-value entries found in input file")

        store_name = store_name or Path(input_file).stem
        store_dir = self._store_dir(store_name)
        store_dir.mkdir(parents=True, exist_ok=True)

        for path in store_dir.iterdir():
            if path.is_file() and (path.suffix == fmt.VALUE_EXTENSION or path.name == fmt.MASTER_FILE):
                path.unlink()

        store_salt = _crypto.random_bytes(fmt.STORE_SALT_LENGTH)
        user_derived = _crypto.stretch_password(user_key, store_salt, self.iterations)

        metadata = _Metadata(
            raw={
                "version": fmt.STORE_FORMAT_VERSION,
                "created": _now(),
                "salt": store_salt.hex(),
                "iterations": self.iterations,
                "master": _crypto.encrypt(
                    parsed.master_key, user_derived, fmt.IV_LENGTH, fmt.CONTEXT_MASTER
                ).to_json(),
                "entries": [],
                "sourceFile": Path(input_file).name,
                "totalKeys": len(parsed.entries),
            }
        )

        keys: list[str] = []
        for entry in parsed.entries:
            file_name = _crypto.safe_file_name(entry.key)
            self._write_value(
                store_name, file_name, entry.key, entry.value, parsed.master_key, metadata
            )
            metadata.raw["entries"].append({"key": entry.key, "file": file_name})
            keys.append(entry.key)

        self._write_metadata(store_name, metadata)
        self._update_index(store_name, metadata)
        self._log(f'Secured {len(keys)} keys in keystore "{store_name}" at {store_dir}')

        return SecureResult(
            store_name=store_name, store_dir=str(store_dir), total_keys=len(keys), keys=keys
        )

    def get(self, key: str, user_key: str, store_name: str | None = None) -> str:
        """Decrypt and return one value.

        With no store name, every store is searched. That is a convenience for a
        single-store setup and a trap for a multi-store one, where two stores may
        hold the same key name and the first match wins - name the store when it
        matters.
        """
        store_name = store_name or self._find_store_for_key(key)
        metadata = self._read_metadata(store_name)

        entry = next((item for item in metadata.entries if item.get("key") == key), None)
        if entry is None:
            raise KeystoreError(
                ErrorCodes.KEY_NOT_FOUND, f'key "{key}" not found in keystore "{store_name}"'
            )

        master_key = self._unlock_master(metadata, user_key, store_name)
        return self._read_value(store_name, entry, master_key, metadata)

    def get_all(self, user_key: str, store_name: str) -> dict[str, str]:
        """Decrypt every value in a store.

        The user key is stretched once, not once per value, so this costs one
        PBKDF2 derivation however many keys the store holds.
        """
        metadata = self._read_metadata(store_name)
        master_key = self._unlock_master(metadata, user_key, store_name)

        return {
            entry["key"]: self._read_value(store_name, entry, master_key, metadata)
            for entry in metadata.entries
        }

    def set(self, key: str, value: str, user_key: str, store_name: str) -> SetResult:
        """Add a key, or replace the value of one already there.

        The replacement gets a fresh salt and a fresh IV, so an observer who kept
        the old file learns nothing by comparing it with the new one.

        On a store still in format 2.0 this writes a 2.0 record, so the store
        stays internally consistent. Run :meth:`migrate` to move the whole store
        to 3.0.
        """
        if not key:
            raise KeystoreError(ErrorCodes.INVALID_ARGUMENT, "set requires a key")

        metadata = self._read_metadata(store_name)
        master_key = self._unlock_master(metadata, user_key, store_name)

        existing = next((item for item in metadata.entries if item.get("key") == key), None)
        file_name = existing["file"] if existing else _crypto.safe_file_name(key)

        self._write_value(store_name, file_name, key, value, master_key, metadata)

        if existing is None:
            metadata.raw["entries"].append({"key": key, "file": file_name})
            metadata.raw["totalKeys"] = len(metadata.entries)

        self._write_metadata(store_name, metadata)
        self._update_index(store_name, metadata)
        self._log(
            f'Key "{key}" {"updated" if existing else "added"} in keystore "{store_name}"'
        )

        return SetResult(
            key=key,
            store_name=store_name,
            added=existing is None,
            store_format=metadata.format_version,
        )

    def migrate(self, store_name: str, user_key: str) -> MigrateResult:
        """Rewrite a whole store in the current format.

        Every value is decrypted with the old parameters and re-encrypted with
        the new ones, under a fresh store salt and fresh per-value salts. The
        master key itself does not change, so nothing outside the store has to be
        told.

        A store already on the current format is re-encrypted rather than
        skipped, which is what makes this the way to raise a store's iteration
        count as well as its format.

        The rewrite is not atomic. Every value is decrypted before anything is
        written, so a wrong user key changes nothing; and every new value file is
        written before master.json, so an interruption leaves the store readable
        in its old format. Export first anyway.
        """
        metadata = self._read_metadata(store_name)
        from_format = metadata.format_version
        master_key = self._unlock_master(metadata, user_key, store_name)

        # Decrypt everything up front. If any value fails, the store is untouched.
        values = [
            (entry["key"], self._read_value(store_name, entry, master_key, metadata))
            for entry in metadata.entries
        ]

        store_salt = _crypto.random_bytes(fmt.STORE_SALT_LENGTH)
        user_derived = _crypto.stretch_password(user_key, store_salt, self.iterations)

        rewritten = _Metadata(raw=dict(metadata.raw))
        rewritten.raw.update(
            {
                "version": fmt.STORE_FORMAT_VERSION,
                "salt": store_salt.hex(),
                "iterations": self.iterations,
                "master": _crypto.encrypt(
                    master_key, user_derived, fmt.IV_LENGTH, fmt.CONTEXT_MASTER
                ).to_json(),
                "migrated": _now(),
                "entries": [],
                "totalKeys": len(values),
            }
        )

        store_dir = self._store_dir(store_name)
        stale = {path.name for path in store_dir.iterdir() if path.suffix == fmt.VALUE_EXTENSION}

        keys: list[str] = []
        for key_name, value in values:
            file_name = _crypto.safe_file_name(key_name)
            self._write_value(store_name, file_name, key_name, value, master_key, rewritten)
            rewritten.raw["entries"].append({"key": key_name, "file": file_name})
            keys.append(key_name)
            stale.discard(file_name)

        self._write_metadata(store_name, rewritten)
        for name in stale:
            (store_dir / name).unlink(missing_ok=True)

        self._update_index(store_name, rewritten)
        self._log(
            f'Keystore "{store_name}" re-encrypted in format {fmt.STORE_FORMAT_VERSION} '
            f"at {self.iterations} iterations"
            if from_format == fmt.STORE_FORMAT_VERSION
            else f'Keystore "{store_name}" migrated from format {from_format} '
            f"to {fmt.STORE_FORMAT_VERSION}"
        )

        return MigrateResult(
            store_name=store_name,
            from_format=from_format,
            to_format=fmt.STORE_FORMAT_VERSION,
            keys=keys,
            iterations=self.iterations,
        )

    def delete_key(self, key: str, store_name: str) -> None:
        """Remove one key and its encrypted file."""
        metadata = self._read_metadata(store_name)

        entry = next((item for item in metadata.entries if item.get("key") == key), None)
        if entry is None:
            raise KeystoreError(
                ErrorCodes.KEY_NOT_FOUND, f'key "{key}" not found in keystore "{store_name}"'
            )

        metadata.raw["entries"] = [item for item in metadata.entries if item.get("key") != key]
        metadata.raw["totalKeys"] = len(metadata.entries)

        (self._store_dir(store_name) / entry["file"]).unlink(missing_ok=True)

        self._write_metadata(store_name, metadata)
        self._update_index(store_name, metadata)
        self._log(f'Key "{key}" deleted from keystore "{store_name}"')

    def list_stores(self) -> list[str]:
        """The names of every store under this keystore directory.

        A directory counts as a store only if it holds a master.json, so an
        unrelated directory sitting alongside is not reported as one.
        """
        if not self.keystore_dir.is_dir():
            return []

        return sorted(
            path.name
            for path in self.keystore_dir.iterdir()
            if path.is_dir() and (path / fmt.MASTER_FILE).is_file()
        )

    def list_keys(self, store_name: str) -> list[str]:
        """The key names in a store.

        No user key, and none is needed: names live in metadata in the clear.
        That is a deliberate trade - it is what makes listing useful without a
        password - and it means a key name must not itself be a secret.
        """
        return [entry["key"] for entry in self._read_metadata(store_name).entries]

    def get_store_info(self, store_name: str) -> StoreInfo:
        """Everything about a store that can be known without decrypting anything."""
        metadata = self._read_metadata(store_name)
        created = metadata.raw.get("created", "")

        return StoreInfo(
            name=store_name,
            path=str(self._store_dir(store_name)),
            version=metadata.format_version,
            current=not metadata.is_legacy,
            created=created,
            updated=metadata.raw.get("updated") or created,
            iterations=metadata.iterations,
            total_keys=metadata.raw.get("totalKeys", len(metadata.entries)),
            keys=[entry["key"] for entry in metadata.entries],
            source_file=metadata.raw.get("sourceFile", ""),
        )

    def export_store(self, store_name: str, backup_path: str | Path | None = None) -> str:
        """Write a store to a single portable bundle, ``.skb`` by default.

        The contents are already encrypted, so the bundle is safe to move through
        a CI artifact store or an ``scp``.
        """
        self._read_metadata(store_name)  # refuse early if it is not a store

        if backup_path is None:
            stamp = int(datetime.now(timezone.utc).timestamp() * 1000)
            backup_path = Path.cwd() / f"{store_name}-backup-{stamp}{fmt.DEFAULT_BACKUP_EXTENSION}"

        bundle = build_bundle(self._store_dir(store_name), store_name)
        Path(backup_path).write_text(
            json.dumps(bundle, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
        )

        self._log(f'Store "{store_name}" exported to {backup_path}')
        return str(backup_path)

    def import_store(self, backup_path: str | Path, store_name: str | None = None) -> str:
        """Restore a bundle, under its own name or a new one."""
        bundle = read_bundle(backup_path)

        target = store_name or bundle.get("storeName")
        if not target:
            raise KeystoreError(
                ErrorCodes.BAD_BACKUP,
                "cannot determine a target store name: the bundle names none and none was given",
            )

        write_bundle(bundle, self._store_dir(target))
        self._update_index(target, self._read_metadata(target))
        self._log(f'Store imported as "{target}"')

        return target

    def delete_store(self, store_name: str) -> None:
        """Remove a store and its index entry. There is no undo; export first."""
        self._read_metadata(store_name)  # refuse to delete a directory that is not a store

        shutil.rmtree(self._store_dir(store_name))

        index_path = self.keystore_dir / fmt.INDEX_FILE
        if index_path.is_file():
            try:
                catalogue = json.loads(index_path.read_text(encoding="utf-8"))
                catalogue.get("stores", {}).pop(store_name, None)
                catalogue["updated"] = _now()
                index_path.write_text(
                    json.dumps(catalogue, indent=2, ensure_ascii=False), encoding="utf-8"
                )
            except (ValueError, OSError, AttributeError):
                pass  # a corrupt catalogue is not worth failing a delete over

        self._log(f'Keystore "{store_name}" deleted')

    def encrypt_value(self, plaintext: str | None, user_key: str, **kwargs: Any) -> str | None:
        """Instance sugar for :func:`secure_keystore.token.encrypt_value`."""
        return encrypt_value(plaintext, user_key, **kwargs)

    def decrypt_value(self, token: Any, user_key: str) -> Any:
        """Instance sugar for :func:`secure_keystore.token.decrypt_value`."""
        return decrypt_value(token, user_key)

    # ----- catalogue -------------------------------------------------------

    def _update_index(self, store_name: str, metadata: _Metadata) -> None:
        """Rewrite this store's entry in the keystore-wide catalogue.

        The catalogue holds names and counts and no secrets, which is what makes
        it safe to read without a user key - and what makes it merely a
        convenience: every operation reads the store's own master.json for
        anything that matters.
        """
        index_path = self.keystore_dir / fmt.INDEX_FILE

        catalogue: dict[str, Any] = {"stores": {}}
        if index_path.is_file():
            try:
                loaded = json.loads(index_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("stores"), dict):
                    catalogue = loaded
            except (ValueError, OSError):
                # A corrupt catalogue is not worth failing a write over - it
                # holds nothing that is not also in each store's own metadata.
                catalogue = {"stores": {}}

        catalogue["stores"][store_name] = {
            "version": metadata.format_version,
            "created": metadata.raw.get("created"),
            "totalKeys": metadata.raw.get("totalKeys", len(metadata.entries)),
            "keys": [entry["key"] for entry in metadata.entries],
            "sourceFile": metadata.raw.get("sourceFile"),
        }
        catalogue["updated"] = _now()

        index_path.write_text(
            json.dumps(catalogue, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def _find_store_for_key(self, key: str) -> str:
        """The first store holding this key."""
        for store_name in self.list_stores():
            try:
                if key in self.list_keys(store_name):
                    return store_name
            except KeystoreError:
                continue  # a store we cannot read is not a store that holds the key

        raise KeystoreError(ErrorCodes.KEY_NOT_FOUND, f'key "{key}" not found in any keystore')
