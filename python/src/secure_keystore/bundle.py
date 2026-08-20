"""Export and import, as one JSON bundle.

The contents are already encrypted, so a bundle is safe to put through a CI
artifact store or an ``scp``, and useless to anyone who intercepts it without the
user key. It is pure JSON - no tar, no shell - so it behaves the same on every
platform.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import _format as fmt
from .errors import ErrorCodes, KeystoreError

__all__ = ["build_bundle", "read_bundle", "write_bundle"]


def build_bundle(store_dir: Path, store_name: str) -> dict[str, Any]:
    """Read every file in a store directory into a bundle."""
    return {
        "format": fmt.BACKUP_FORMAT,
        "version": fmt.BACKUP_VERSION,
        "storeName": store_name,
        "files": {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(store_dir.iterdir())
            if path.is_file()
        },
    }


def read_bundle(backup_path: str | Path) -> dict[str, Any]:
    """Read a bundle off disk and check it is one of ours before any of it is believed.

    The checks are in the order that matters: a file that is not JSON, a JSON
    document that is not a bundle, a bundle from a future version, and a bundle
    with no master.json are four different mistakes and each says so.
    """
    path = Path(backup_path)
    if not path.is_file():
        raise KeystoreError(ErrorCodes.BAD_BACKUP, f"backup file not found: {backup_path}")

    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as cause:
        raise KeystoreError(
            ErrorCodes.BAD_BACKUP,
            f"invalid backup file: {backup_path} is not readable as JSON",
        ) from cause

    if (
        not isinstance(bundle, dict)
        or bundle.get("format") != fmt.BACKUP_FORMAT
        or not isinstance(bundle.get("files"), dict)
    ):
        raise KeystoreError(
            ErrorCodes.BAD_BACKUP, f"invalid backup file: {backup_path} is not a keystore bundle"
        )

    version = bundle.get("version", 0)
    if isinstance(version, int) and version > fmt.BACKUP_VERSION:
        raise KeystoreError(
            ErrorCodes.UNSUPPORTED_FORMAT,
            f"backup was written in bundle format {version}, "
            f"and this build reads up to {fmt.BACKUP_VERSION}",
        )

    if fmt.MASTER_FILE not in bundle["files"]:
        raise KeystoreError(
            ErrorCodes.BAD_BACKUP, f"invalid backup: {fmt.MASTER_FILE} not found in bundle"
        )

    return bundle


def write_bundle(bundle: dict[str, Any], target_dir: Path) -> None:
    """Write a bundle's files into a target directory.

    Every name is reduced to its base name first. A bundle is an untrusted file
    that arrived over a wire, and ``{"files": {"../../.ssh/authorized_keys": ...}}``
    is a bundle someone could write by hand.

    ``PurePath.name`` alone is not enough for a Windows path arriving on Unix or
    the reverse, so both separators are handled explicitly.
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    for name, content in bundle["files"].items():
        safe = _base_name(str(name))
        if safe in ("", ".", ".."):
            continue
        (target_dir / safe).write_text(content, encoding="utf-8")


def _base_name(name: str) -> str:
    """Strip every directory component, whichever separator was used."""
    for index in range(len(name) - 1, -1, -1):
        if name[index] in ("/", "\\"):
            return name[index + 1 :]

    # A drive-relative name like "C:evil.txt" has no separator at all.
    if len(name) > 1 and name[1] == ":":
        return name[2:]

    return name
