"""The command line.

    python -m secure_keystore --help
    secure-keystore --help

Every line this package prints is printed here. The library takes a logger and is
otherwise silent, which is what lets it drop into a server that has opinions
about its own logging.

The verbs, the error codes and the ``--json`` output match every other
implementation, so a shell script should not be able to tell which one it is
calling.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__, _format as fmt
from .errors import KeystoreError
from .keystore import Keystore
from .token import decrypt_value, encrypt_value

NAME = "secure-keystore"

HELP = f"""
{NAME} {__version__} - encrypted secrets at rest, with no service to run

Usage:
  {NAME} secure <input-file> <user-key> [store-name]
  {NAME} get <key> <user-key> [store-name]
  {NAME} all <store-name> <user-key>
  {NAME} set <key> <value> <user-key> <store-name>
  {NAME} migrate <store-name> <user-key>
  {NAME} list <store-name>
  {NAME} stores
  {NAME} info <store-name>
  {NAME} delete <key> <store-name>
  {NAME} delete-store <store-name>
  {NAME} export <store-name> [backup-path]
  {NAME} import <backup-path> [store-name]
  {NAME} encrypt <value> <user-key>
  {NAME} decrypt <token> <user-key>
  {NAME} --help | --version

Options:
  --keystore <dir>     where stores live (default ./.keystore)
  --iterations <n>     PBKDF2 rounds for new or migrated stores (default {fmt.DEFAULT_ITERATIONS})
  --json               print machine-readable JSON instead of prose
  --quiet              print results only, no progress

Examples:
  {NAME} secure keys.env "$USER_KEY" production
  {NAME} get api_key "$USER_KEY" production
  {NAME} stores
  {NAME} migrate production "$USER_KEY"

A key name is not a secret: 'list', 'stores' and 'info' read metadata and need
no user key. 'get', 'all', 'set' and 'migrate' decrypt, and do.
"""


def _parse_args(argv: Sequence[str]) -> tuple[dict[str, Any], list[str]]:
    """Pull the flags out and leave the positional arguments behind.

    Written by hand rather than with argparse, because flags may appear after the
    verb here and the subcommand machinery would cost more than it saves for
    fifteen fixed shapes.
    """
    flags: dict[str, Any] = {
        "keystore": None,
        "iterations": None,
        "json": False,
        "quiet": False,
        "help": False,
        "version": False,
    }
    positional: list[str] = []

    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--keystore" and index + 1 < len(argv):
            index += 1
            flags["keystore"] = argv[index]
        elif arg.startswith("--keystore="):
            flags["keystore"] = arg[len("--keystore=") :]
        elif arg == "--iterations" and index + 1 < len(argv):
            index += 1
            flags["iterations"] = int(argv[index])
        elif arg.startswith("--iterations="):
            flags["iterations"] = int(arg[len("--iterations=") :])
        elif arg == "--json":
            flags["json"] = True
        elif arg == "--quiet":
            flags["quiet"] = True
        elif arg in ("--help", "-h"):
            flags["help"] = True
        elif arg in ("--version", "-v"):
            flags["version"] = True
        else:
            positional.append(arg)
        index += 1

    return flags, positional


def _use_utf8_output() -> None:
    """Make stdout and stderr UTF-8, whatever the host's encoding says.

    On Windows the default is the ANSI code page - cp1252 - and printing a value
    containing an emoji or a Cyrillic key name raises ``UnicodeEncodeError``
    rather than printing anything at all. A secret is whatever bytes it is, and a
    command line that can store one but not show it is not much of a command
    line.

    Errors are replaced rather than raised: a terminal that genuinely cannot
    render a character should show a placeholder, not abort the command. Anything
    being captured by a script should use ``--json``, which is UTF-8 either way.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass  # a stream that will not be reconfigured is not worth failing over


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line. Returns the process exit status."""
    _use_utf8_output()
    flags, positional = _parse_args(sys.argv[1:] if argv is None else argv)

    if flags["version"]:
        print(__version__)
        return 0

    if flags["help"] or not positional:
        print(HELP)
        return 0

    def usage(line: str) -> int:
        print(f"Usage: {NAME} {line}", file=sys.stderr)
        return 1

    # Each command hands over both forms of its result at once: text for a
    # person, data for a script. Which one is printed is decided in one place.
    def emit(text: str, data: dict[str, Any]) -> int:
        print(json.dumps(data, indent=2, ensure_ascii=False) if flags["json"] else text)
        return 0

    try:
        store = Keystore(
            Path(flags["keystore"]).resolve() if flags["keystore"] else None,
            iterations=flags["iterations"] or fmt.DEFAULT_ITERATIONS,
            logger=None if flags["quiet"] or flags["json"] else print,
        )

        command, args = positional[0], positional[1:]

        if command == "secure":
            if len(args) < 2:
                return usage("secure <input-file> <user-key> [store-name]")
            result = store.secure(args[0], args[1], args[2] if len(args) > 2 else None)
            return emit(
                "\n".join(result.keys),
                {
                    "storeName": result.store_name,
                    "storeDir": result.store_dir,
                    "totalKeys": result.total_keys,
                    "keys": result.keys,
                },
            )

        if command == "get":
            if len(args) < 2:
                return usage("get <key> <user-key> [store-name]")
            value = store.get(args[0], args[1], args[2] if len(args) > 2 else None)
            # The bare value, so KEY=$(secure-keystore get x "$K" prod) works.
            return emit(value, {"key": args[0], "value": value})

        if command == "all":
            if len(args) < 2:
                return usage("all <store-name> <user-key>")
            values = store.get_all(args[1], args[0])
            text = "\n".join(f"{key}={value}" for key, value in sorted(values.items()))
            return emit(text, {"store": args[0], "values": values})

        if command == "set":
            if len(args) < 4:
                return usage("set <key> <value> <user-key> <store-name>")
            result = store.set(args[0], args[1], args[2], args[3])
            verb = "added to" if result.added else "updated in"
            return emit(
                f'Key "{result.key}" {verb} "{result.store_name}"',
                {
                    "key": result.key,
                    "storeName": result.store_name,
                    "added": result.added,
                    "format": result.store_format,
                },
            )

        if command == "migrate":
            if len(args) < 2:
                return usage("migrate <store-name> <user-key>")
            result = store.migrate(args[0], args[1])
            text = (
                f'Store "{result.store_name}" re-encrypted in format {result.to_format} '
                f"at {result.iterations} iterations"
                if result.from_format == result.to_format
                else f'Store "{result.store_name}" migrated from format '
                f"{result.from_format} to {result.to_format}"
            )
            return emit(
                text,
                {
                    "storeName": result.store_name,
                    "from": result.from_format,
                    "to": result.to_format,
                    "keys": result.keys,
                    "iterations": result.iterations,
                },
            )

        if command == "list":
            if len(args) < 1:
                return usage("list <store-name>")
            keys = store.list_keys(args[0])
            return emit("\n".join(keys), {"store": args[0], "keys": keys})

        if command == "stores":
            infos = [store.get_store_info(name) for name in store.list_stores()]
            text = (
                "\n".join(f"{info.name}  ({info.total_keys} keys)" for info in infos)
                if infos
                else "No stores found"
            )
            return emit(
                text,
                {
                    "stores": [
                        {
                            "name": info.name,
                            "version": info.version,
                            "current": info.current,
                            "totalKeys": info.total_keys,
                        }
                        for info in infos
                    ]
                },
            )

        if command == "info":
            if len(args) < 1:
                return usage("info <store-name>")
            info = store.get_store_info(args[0])
            shown = (
                info.version
                if info.current
                else f"{info.version}  (run migrate to bring it to {fmt.STORE_FORMAT_VERSION})"
            )
            text = "\n".join(
                [
                    f"Name:        {info.name}",
                    f"Path:        {info.path}",
                    f"Format:      {shown}",
                    f"Created:     {info.created}",
                    f"Updated:     {info.updated}",
                    f"Iterations:  {info.iterations}",
                    f"Total keys:  {info.total_keys}",
                    f"Keys:        {', '.join(info.keys)}",
                    f"Source file: {info.source_file}",
                ]
            )
            return emit(
                text,
                {
                    "name": info.name,
                    "path": info.path,
                    "version": info.version,
                    "current": info.current,
                    "created": info.created,
                    "updated": info.updated,
                    "iterations": info.iterations,
                    "totalKeys": info.total_keys,
                    "keys": info.keys,
                    "sourceFile": info.source_file,
                },
            )

        if command == "delete":
            if len(args) < 2:
                return usage("delete <key> <store-name>")
            store.delete_key(args[0], args[1])
            return emit(
                f'Key "{args[0]}" deleted from "{args[1]}"',
                {"key": args[0], "store": args[1], "deleted": True},
            )

        if command == "delete-store":
            if len(args) < 1:
                return usage("delete-store <store-name>")
            store.delete_store(args[0])
            return emit(f'Keystore "{args[0]}" deleted', {"store": args[0], "deleted": True})

        if command == "export":
            if len(args) < 1:
                return usage("export <store-name> [backup-path]")
            written = store.export_store(args[0], args[1] if len(args) > 1 else None)
            return emit(written, {"store": args[0], "path": written})

        if command == "import":
            if len(args) < 1:
                return usage("import <backup-path> [store-name]")
            imported = store.import_store(args[0], args[1] if len(args) > 1 else None)
            return emit(f'Store imported as "{imported}"', {"store": imported})

        if command == "encrypt":
            if len(args) < 2:
                return usage("encrypt <value> <user-key>")
            token = encrypt_value(args[0], args[1], iterations=flags["iterations"])
            return emit(token or "", {"token": token})

        if command == "decrypt":
            if len(args) < 2:
                return usage("decrypt <token> <user-key>")
            value = decrypt_value(args[0], args[1])
            return emit(value or "", {"value": value})

        print(f"Unknown command: {command}\n", file=sys.stderr)
        print(HELP)
        return 1

    except KeystoreError as error:
        # The code first, because the code is the half that is stable, and the
        # same line every implementation prints for the same failure.
        if flags["json"]:
            print(
                json.dumps({"error": error.message, "code": error.code}, indent=2),
                file=sys.stderr,
            )
        else:
            print(f"{error.code}: {error.message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
