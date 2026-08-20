"""Reading an input file into a master key and a list of entries.

Three formats, chosen by extension, all saying the same thing. They are parsed
here rather than in the store so that each can be tested against a string, with
no directory involved - which is how the ``export`` prefix and the quoted-value
cases below came to be covered at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from . import _format as fmt
from .errors import ErrorCodes, KeystoreError

__all__ = ["InputFormat", "Entry", "ParsedInput", "format_for", "parse_input", "parse_text"]


class InputFormat(str, Enum):
    """One of the three shapes an input file can take."""

    #: ``master:<key>`` on the first line, then ``key:value`` lines.
    COLON = "colon"
    #: dotenv: ``KEY=value``, with comments, quotes and ``export``.
    ENV = "env"
    #: A flat object with a ``master`` property.
    JSON = "json"


@dataclass(frozen=True, slots=True)
class Entry:
    """One key-value pair read out of an input file."""

    key: str
    value: str


@dataclass(frozen=True, slots=True)
class ParsedInput:
    """What an input file said."""

    #: The master key, or ``None`` if the file did not define one.
    master_key: str | None
    #: Everything else, in the order the file gave it.
    entries: list[Entry]


def format_for(input_file: str | Path) -> InputFormat:
    """The format an input file will be read as, from its extension.

    ``.json`` and ``.env`` are named; everything else is the colon format.
    """
    suffix = Path(input_file).suffix.lower()
    if suffix == ".json":
        return InputFormat.JSON
    if suffix == ".env":
        return InputFormat.ENV
    return InputFormat.COLON


def parse_input(input_file: str | Path) -> ParsedInput:
    """Read a file and parse it as whatever its extension says it is."""
    try:
        content = Path(input_file).read_text(encoding="utf-8")
    except OSError as cause:
        raise KeystoreError(
            ErrorCodes.BAD_INPUT, f"could not read input file: {input_file}"
        ) from cause

    return parse_text(content, format_for(input_file))


def parse_text(content: str, input_format: InputFormat) -> ParsedInput:
    """Parse input text in a named format. The file-free half of :func:`parse_input`."""
    if input_format is InputFormat.JSON:
        return _parse_json(content)
    if input_format is InputFormat.ENV:
        return _parse_env(content)
    if input_format is InputFormat.COLON:
        return _parse_colon(content)
    raise KeystoreError(ErrorCodes.BAD_INPUT, f"unknown input format: {input_format}")


def _parse_colon(content: str) -> ParsedInput:
    """The default format: ``master:<key>`` first, then ``key:value``.

    Only the first colon splits, so a value may contain as many more as it likes -
    which is what lets a URL or a connection string go in without escaping.
    """
    lines = [line.strip() for line in content.split("\n")]
    lines = [line for line in lines if line]

    if not lines:
        raise KeystoreError(ErrorCodes.BAD_INPUT, "input file is empty")

    head, separator, master_key = lines[0].partition(":")
    if not separator or head != fmt.MASTER_ENTRY_KEY:
        raise KeystoreError(
            ErrorCodes.BAD_INPUT,
            f'first line must be "{fmt.MASTER_ENTRY_KEY}:your_master_key"',
        )

    entries: list[Entry] = []
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if not separator:
            continue
        entries.append(Entry(key=key, value=value))

    return ParsedInput(master_key=master_key, entries=entries)


def _parse_env(content: str) -> ParsedInput:
    """dotenv syntax.

    Lines beginning ``#`` are skipped, as are lines with no ``=`` and lines with
    an empty key. A leading ``export `` is stripped. A matched pair of single or
    double quotes around the whole value is stripped - no escape sequences are
    interpreted. The master entry may appear anywhere.
    """
    master_key: str | None = None
    entries: list[Entry] = []

    for raw in content.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export ") :].strip()

        key, separator, value = line.partition("=")
        if not separator:
            continue

        key = key.strip()
        if not key:
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]

        if key == fmt.MASTER_ENTRY_KEY:
            master_key = value
            continue

        entries.append(Entry(key=key, value=value))

    return ParsedInput(master_key=master_key, entries=entries)


def _parse_json(content: str) -> ParsedInput:
    """A flat object.

    Values that are not strings are serialised to their JSON form rather than
    refused, so a port number or a feature flag lifted straight out of an
    existing config file goes in without being quoted first. Everything comes
    back out as a string, which is what the store holds.
    """
    try:
        document = json.loads(content)
    except ValueError as cause:
        raise KeystoreError(ErrorCodes.BAD_INPUT, "invalid JSON input file") from cause

    if not isinstance(document, dict):
        raise KeystoreError(
            ErrorCodes.BAD_INPUT, "JSON input must be an object of key-value pairs"
        )

    master_key: str | None = None
    entries: list[Entry] = []

    for key, value in document.items():
        # json.dumps with these separators produces the same compact form every
        # other implementation writes for a non-string value.
        text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))

        if key == fmt.MASTER_ENTRY_KEY:
            master_key = text
            continue

        entries.append(Entry(key=key, value=text))

    return ParsedInput(master_key=master_key, entries=entries)
