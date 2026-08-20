"""Tests written against the behaviour, not against another implementation.

Where a property is shared across implementations it is in the conformance
corpus instead; this file is what is specific to Python, plus the things worth
asserting twice.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_keystore import (
    ALGORITHMS,
    STORE_FORMAT_VERSION,
    ErrorCodes,
    InputFormat,
    Keystore,
    KeystoreError,
    decrypt_value,
    encrypt_value,
    format_for,
    parse_text,
    token_version,
)

# The real default is 600,000, which is the point of it and which would make this
# file take a minute.
FAST = 10_000

USER_KEY = "testUser123!@#"
MASTER_KEY = "TestMasterKey123"

KEYS_TXT = "\n".join(
    [
        f"master:{MASTER_KEY}",
        "api_key:sk_test_abc123",
        "jwt_secret:test_secret_xyz",
        "db_url:postgres://user:pass@host:5432/db",
    ]
)


@pytest.fixture()
def store(tmp_path: Path) -> Keystore:
    return Keystore(tmp_path / ".keystore", iterations=FAST)


@pytest.fixture()
def keys_file(tmp_path: Path) -> Path:
    path = tmp_path / "keys.txt"
    path.write_text(KEYS_TXT, encoding="utf-8")
    return path


def test_secure_then_get(store: Keystore, keys_file: Path) -> None:
    result = store.secure(keys_file, USER_KEY, "prod")

    assert result.total_keys == 3
    assert result.keys == ["api_key", "jwt_secret", "db_url"]
    assert store.get("api_key", USER_KEY, "prod") == "sk_test_abc123"

    # Only the first colon splits, so the URL survives intact.
    assert store.get("db_url", USER_KEY, "prod") == "postgres://user:pass@host:5432/db"


def test_store_name_defaults_to_file_name(store: Keystore, tmp_path: Path) -> None:
    source = tmp_path / "staging.txt"
    source.write_text(KEYS_TXT, encoding="utf-8")

    assert store.secure(source, USER_KEY).store_name == "staging"
    assert store.list_stores() == ["staging"]


def test_wrong_user_key_is_reported_as_such(store: Keystore, keys_file: Path) -> None:
    store.secure(keys_file, USER_KEY, "prod")

    with pytest.raises(KeystoreError) as caught:
        store.get("api_key", "wrong-key", "prod")

    assert caught.value.code == ErrorCodes.BAD_USER_KEY
    assert 'keystore "prod"' in caught.value.message


def test_a_value_is_bound_to_its_key_name(store: Keystore, tmp_path: Path) -> None:
    """The format 2.0 gap, closed.

    On 2.0 both reads succeeded and returned each other's values.
    """
    source = tmp_path / "keys.txt"
    source.write_text("master:M\nfirst:VALUE_A\nsecond:VALUE_B", encoding="utf-8")
    store.secure(source, USER_KEY, "prod")

    store_dir = store.keystore_dir / "prod"
    metadata = json.loads((store_dir / "master.json").read_text(encoding="utf-8"))
    files = {entry["key"]: store_dir / entry["file"] for entry in metadata["entries"]}

    first, second = files["first"].read_bytes(), files["second"].read_bytes()
    files["first"].write_bytes(second)
    files["second"].write_bytes(first)

    for key in ("first", "second"):
        with pytest.raises(KeystoreError) as caught:
            store.get(key, USER_KEY, "prod")
        assert caught.value.code == ErrorCodes.BAD_USER_KEY


def test_every_iv_is_twelve_bytes(store: Keystore, keys_file: Path) -> None:
    store.secure(keys_file, USER_KEY, "prod")

    store_dir = store.keystore_dir / "prod"
    metadata = json.loads((store_dir / "master.json").read_text(encoding="utf-8"))

    # 12 bytes is 24 hex characters, the only length .NET's AesGcm accepts.
    assert len(metadata["master"]["iv"]) == 24
    assert len(metadata["master"]["authTag"]) == 32

    for entry in metadata["entries"]:
        record = json.loads((store_dir / entry["file"]).read_text(encoding="utf-8"))
        assert len(record["data"]["iv"]) == 24
        # A 3.0 value records no count, because HKDF takes none.
        assert "iterations" not in record


def test_set_adds_and_replaces(store: Keystore, keys_file: Path) -> None:
    store.secure(keys_file, USER_KEY, "prod")

    added = store.set("new_key", "new_value", USER_KEY, "prod")
    assert added.added
    assert added.store_format == STORE_FORMAT_VERSION
    assert store.get("new_key", USER_KEY, "prod") == "new_value"

    replaced = store.set("api_key", "rotated", USER_KEY, "prod")
    assert not replaced.added
    assert store.get("api_key", USER_KEY, "prod") == "rotated"
    assert store.list_keys("prod").count("api_key") == 1


def test_migrate_re_encrypts_at_a_new_count(store: Keystore, keys_file: Path) -> None:
    store.secure(keys_file, USER_KEY, "prod")
    before = store.get_all(USER_KEY, "prod")

    stronger = Keystore(store.keystore_dir, iterations=50_000)
    result = stronger.migrate("prod", USER_KEY)

    assert result.from_format == STORE_FORMAT_VERSION
    assert result.iterations == 50_000
    assert stronger.get_store_info("prod").iterations == 50_000
    assert stronger.get_all(USER_KEY, "prod") == before


def test_migrate_leaves_the_store_untouched_on_a_wrong_key(store: Keystore, keys_file: Path) -> None:
    store.secure(keys_file, USER_KEY, "prod")
    master_path = store.keystore_dir / "prod" / "master.json"
    before = master_path.read_text(encoding="utf-8")

    with pytest.raises(KeystoreError) as caught:
        store.migrate("prod", "wrong-key")

    assert caught.value.code == ErrorCodes.BAD_USER_KEY
    assert master_path.read_text(encoding="utf-8") == before
    assert store.get("api_key", USER_KEY, "prod") == "sk_test_abc123"


def test_key_names_cannot_escape_the_store(store: Keystore, keys_file: Path, tmp_path: Path) -> None:
    store.secure(keys_file, USER_KEY, "prod")

    evil = "../../escape:key"
    store.set(evil, "evil_value", USER_KEY, "prod")

    assert store.get(evil, USER_KEY, "prod") == "evil_value"
    assert not (tmp_path / "escape:key").exists()

    # Two names that sanitise alike must still get separate files.
    store.set("a/b", "first", USER_KEY, "prod")
    store.set("a_b", "second", USER_KEY, "prod")
    assert store.get("a/b", USER_KEY, "prod") == "first"
    assert store.get("a_b", USER_KEY, "prod") == "second"


def test_list_stores_ignores_non_stores(store: Keystore, keys_file: Path) -> None:
    store.secure(keys_file, USER_KEY, "prod")
    (store.keystore_dir / "not-a-store").mkdir()

    assert store.list_stores() == ["prod"]


def test_export_import_round_trip(store: Keystore, keys_file: Path, tmp_path: Path) -> None:
    store.secure(keys_file, USER_KEY, "prod")
    bundle = store.export_store("prod", tmp_path / "prod.skb")

    assert store.import_store(bundle, "restored") == "restored"
    assert store.get("api_key", USER_KEY, "restored") == "sk_test_abc123"


def test_delete_store_refuses_a_non_store(store: Keystore) -> None:
    stranger = store.keystore_dir / "important-data"
    stranger.mkdir(parents=True)
    (stranger / "notes.txt").write_text("do not delete me", encoding="utf-8")

    with pytest.raises(KeystoreError) as caught:
        store.delete_store("important-data")

    assert caught.value.code == ErrorCodes.STORE_CORRUPT
    assert (stranger / "notes.txt").is_file()


def test_unknown_fields_survive_a_rewrite(store: Keystore, keys_file: Path) -> None:
    """An older reader that silently downgrades a store is worse than one that refuses it."""
    store.secure(keys_file, USER_KEY, "prod")

    master_path = store.keystore_dir / "prod" / "master.json"
    metadata = json.loads(master_path.read_text(encoding="utf-8"))
    metadata["somethingNewer"] = {"a": 1}
    master_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    store.set("another", "value", USER_KEY, "prod")

    reread = json.loads(master_path.read_text(encoding="utf-8"))
    assert "somethingNewer" in reread


def test_options_are_validated_at_construction(tmp_path: Path) -> None:
    with pytest.raises(KeystoreError) as caught:
        Keystore(tmp_path, iterations=10)
    assert caught.value.code == ErrorCodes.INVALID_OPTIONS

    with pytest.raises(KeystoreError):
        Keystore(tmp_path, logger="stdout")  # type: ignore[arg-type]


def test_the_package_is_silent_without_a_logger(store: Keystore, keys_file: Path, tmp_path: Path) -> None:
    lines: list[str] = []
    talkative = Keystore(tmp_path / ".keystore-2", iterations=FAST, logger=lines.append)

    talkative.secure(keys_file, USER_KEY, "prod")
    assert len(lines) == 1
    assert "Secured 3 keys" in lines[0]

    # The default store has no logger, and must stay silent.
    before = len(lines)
    store.secure(keys_file, USER_KEY, "prod")
    assert len(lines) == before


def test_token_round_trip() -> None:
    token = encrypt_value("sk_live_abc123", USER_KEY, iterations=FAST)

    assert token_version(token) == "skv2"
    assert token.split(":")[1] == str(FAST)
    assert len(token.split(":")) == 6
    assert decrypt_value(token, USER_KEY) == "sk_live_abc123"

    # Empty and absent values pass through, matching every implementation.
    assert encrypt_value("", USER_KEY) == ""
    assert encrypt_value(None, USER_KEY) is None
    assert decrypt_value("not encrypted", USER_KEY) == "not encrypted"


def test_token_refuses_a_wrong_key_and_a_tampered_body() -> None:
    token = encrypt_value("secret", USER_KEY, iterations=FAST)

    with pytest.raises(KeystoreError) as caught:
        decrypt_value(token, "wrong-key")
    assert caught.value.code == ErrorCodes.BAD_USER_KEY

    parts = token.split(":")
    parts[5] = ("b" if parts[5][0] == "a" else "a") + parts[5][1:]
    with pytest.raises(KeystoreError):
        decrypt_value(":".join(parts), USER_KEY)

    with pytest.raises(KeystoreError) as caught:
        decrypt_value("skv2:only:three", USER_KEY)
    assert caught.value.code == ErrorCodes.BAD_TOKEN


def test_parse_text_formats() -> None:
    parsed = parse_text(
        "# comment\nmaster=M\nexport api=a\njwt=\"quoted\"\nno_equals", InputFormat.ENV
    )
    assert parsed.master_key == "M"
    assert [(entry.key, entry.value) for entry in parsed.entries] == [("api", "a"), ("jwt", "quoted")]

    parsed = parse_text('{"master":"M","api":"a","port":8080,"on":true}', InputFormat.JSON)
    assert parsed.master_key == "M"
    # Order is the document's order, and non-strings keep their JSON form.
    assert [(entry.key, entry.value) for entry in parsed.entries] == [
        ("api", "a"),
        ("port", "8080"),
        ("on", "true"),
    ]

    with pytest.raises(KeystoreError) as caught:
        parse_text("api:a\nmaster:M", InputFormat.COLON)
    assert caught.value.code == ErrorCodes.BAD_INPUT

    with pytest.raises(KeystoreError):
        parse_text("[1,2]", InputFormat.JSON)


def test_format_for() -> None:
    assert format_for("keys.json") is InputFormat.JSON
    assert format_for("KEYS.JSON") is InputFormat.JSON
    assert format_for("keys.env") is InputFormat.ENV
    assert format_for("keys.txt") is InputFormat.COLON
    assert format_for("keys") is InputFormat.COLON


def test_algorithms_describe_what_this_build_does() -> None:
    assert ALGORITHMS["cipher"] == "aes-256-gcm"
    assert ALGORITHMS["ivBytes"] == 12
    assert ALGORITHMS["passwordKdf"] == "pbkdf2-hmac-sha256"
    assert ALGORITHMS["keyKdf"] == "hkdf-sha256"
    assert ALGORITHMS["defaultIterations"] == 600_000
    assert ALGORITHMS["bindsKeyName"] is True
