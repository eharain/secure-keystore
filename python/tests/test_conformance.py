"""The shared corpus, run against this implementation.

The corpus was written by the JavaScript implementation. Nothing here has ever
seen that code - this package was written against SPEC.md - so passing this file
is the whole cross-language claim, tested rather than asserted.

It cannot be a comparison of encoders: every write in this format draws a fresh
salt and a fresh IV, so two implementations encrypting the same secret never
produce the same bytes. What is pinned is the other direction - these bytes,
under this key, must come back as this plaintext - plus the refusals, which
matter just as much. An implementation that accepts a tampered token is not
conforming however well it handles the happy path.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from secure_keystore import (
    Keystore,
    KeystoreError,
    decrypt_value,
    is_encrypted_value,
    token_version,
)

CORPUS = Path(__file__).resolve().parents[2] / "conformance"
MANIFEST = CORPUS / "manifest.json"

pytestmark = pytest.mark.skipif(
    not MANIFEST.is_file(),
    reason=f"no corpus at {MANIFEST} - run: node conformance/generate.js",
)


def manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def fixture(relative: str) -> Path:
    return CORPUS / "fixtures" / Path(relative)


def reader(keystore_path: str) -> Keystore:
    """Open a corpus keystore without creating anything."""
    return Keystore(fixture(keystore_path), create_dir=False)


def scratch(tmp_path: Path, iterations: int) -> Keystore:
    return Keystore(tmp_path / ".keystore", iterations=iterations)


def test_every_store_decrypts_to_the_expected_values() -> None:
    corpus = manifest()
    assert corpus["stores"]

    for store in corpus["stores"]:
        keystore = reader(store["keystorePath"])

        assert keystore.get_store_info(store["name"]).version == store["format"]

        values = keystore.get_all(corpus["userKey"], store["name"])
        assert values == store["expected"], store["name"]

        # And one at a time, which takes a different path through the code.
        for key, expected in store["expected"].items():
            assert keystore.get(key, corpus["userKey"], store["name"]) == expected


def test_every_token_decrypts_to_the_expected_value() -> None:
    corpus = manifest()
    assert corpus["tokens"]

    for token in corpus["tokens"]:
        assert decrypt_value(token["token"], corpus["userKey"]) == token["expected"], token["name"]

        if token["version"] is None:
            assert not is_encrypted_value(token["token"])
        else:
            assert is_encrypted_value(token["token"])
            assert token_version(token["token"]) == token["version"]


def test_every_bundle_imports_and_decrypts(tmp_path: Path) -> None:
    corpus = manifest()

    for bundle in corpus["bundles"]:
        target = tmp_path / bundle["name"]
        keystore = scratch(target, corpus["iterations"])

        assert keystore.import_store(fixture(bundle["path"]), bundle["importAs"]) == bundle["importAs"]

        values = keystore.get_all(corpus["userKey"], bundle["importAs"])
        for key, expected in bundle["expected"].items():
            assert values[key] == expected

        # A hostile bundle must land entirely inside the target store.
        for name in bundle.get("mustNotCreate") or []:
            assert not (target / name).exists()
            assert not (target / ".keystore" / name).exists()

        for name in bundle.get("mustCreateInsideStore") or []:
            assert (target / ".keystore" / bundle["importAs"] / name).is_file()


def test_every_token_refusal_is_refused() -> None:
    corpus = manifest()
    assert corpus["refusals"]["tokens"]

    for refusal in corpus["refusals"]["tokens"]:
        with pytest.raises(KeystoreError) as caught:
            decrypt_value(refusal["token"], refusal["userKey"])
        assert caught.value.code == refusal["code"], refusal["name"]


def test_every_bundle_refusal_is_refused(tmp_path: Path) -> None:
    corpus = manifest()
    assert corpus["refusals"]["bundles"]

    keystore = scratch(tmp_path, corpus["iterations"])

    for refusal in corpus["refusals"]["bundles"]:
        with pytest.raises(KeystoreError) as caught:
            keystore.import_store(fixture(refusal["path"]), "target")
        assert caught.value.code == refusal["code"], refusal["name"]


def test_every_store_refusal_is_refused() -> None:
    corpus = manifest()

    for refusal in corpus["refusals"]["stores"]:
        with pytest.raises(KeystoreError) as caught:
            reader(refusal["keystorePath"]).get_store_info(refusal["store"])
        assert caught.value.code == refusal["code"], refusal["name"]


def test_writes_a_store_that_reads_back(tmp_path: Path) -> None:
    """The other direction: a store this package wrote, read back.

    The JavaScript, Go and .NET suites do the same, which is what closes the
    loop.
    """
    corpus = manifest()
    expected = next(store["expected"] for store in corpus["stores"] if store["name"] == "basic")

    keystore = scratch(tmp_path, corpus["iterations"])

    source = tmp_path / "python-written.env"
    source.write_text(f"master={corpus['masterKey']}\nplaceholder=x", encoding="utf-8")
    keystore.secure(source, corpus["userKey"], "python-written")

    for key, value in expected.items():
        keystore.set(key, value, corpus["userKey"], "python-written")
    keystore.delete_key("placeholder", "python-written")

    assert keystore.get_all(corpus["userKey"], "python-written") == expected

    # Leave it where a cross-language check can find it, if asked to.
    out_dir = os.environ.get("SECURE_KEYSTORE_CROSS_WRITE_DIR")
    if out_dir:
        keystore.export_store("python-written", Path(out_dir) / "python-written.skb")


def test_migrates_a_legacy_store(tmp_path: Path) -> None:
    """A format 2.0 store read, migrated to 3.0, then read again."""
    import shutil

    corpus = manifest()
    legacy = next(store for store in corpus["stores"] if store["format"] == "2.0")

    # Copy the corpus store, so the fixtures are never written to.
    source = fixture(f"{legacy['keystorePath']}/{legacy['name']}")
    target = tmp_path / ".keystore" / legacy["name"]
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target)

    keystore = scratch(tmp_path, corpus["iterations"])
    assert keystore.get_store_info(legacy["name"]).version == "2.0"
    assert not keystore.get_store_info(legacy["name"]).current

    result = keystore.migrate(legacy["name"], corpus["userKey"])
    assert result.from_format == "2.0"
    assert result.to_format == "3.0"

    assert keystore.get_all(corpus["userKey"], legacy["name"]) == legacy["expected"]
    assert keystore.get_store_info(legacy["name"]).current
