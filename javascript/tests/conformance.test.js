'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

// The shared corpus, run against this implementation.
//
// Every language runs this same manifest against the same bytes. It is what
// turns "a store written by any of them opens in all the others" from a claim
// into a test - and, when two implementations disagree, it is what settles the
// argument in minutes rather than by whoever is more confident.
//
// JavaScript generated the corpus, so passing it here proves less than it does
// in the other five. What it does prove is that the corpus is self-consistent
// and that a later JavaScript release has not quietly changed what it reads.

const { SecureKeystore, decryptValue, isEncryptedValue, ErrorCodes } = require('../src');

const CORPUS = path.join(__dirname, '..', '..', 'conformance');
const MANIFEST = path.join(CORPUS, 'manifest.json');

if (!fs.existsSync(MANIFEST)) {
  test('conformance corpus is present', () => {
    assert.fail(`no corpus at ${MANIFEST} - run: node conformance/generate.js`);
  });
  return;
}

const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
const fixture = relative => path.join(CORPUS, 'fixtures', relative);

const reader = keystorePath => new SecureKeystore({
  keystoreDir: fixture(keystorePath),
  createDir: false
});

test('corpus: every store decrypts to the expected values', () => {
  for (const store of manifest.stores) {
    const keystore = reader(store.keystorePath);
    const actual = keystore.getAll(manifest.userKey, store.name);

    assert.deepEqual(actual, store.expected, `store "${store.name}" (${store.format})`);
  }
});

test('corpus: every store reports the format it was written in', () => {
  for (const store of manifest.stores) {
    const info = reader(store.keystorePath).getStoreInfo(store.name);
    assert.equal(info.version, store.format, `store "${store.name}"`);
  }
});

test('corpus: every value also reads one at a time', () => {
  for (const store of manifest.stores) {
    const keystore = reader(store.keystorePath);
    for (const [key, expected] of Object.entries(store.expected)) {
      assert.equal(
        keystore.get(key, manifest.userKey, store.name),
        expected,
        `store "${store.name}", key "${key}"`
      );
    }
  }
});

test('corpus: every token decrypts to the expected value', () => {
  for (const entry of manifest.tokens) {
    assert.equal(
      decryptValue(entry.token, manifest.userKey),
      entry.expected,
      `token "${entry.name}" (${entry.version || 'not a token'})`
    );

    if (entry.version) {
      assert.ok(isEncryptedValue(entry.token), `token "${entry.name}" should be recognised as one`);
    } else {
      assert.ok(!isEncryptedValue(entry.token), `"${entry.name}" is not a token and must not look like one`);
    }
  }
});

test('corpus: every bundle imports and decrypts', t => {
  for (const bundle of manifest.bundles) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-keystore-conformance-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    const keystore = new SecureKeystore({ keystoreDir: path.join(dir, '.keystore') });
    const imported = keystore.importStore(fixture(bundle.path), bundle.importAs);

    assert.equal(imported, bundle.importAs);
    assert.deepEqual(
      keystore.getAll(manifest.userKey, bundle.importAs),
      bundle.expected,
      `bundle "${bundle.name}"`
    );

    // A hostile bundle must land entirely inside the target store.
    for (const name of bundle.mustNotCreate || []) {
      assert.ok(!fs.existsSync(path.join(dir, name)), `bundle "${bundle.name}" wrote ${name} outside the keystore`);
      assert.ok(!fs.existsSync(path.join(dir, '.keystore', name)), `bundle "${bundle.name}" wrote ${name} outside its store`);
    }
    for (const name of bundle.mustCreateInsideStore || []) {
      assert.ok(
        fs.existsSync(path.join(dir, '.keystore', bundle.importAs, name)),
        `bundle "${bundle.name}" should have written ${name} inside the store`
      );
    }
  }
});

test('corpus: every token refusal is refused, with the right code', () => {
  for (const refusal of manifest.refusals.tokens) {
    assert.throws(
      () => decryptValue(refusal.token, refusal.userKey),
      error => {
        assert.equal(error.code, refusal.code, `token refusal "${refusal.name}"`);
        return true;
      },
      `token refusal "${refusal.name}" was not refused`
    );
  }
});

test('corpus: every bundle refusal is refused, with the right code', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-keystore-conformance-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const keystore = new SecureKeystore({ keystoreDir: path.join(dir, '.keystore') });

  for (const refusal of manifest.refusals.bundles) {
    assert.throws(
      () => keystore.importStore(fixture(refusal.path), 'target'),
      error => {
        assert.equal(error.code, refusal.code, `bundle refusal "${refusal.name}": ${refusal.note}`);
        return true;
      },
      `bundle refusal "${refusal.name}" was not refused`
    );
  }
});

test('corpus: a store from a future format is refused', () => {
  for (const refusal of manifest.refusals.stores) {
    assert.throws(
      () => reader(refusal.keystorePath).getStoreInfo(refusal.store),
      error => {
        assert.equal(error.code, refusal.code, `store refusal "${refusal.name}": ${refusal.note}`);
        return true;
      },
      `store refusal "${refusal.name}" was not refused`
    );
  }
});

test('corpus: the manifest covers what it claims to', () => {
  // A corpus that silently shrinks is worse than no corpus, because it still
  // passes. These are floors, not exact counts - adding cases is expected.
  assert.ok(manifest.stores.length >= 4, 'expected at least four stores');
  assert.ok(manifest.tokens.length >= 10, 'expected at least ten tokens');
  assert.ok(manifest.refusals.tokens.length >= 8, 'expected at least eight token refusals');
  assert.ok(manifest.refusals.bundles.length >= 4, 'expected at least four bundle refusals');

  // The two that must always be there, whatever else changes.
  assert.ok(manifest.stores.some(store => store.format === '2.0'), 'no format 2.0 store in the corpus');
  assert.ok(manifest.tokens.some(token => token.version === 'skv1'), 'no skv1 token in the corpus');
});
