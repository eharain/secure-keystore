#!/usr/bin/env node
'use strict';

// Generates the conformance corpus.
//
//   node conformance/generate.js
//
// Run from the repository root. Overwrites conformance/fixtures/ and
// conformance/manifest.json.
//
// Why a corpus of fixtures rather than a comparison of encoders: every write in
// this format draws a fresh salt and a fresh IV, so two implementations
// encrypting the same secret never produce the same bytes and there is nothing
// to diff. What can be pinned is the other direction - these bytes, under this
// key, must come back as this plaintext, in every language. Plus the refusals,
// which matter just as much: an implementation that accepts a tampered token is
// not conforming however well it handles the happy path.
//
// The counts here are deliberately low. A corpus is decrypted on every CI run
// in six languages, and 600,000 rounds times that is minutes of nothing. The
// iteration count is not what is under test; the format is.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
  SecureKeystore,
  encryptValue,
  VERSION,
  STORE_FORMAT_VERSION
} = require('../javascript/src');

const ROOT = path.join(__dirname, 'fixtures');
const ITERATIONS = 10000;

const USER_KEY = 'conformance-user-key-!@#-£€-🔐';
const MASTER_KEY = 'conformance-master-key';

// Values chosen to break things: an empty string, one that is only colons, one
// with the format's own delimiter, unicode past the BMP, a long one, and one
// that looks like a token but is not.
const VALUES = {
  api_key: 'sk_live_abc123',
  empty: '',
  colons: ':::',
  delimited: 'a:b:c:d:e:f',
  unicode: '🔐 ключ ñ 日本語',
  newlines: 'line one\nline two\r\nline three',
  json_ish: '{"nested":{"a":[1,2,3]},"b":null}',
  long: 'x'.repeat(5000),
  looks_like_token: 'skv2:not:really:a:token:at:all',
  spaces: '  leading and trailing  '
};

// Key names chosen to break filenames: one that needs sanitising, one that
// collides with another after sanitising, one with unicode, one at the length
// limit.
const AWKWARD_KEYS = {
  'a/b': 'slash',
  'a_b': 'underscore - must not collide with a/b',
  '../escape': 'traversal',
  'ключ': 'unicode key name',
  'UPPER.case-mixed_123': 'punctuation',
  ['k'.repeat(80)]: 'over the stem limit'
};

fs.rmSync(ROOT, { recursive: true, force: true });
fs.mkdirSync(ROOT, { recursive: true });

const manifest = {
  description: 'Fixtures every secure-keystore implementation must read identically. See conformance/README.md.',
  generatedBy: `@tech-style/secure-keystore ${VERSION} (JavaScript)`,
  storeFormat: STORE_FORMAT_VERSION,
  userKey: USER_KEY,
  masterKey: MASTER_KEY,
  iterations: ITERATIONS,
  stores: [],
  tokens: [],
  bundles: [],
  refusals: { tokens: [], bundles: [], stores: [] }
};

// ── Stores ───────────────────────────────────────────────────────────────────

function writeStore(name, entries, options = {}) {
  const keystoreDir = path.join(ROOT, 'stores', name);
  const store = new SecureKeystore({ keystoreDir, iterations: ITERATIONS });

  const input = path.join(ROOT, 'stores', `${name}-input.env`);
  fs.writeFileSync(input, [
    `master=${MASTER_KEY}`,
    ...Object.entries(entries).map(([key, value]) => `${key}=${value}`)
  ].join('\n'));

  store.secure(input, USER_KEY, name);
  fs.unlinkSync(input);

  if (options.migrateFrom) store.migrate(name, USER_KEY);

  manifest.stores.push({
    name,
    path: `stores/${name}/${name}`,
    keystorePath: `stores/${name}`,
    format: store.getStoreInfo(name).version,
    note: options.note || null,
    expected: entries
  });
}

// A store whose values are ordinary but whose *values* are awkward. The .env
// input format cannot carry an empty value or leading spaces faithfully, so
// those go in through `set` instead.
{
  const name = 'basic';
  const keystoreDir = path.join(ROOT, 'stores', name);
  const store = new SecureKeystore({ keystoreDir, iterations: ITERATIONS });
  const input = path.join(ROOT, 'stores', `${name}-input.env`);

  fs.writeFileSync(input, `master=${MASTER_KEY}\napi_key=${VALUES.api_key}`);
  store.secure(input, USER_KEY, name);
  fs.unlinkSync(input);

  for (const [key, value] of Object.entries(VALUES)) {
    if (key === 'api_key') continue;
    store.set(key, value, USER_KEY, name);
  }

  manifest.stores.push({
    name,
    path: `stores/${name}/${name}`,
    keystorePath: `stores/${name}`,
    format: STORE_FORMAT_VERSION,
    note: 'every awkward value shape',
    expected: VALUES
  });
}

// A store whose *key names* are awkward.
{
  const name = 'awkward-keys';
  const keystoreDir = path.join(ROOT, 'stores', name);
  const store = new SecureKeystore({ keystoreDir, iterations: ITERATIONS });
  const input = path.join(ROOT, 'stores', `${name}-input.env`);

  fs.writeFileSync(input, `master=${MASTER_KEY}\nplaceholder=x`);
  store.secure(input, USER_KEY, name);
  fs.unlinkSync(input);

  for (const [key, value] of Object.entries(AWKWARD_KEYS)) {
    store.set(key, value, USER_KEY, name);
  }
  store.deleteKey('placeholder', name);

  manifest.stores.push({
    name,
    path: `stores/${name}/${name}`,
    keystorePath: `stores/${name}`,
    format: STORE_FORMAT_VERSION,
    note: 'key names that must survive sanitising without colliding',
    expected: AWKWARD_KEYS
  });
}

// A store in format 2.0, written the way 2.0 wrote one, so that every
// implementation proves it still reads the old format rather than assuming it.
{
  const name = 'legacy-2.0';
  const keystoreDir = path.join(ROOT, 'stores', name);
  const storeDir = path.join(keystoreDir, name);
  fs.mkdirSync(storeDir, { recursive: true });

  const entries = { api_key: 'sk_legacy_abc', jwt_secret: 'legacy_jwt', unicode: '🔐 старый' };

  const legacyEncrypt = (plaintext, key) => {
    const iv = crypto.randomBytes(16);                  // 2.0 used 16
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    // No AAD - 2.0 bound nothing.
    let data = cipher.update(String(plaintext), 'utf8', 'hex');
    data += cipher.final('hex');
    return { iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex'), data };
  };

  const storeSalt = crypto.randomBytes(32);
  const userDerived = crypto.pbkdf2Sync(USER_KEY, storeSalt, ITERATIONS, 32, 'sha256');

  const written = Object.entries(entries).map(([key, value]) => {
    const valueSalt = crypto.randomBytes(32);
    const valueKey = crypto.pbkdf2Sync(MASTER_KEY, valueSalt, ITERATIONS, 32, 'sha256');
    const stem = key.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64);
    const hash = crypto.createHash('sha256').update(key, 'utf8').digest('hex').slice(0, 8);
    const file = `${stem}-${hash}.enc`;

    fs.writeFileSync(path.join(storeDir, file), JSON.stringify({
      salt: valueSalt.toString('hex'),
      iterations: ITERATIONS,
      data: legacyEncrypt(value, valueKey)
    }, null, 2));

    return { key, file };
  });

  fs.writeFileSync(path.join(storeDir, 'master.json'), JSON.stringify({
    version: '2.0',
    created: '2026-01-01T00:00:00.000Z',
    salt: storeSalt.toString('hex'),
    iterations: ITERATIONS,
    master: legacyEncrypt(MASTER_KEY, userDerived),
    entries: written,
    sourceFile: 'legacy.env',
    totalKeys: written.length
  }, null, 2));

  manifest.stores.push({
    name,
    path: `stores/${name}/${name}`,
    keystorePath: `stores/${name}`,
    format: '2.0',
    note: 'the old format - 16-byte IV, no AAD, PBKDF2 per value',
    expected: entries
  });
}

// A single-key store, the simplest thing that can be got wrong.
writeStore('single', { only_key: 'only_value' }, { note: 'one key, nothing else' });

// ── Tokens ───────────────────────────────────────────────────────────────────

for (const [name, value] of Object.entries(VALUES)) {
  if (value === '') continue;   // encryptValue returns '' unchanged, by contract
  manifest.tokens.push({
    name,
    version: 'skv2',
    token: encryptValue(value, USER_KEY, { iterations: ITERATIONS }),
    expected: value
  });
}

// One skv1 token, so every implementation proves it reads the old layout.
{
  const value = 'written_by_version_1';
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(USER_KEY, salt, 100000, 32, 'sha256');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let data = cipher.update(value, 'utf8', 'hex');
  data += cipher.final('hex');

  manifest.tokens.push({
    name: 'legacy-skv1',
    version: 'skv1',
    token: ['skv1', salt.toString('hex'), iv.toString('hex'), cipher.getAuthTag().toString('hex'), data].join(':'),
    expected: value,
    note: '16-byte salt and IV, 100000 rounds, no AAD - fixed by the skv1 layout'
  });
}

// Values that are not tokens must come back unchanged, not throw.
manifest.tokens.push(
  { name: 'passthrough-plain', version: null, token: 'not encrypted at all', expected: 'not encrypted at all' },
  { name: 'passthrough-lookalike', version: null, token: 'skv:almost', expected: 'skv:almost' }
);

// ── Bundles ──────────────────────────────────────────────────────────────────

{
  const keystoreDir = path.join(ROOT, 'stores', 'basic');
  const store = new SecureKeystore({ keystoreDir, iterations: ITERATIONS });
  const bundlePath = path.join(ROOT, 'bundles', 'basic.skb');

  fs.mkdirSync(path.dirname(bundlePath), { recursive: true });
  store.exportStore('basic', bundlePath);

  manifest.bundles.push({
    name: 'basic',
    path: 'bundles/basic.skb',
    importAs: 'imported',
    expected: VALUES
  });
}

// ── Refusals ─────────────────────────────────────────────────────────────────
//
// Each of these must fail. An implementation that returns a value for any of
// them is not conforming - it is handing a caller ciphertext it believes is
// plaintext, or writing a file where it was told to.

const good = encryptValue('secret', USER_KEY, { iterations: ITERATIONS });
const flip = (text, index) => {
  const chars = [...text];
  chars[index] = chars[index] === 'a' ? 'b' : 'a';
  return chars.join('');
};
const parts = good.split(':');

manifest.refusals.tokens = [
  { name: 'wrong-user-key', token: good, userKey: 'the-wrong-key', code: 'BAD_USER_KEY' },
  {
    name: 'tampered-ciphertext',
    token: [...parts.slice(0, 5), flip(parts[5], 0)].join(':'),
    userKey: USER_KEY,
    code: 'BAD_USER_KEY'
  },
  {
    name: 'tampered-auth-tag',
    token: [...parts.slice(0, 4), flip(parts[4], 0), parts[5]].join(':'),
    userKey: USER_KEY,
    code: 'BAD_USER_KEY'
  },
  {
    name: 'edited-iteration-count',
    token: [parts[0], String(ITERATIONS + 1), ...parts.slice(2)].join(':'),
    userKey: USER_KEY,
    code: 'BAD_USER_KEY'
  },
  { name: 'too-few-fields', token: 'skv2:10000:aabb:ccdd', userKey: USER_KEY, code: 'BAD_TOKEN' },
  { name: 'too-many-fields', token: `${good}:extra`, userKey: USER_KEY, code: 'BAD_TOKEN' },
  { name: 'non-numeric-count', token: 'skv2:lots:aa:bb:cc:dd', userKey: USER_KEY, code: 'BAD_TOKEN' },
  { name: 'skv1-too-few-fields', token: 'skv1:aa:bb', userKey: USER_KEY, code: 'BAD_TOKEN' }
];

function writeRefusedBundle(name, content, code, note) {
  const relative = `bundles/refuse-${name}.skb`;
  fs.writeFileSync(path.join(ROOT, relative), content);
  manifest.refusals.bundles.push({ name, path: relative, code, note });
}

writeRefusedBundle('not-json', 'this is not json', 'BAD_BACKUP', 'unparseable');
writeRefusedBundle('not-a-bundle', JSON.stringify({ hello: 'world' }), 'BAD_BACKUP', 'JSON, but not ours');
writeRefusedBundle('no-master', JSON.stringify({
  format: 'secure-keystore-backup', version: 1, storeName: 'x', files: { 'a.enc': '{}' }
}), 'BAD_BACKUP', 'no master.json');
writeRefusedBundle('future-version', JSON.stringify({
  format: 'secure-keystore-backup', version: 99, storeName: 'x', files: { 'master.json': '{}' }
}), 'UNSUPPORTED_FORMAT', 'a bundle format from the future');

// The one that is not merely invalid but hostile: a bundle whose filenames try
// to climb out of the keystore. It must import, and every file must land inside
// the target directory under its base name.
{
  const source = JSON.parse(fs.readFileSync(path.join(ROOT, 'bundles', 'basic.skb'), 'utf8'));
  source.files['../../pwned.txt'] = 'this must not escape';
  source.files['/etc/pwned.txt'] = 'nor this';

  const relative = 'bundles/traversal.skb';
  fs.writeFileSync(path.join(ROOT, relative), JSON.stringify(source));

  manifest.bundles.push({
    name: 'traversal',
    path: relative,
    importAs: 'traversal-target',
    expected: VALUES,
    mustNotCreate: ['pwned.txt'],
    mustCreateInsideStore: ['pwned.txt'],
    note: 'every entry is reduced to its base name before writing'
  });
}

// A store whose format major version is beyond what any current build reads.
{
  const name = 'future-format';
  const storeDir = path.join(ROOT, 'stores', name, name);
  fs.mkdirSync(storeDir, { recursive: true });
  fs.writeFileSync(path.join(storeDir, 'master.json'), JSON.stringify({
    version: '9.0',
    created: '2030-01-01T00:00:00.000Z',
    salt: '00'.repeat(32),
    iterations: ITERATIONS,
    master: { iv: '00'.repeat(12), authTag: '00'.repeat(16), data: '00' },
    entries: [],
    totalKeys: 0
  }, null, 2));

  manifest.refusals.stores.push({
    name,
    keystorePath: `stores/${name}`,
    store: name,
    code: 'UNSUPPORTED_FORMAT',
    note: 'a major version from the future must be refused, not partly read'
  });
}

fs.writeFileSync(
  path.join(__dirname, 'manifest.json'),
  `${JSON.stringify(manifest, null, 2)}\n`
);

console.log(`Wrote ${manifest.stores.length} stores, ${manifest.tokens.length} tokens, ` +
  `${manifest.bundles.length} bundles and ` +
  `${manifest.refusals.tokens.length + manifest.refusals.bundles.length + manifest.refusals.stores.length} refusal cases.`);
console.log(`Corpus: ${path.relative(process.cwd(), ROOT)}`);
