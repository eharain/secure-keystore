'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

// Format 3.0, and what it fixed.
//
// Three changes, each with a test that would fail on 2.0: a 12-byte IV, a value
// bound to its key name, and a value key derived rather than stretched.

const {
  SecureKeystore,
  ErrorCodes,
  STORE_FORMAT_VERSION,
  STORE_FORMAT_LEGACY,
  ALGORITHMS
} = require('../src');
const { scratch, writeLegacyStore, KEYS_TXT, USER_KEY, FAST } = require('./helpers');

const readRecord = (dir, file) => JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));

test('a new store is written in format 3.0', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  const info = s.store.getStoreInfo('prod');
  assert.equal(info.version, STORE_FORMAT_VERSION);
  assert.equal(info.version, '3.0');
  assert.equal(info.current, true);
});

test('every IV is 12 bytes, which is what the other platforms will accept', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  const dir = path.join(s.keystoreDir, 'prod');
  const metadata = readRecord(dir, 'master.json');

  // 12 bytes is 24 hex characters. .NET's AesGcm accepts this and only this.
  assert.equal(metadata.master.iv.length, 24);
  assert.equal(metadata.master.authTag.length, 32);   // 16-byte tag

  for (const entry of metadata.entries) {
    assert.equal(readRecord(dir, entry.file).data.iv.length, 24);
  }

  assert.equal(ALGORITHMS.ivBytes, 12);
});

test('a value is bound to its key name, so two files cannot be swapped', t => {
  const s = scratch();
  t.after(s.cleanup);

  // This is the 2.0 gap, closed. On 2.0 both reads succeeded and returned each
  // other's values.
  s.store.secure(s.file('keys.txt', 'master:M\nfirst:VALUE_A\nsecond:VALUE_B'), USER_KEY, 'prod');

  const dir = path.join(s.keystoreDir, 'prod');
  const metadata = readRecord(dir, 'master.json');
  const fileFor = name => path.join(dir, metadata.entries.find(entry => entry.key === name).file);

  const a = fs.readFileSync(fileFor('first'));
  const b = fs.readFileSync(fileFor('second'));
  fs.writeFileSync(fileFor('first'), b);
  fs.writeFileSync(fileFor('second'), a);

  for (const key of ['first', 'second']) {
    assert.throws(() => s.store.get(key, USER_KEY, 'prod'), error => {
      assert.equal(error.code, ErrorCodes.BAD_USER_KEY);
      return true;
    }, `swapping ${key} should be refused`);
  }
});

test('the master key is bound to its own context too', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('a.txt', KEYS_TXT), USER_KEY, 'a');
  s.store.secure(s.file('b.txt', KEYS_TXT), USER_KEY, 'b');

  // Lifting store a's encrypted master into store b, salt and all, must fail:
  // the two are separated by context as well as by salt.
  const dirA = path.join(s.keystoreDir, 'a');
  const dirB = path.join(s.keystoreDir, 'b');
  const metaA = readRecord(dirA, 'master.json');
  const metaB = readRecord(dirB, 'master.json');

  metaB.master = metaA.master;
  fs.writeFileSync(path.join(dirB, 'master.json'), JSON.stringify(metaB, null, 2));

  assert.throws(() => s.store.get('api_key', USER_KEY, 'b'), error => {
    assert.equal(error.code, ErrorCodes.BAD_USER_KEY);
    return true;
  });
});

test('a 3.0 value file records no iteration count, because nothing derives from one', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  const dir = path.join(s.keystoreDir, 'prod');
  const metadata = readRecord(dir, 'master.json');

  // The store records the count, because the user key is stretched with it.
  assert.equal(metadata.iterations, FAST);

  // A value does not, because its key comes from HKDF over the master key -
  // which takes no count. Recording one would be writing a number nothing reads.
  for (const entry of metadata.entries) {
    assert.equal(readRecord(dir, entry.file).iterations, undefined);
  }
});

test('reading every value costs one password stretch, not one per value', t => {
  const s = scratch({ iterations: 200000 });
  t.after(s.cleanup);

  // Twelve values at a deliberately expensive count. Under 2.0 this was one
  // full PBKDF2 run per value on the way in and another on the way out; under
  // 3.0 it is one on each side, and HKDF for the rest.
  const many = ['master:M', ...Array.from({ length: 12 }, (_, i) => `key_${i}:value_${i}`)].join('\n');
  s.store.secure(s.file('many.txt', many), USER_KEY, 'prod');

  const started = process.hrtime.bigint();
  const values = s.store.getAll(USER_KEY, 'prod');
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  assert.equal(Object.keys(values).length, 12);
  assert.equal(values.key_7, 'value_7');

  // One 200k stretch is well under a second on any machine that can run node.
  // Thirteen of them would not be. The bound is loose on purpose - this is
  // asserting a complexity class, not a benchmark.
  assert.ok(elapsedMs < 3000, `getAll took ${elapsedMs.toFixed(0)}ms - that looks like one stretch per value`);
});

test('a 2.0 store still opens, and is reported as not current', t => {
  const s = scratch();
  t.after(s.cleanup);

  writeLegacyStore(s.keystoreDir, 'legacy', USER_KEY, 'LegacyMaster', [
    { key: 'api_key', value: 'sk_legacy_abc' },
    { key: 'jwt_secret', value: 'legacy_jwt' }
  ]);

  assert.equal(s.store.get('api_key', USER_KEY, 'legacy'), 'sk_legacy_abc');
  assert.deepEqual(s.store.getAll(USER_KEY, 'legacy'), {
    api_key: 'sk_legacy_abc',
    jwt_secret: 'legacy_jwt'
  });

  const info = s.store.getStoreInfo('legacy');
  assert.equal(info.version, STORE_FORMAT_LEGACY);
  assert.equal(info.current, false);
});

test('a wrong user key on a 2.0 store still says so', t => {
  const s = scratch();
  t.after(s.cleanup);

  writeLegacyStore(s.keystoreDir, 'legacy', USER_KEY, 'LegacyMaster', [
    { key: 'api_key', value: 'sk_legacy_abc' }
  ]);

  assert.throws(() => s.store.get('api_key', 'wrong', 'legacy'), error => {
    assert.equal(error.code, ErrorCodes.BAD_USER_KEY);
    return true;
  });
});

test('writing to a 2.0 store keeps it in 2.0, rather than half-upgrading it', t => {
  const s = scratch();
  t.after(s.cleanup);

  writeLegacyStore(s.keystoreDir, 'legacy', USER_KEY, 'LegacyMaster', [
    { key: 'api_key', value: 'sk_legacy_abc' }
  ]);

  const result = s.store.set('added_later', 'new_value', USER_KEY, 'legacy');
  assert.equal(result.format, STORE_FORMAT_LEGACY);

  // It reads back, and the store is still uniformly 2.0 - a 16-byte IV, and an
  // iteration count on the value record.
  assert.equal(s.store.get('added_later', USER_KEY, 'legacy'), 'new_value');
  assert.equal(s.store.getStoreInfo('legacy').version, STORE_FORMAT_LEGACY);

  const dir = path.join(s.keystoreDir, 'legacy');
  const entry = readRecord(dir, 'master.json').entries.find(e => e.key === 'added_later');
  const record = readRecord(dir, entry.file);
  assert.equal(record.data.iv.length, 32);      // 16 bytes, the 2.0 length
  assert.equal(record.iterations, FAST);
});

test('migrate moves a 2.0 store to 3.0 with every value intact', t => {
  const s = scratch();
  t.after(s.cleanup);

  writeLegacyStore(s.keystoreDir, 'legacy', USER_KEY, 'LegacyMaster', [
    { key: 'api_key', value: 'sk_legacy_abc' },
    { key: 'jwt_secret', value: 'legacy_jwt' },
    { key: 'db_url', value: 'postgres://user:pass@host:5432/db' }
  ]);

  const result = s.store.migrate('legacy', USER_KEY);

  assert.equal(result.from, STORE_FORMAT_LEGACY);
  assert.equal(result.to, STORE_FORMAT_VERSION);
  assert.deepEqual(result.keys, ['api_key', 'jwt_secret', 'db_url']);

  assert.deepEqual(s.store.getAll(USER_KEY, 'legacy'), {
    api_key: 'sk_legacy_abc',
    jwt_secret: 'legacy_jwt',
    db_url: 'postgres://user:pass@host:5432/db'
  });

  const info = s.store.getStoreInfo('legacy');
  assert.equal(info.version, STORE_FORMAT_VERSION);
  assert.equal(info.current, true);

  // And it is really 3.0 on disk, not merely labelled so.
  const dir = path.join(s.keystoreDir, 'legacy');
  const metadata = readRecord(dir, 'master.json');
  assert.equal(metadata.master.iv.length, 24);
  for (const entry of metadata.entries) {
    assert.equal(readRecord(dir, entry.file).data.iv.length, 24);
  }
});

test('a migrated store is bound to its key names, like any other 3.0 store', t => {
  const s = scratch();
  t.after(s.cleanup);

  writeLegacyStore(s.keystoreDir, 'legacy', USER_KEY, 'LegacyMaster', [
    { key: 'first', value: 'VALUE_A' },
    { key: 'second', value: 'VALUE_B' }
  ]);
  s.store.migrate('legacy', USER_KEY);

  const dir = path.join(s.keystoreDir, 'legacy');
  const metadata = readRecord(dir, 'master.json');
  const fileFor = name => path.join(dir, metadata.entries.find(entry => entry.key === name).file);

  const a = fs.readFileSync(fileFor('first'));
  fs.writeFileSync(fileFor('first'), fs.readFileSync(fileFor('second')));
  fs.writeFileSync(fileFor('second'), a);

  assert.throws(() => s.store.get('first', USER_KEY, 'legacy'), /could not decrypt|wrong user key/);
});

test('migrate on a current store re-encrypts it at the new iteration count', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  assert.equal(s.store.getStoreInfo('prod').iterations, FAST);

  const stronger = new SecureKeystore({ keystoreDir: s.keystoreDir, iterations: 50000 });
  const result = stronger.migrate('prod', USER_KEY);

  assert.equal(result.from, STORE_FORMAT_VERSION);
  assert.equal(result.to, STORE_FORMAT_VERSION);
  assert.equal(result.iterations, 50000);
  assert.equal(stronger.getStoreInfo('prod').iterations, 50000);
  assert.equal(stronger.get('api_key', USER_KEY, 'prod'), 'sk_test_abc123');
});

test('migrate leaves the store untouched when the user key is wrong', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  const before = fs.readFileSync(path.join(s.keystoreDir, 'prod', 'master.json'), 'utf8');

  assert.throws(() => s.store.migrate('prod', 'wrong-key'), error => {
    assert.equal(error.code, ErrorCodes.BAD_USER_KEY);
    return true;
  });

  assert.equal(fs.readFileSync(path.join(s.keystoreDir, 'prod', 'master.json'), 'utf8'), before);
  assert.equal(s.store.get('api_key', USER_KEY, 'prod'), 'sk_test_abc123');
});

test('migrate leaves no orphaned value files behind', t => {
  const s = scratch();
  t.after(s.cleanup);

  writeLegacyStore(s.keystoreDir, 'legacy', USER_KEY, 'LegacyMaster', [
    { key: 'api_key', value: 'a' },
    { key: 'jwt_secret', value: 'b' }
  ]);
  s.store.migrate('legacy', USER_KEY);

  const files = fs.readdirSync(path.join(s.keystoreDir, 'legacy'));
  assert.equal(files.filter(file => file.endsWith('.enc')).length, 2);
});

test('a store from a newer major format is refused, not partly read', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  const masterFile = path.join(s.keystoreDir, 'prod', 'master.json');
  const metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));
  metadata.version = '9.0';
  fs.writeFileSync(masterFile, JSON.stringify(metadata, null, 2));

  assert.throws(() => s.store.get('api_key', USER_KEY, 'prod'), error => {
    assert.equal(error.code, ErrorCodes.UNSUPPORTED_FORMAT);
    assert.match(error.message, /format 9\.0/);
    return true;
  });
});

test('the default iteration count follows current guidance', () => {
  const { defaultOptions } = require('../src');
  assert.equal(defaultOptions().iterations, 600000);
  assert.equal(ALGORITHMS.defaultIterations, 600000);
  assert.equal(ALGORITHMS.passwordKdf, 'pbkdf2-hmac-sha256');
  assert.equal(ALGORITHMS.keyKdf, 'hkdf-sha256');
  assert.equal(ALGORITHMS.bindsKeyName, true);
});
