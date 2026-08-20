'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { SecureKeystore, ErrorCodes, KeystoreError, VERSION, STORE_FORMAT_VERSION } = require('../src');
const { scratch, KEYS_TXT, USER_KEY, FAST } = require('./helpers');

test('secure then get returns the value that went in', t => {
  const s = scratch();
  t.after(s.cleanup);

  const result = s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  assert.equal(result.storeName, 'prod');
  assert.equal(result.totalKeys, 3);
  assert.deepEqual(result.keys, ['api_key', 'jwt_secret', 'db_url']);
  assert.equal(s.store.get('api_key', USER_KEY, 'prod'), 'sk_test_abc123');
});

test('a value keeps every colon it arrived with', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  assert.equal(s.store.get('db_url', USER_KEY, 'prod'), 'postgres://user:pass@host:5432/db');
});

test('the store name defaults to the input file name', t => {
  const s = scratch();
  t.after(s.cleanup);

  const result = s.store.secure(s.file('staging.txt', KEYS_TXT), USER_KEY);
  assert.equal(result.storeName, 'staging');
  assert.deepEqual(s.store.listStores(), ['staging']);
});

test('get with no store name searches every store', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  assert.equal(s.store.get('api_key', USER_KEY), 'sk_test_abc123');
});

test('getAll returns every value in the store', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  assert.deepEqual(s.store.getAll(USER_KEY, 'prod'), {
    api_key: 'sk_test_abc123',
    jwt_secret: 'test_secret_xyz',
    db_url: 'postgres://user:pass@host:5432/db'
  });
});

test('set adds a key, and says it added one', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  const result = s.store.set('new_key', 'new_value', USER_KEY, 'prod');
  assert.equal(result.added, true);
  assert.equal(s.store.get('new_key', USER_KEY, 'prod'), 'new_value');
  assert.equal(s.store.getStoreInfo('prod').totalKeys, 4);
});

test('set replaces an existing value without adding an entry', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  const result = s.store.set('api_key', 'rotated', USER_KEY, 'prod');
  assert.equal(result.added, false);
  assert.equal(s.store.get('api_key', USER_KEY, 'prod'), 'rotated');
  assert.equal(s.store.listKeys('prod').filter(key => key === 'api_key').length, 1);
});

test('deleteKey removes both the entry and its file', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  const before = fs.readdirSync(path.join(s.dir, '.keystore', 'prod')).length;

  s.store.deleteKey('api_key', 'prod');

  assert.ok(!s.store.listKeys('prod').includes('api_key'));
  assert.equal(fs.readdirSync(path.join(s.dir, '.keystore', 'prod')).length, before - 1);
});

test('re-securing a store leaves no orphaned value files behind', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  s.store.secure(s.file('fewer.txt', 'master:TestMasterKey123\nonly_key:only_value'), USER_KEY, 'prod');

  const files = fs.readdirSync(path.join(s.dir, '.keystore', 'prod'));
  assert.deepEqual(s.store.listKeys('prod'), ['only_key']);
  assert.equal(files.filter(file => file.endsWith('.enc')).length, 1);
});

test('listKeys and getStoreInfo need no user key', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  assert.deepEqual(s.store.listKeys('prod'), ['api_key', 'jwt_secret', 'db_url']);

  const info = s.store.getStoreInfo('prod');
  assert.equal(info.name, 'prod');
  assert.equal(info.version, STORE_FORMAT_VERSION);
  assert.equal(info.totalKeys, 3);
  assert.equal(info.sourceFile, 'keys.txt');
  assert.equal(info.iterations, FAST);
});

test('listStores ignores a directory that is not a store', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  fs.mkdirSync(path.join(s.dir, '.keystore', 'not-a-store'));

  assert.deepEqual(s.store.listStores(), ['prod']);
});

test('export and import round-trip a store into a new name', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  const backup = s.store.exportStore('prod', path.join(s.dir, 'prod.skb'));

  assert.ok(fs.existsSync(backup));
  assert.equal(s.store.importStore(backup, 'restored'), 'restored');
  assert.equal(s.store.get('api_key', USER_KEY, 'restored'), 'sk_test_abc123');
});

test('an imported store carries its own name when none is given', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  const backup = s.store.exportStore('prod', path.join(s.dir, 'prod.skb'));
  s.store.deleteStore('prod');

  assert.equal(s.store.importStore(backup), 'prod');
  assert.equal(s.store.get('api_key', USER_KEY, 'prod'), 'sk_test_abc123');
});

test('deleteStore removes the directory and the index entry', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  s.store.deleteStore('prod');

  assert.deepEqual(s.store.listStores(), []);
  const index = JSON.parse(fs.readFileSync(path.join(s.dir, '.keystore', 'index.json'), 'utf8'));
  assert.ok(!('prod' in index.stores));
});

test('the library prints nothing unless it is given a logger', t => {
  const s = scratch();
  t.after(s.cleanup);

  const lines = [];
  const talkative = new SecureKeystore({
    keystoreDir: path.join(s.dir, '.keystore-2'),
    logger: message => lines.push(message)
  });

  talkative.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  assert.equal(lines.length, 1);
  assert.match(lines[0], /Secured 3 keys/);

  // The default instance in `scratch` has no logger, and must stay silent.
  const before = lines.length;
  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  assert.equal(lines.length, before);
});

test('options are validated at construction, not at first use', () => {
  assert.throws(() => new SecureKeystore({ iterations: 10 }), error => {
    assert.ok(error instanceof KeystoreError);
    assert.equal(error.code, ErrorCodes.INVALID_OPTIONS);
    return true;
  });

  assert.throws(() => new SecureKeystore({ keystoreDirectory: '/tmp/typo' }), error => {
    assert.equal(error.code, ErrorCodes.INVALID_OPTIONS);
    assert.match(error.message, /unknown option: keystoreDirectory/);
    return true;
  });

  assert.throws(() => new SecureKeystore({ logger: 'stdout' }), /logger must be a function/);
});

test('a raised iteration count is recorded, and the store still reads back', t => {
  const s = scratch({ iterations: 150000 });
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  assert.equal(s.store.getStoreInfo('prod').iterations, 150000);
  assert.equal(s.store.get('api_key', USER_KEY, 'prod'), 'sk_test_abc123');

  // A reader on the defaults must follow what the store recorded, not its own
  // option - which is the whole point of writing the count down.
  const defaults = new SecureKeystore({ keystoreDir: s.store.keystoreDir });
  assert.equal(defaults.get('api_key', USER_KEY, 'prod'), 'sk_test_abc123');
});

test('VERSION is the implementation version, not the format version', () => {
  assert.match(VERSION, /^\d+\.\d+\.\d+$/);
  assert.equal(STORE_FORMAT_VERSION, '3.0');
});
