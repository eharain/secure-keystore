'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

// The tests that exist because something once went wrong, or could.
//
// Each one names the property it holds rather than the function it calls: a key
// cannot escape its directory, a wrong password says so, a hand-written bundle
// cannot write outside the keystore.

const { SecureKeystore, ErrorCodes } = require('../src');
const { scratch, writeLegacyStore, KEYS_TXT, USER_KEY } = require('./helpers');

test('the wrong user key is reported as such, not as a GCM message', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  assert.throws(() => s.store.get('api_key', 'wrong-key', 'prod'), error => {
    assert.equal(error.code, ErrorCodes.BAD_USER_KEY);
    assert.match(error.message, /wrong user key for keystore "prod"/);
    // The node message is kept, but underneath, for whoever wants it.
    assert.ok(error.cause);
    return true;
  });
});

test('a key name with path separators cannot escape the store directory', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  const evil = '../../escape:key';
  s.store.set(evil, 'evil_value', USER_KEY, 'prod');

  assert.equal(s.store.get(evil, USER_KEY, 'prod'), 'evil_value');
  assert.ok(!fs.existsSync(path.join(s.dir, 'escape:key')));
  assert.ok(!fs.existsSync(path.join(s.dir, '.keystore', 'escape:key')));

  const files = fs.readdirSync(path.join(s.dir, '.keystore', 'prod'));
  assert.equal(files.filter(file => file.startsWith('.._.._escape_key-')).length, 1);
});

test('two key names that sanitise alike still get separate files', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  s.store.set('a/b', 'first', USER_KEY, 'prod');
  s.store.set('a_b', 'second', USER_KEY, 'prod');

  assert.equal(s.store.get('a/b', USER_KEY, 'prod'), 'first');
  assert.equal(s.store.get('a_b', USER_KEY, 'prod'), 'second');
});

test('a bundle naming a file outside the store cannot write outside it', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');
  const backupPath = s.store.exportStore('prod', path.join(s.dir, 'prod.skb'));

  const bundle = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
  bundle.files['../../pwned.txt'] = 'should not land here';
  fs.writeFileSync(backupPath, JSON.stringify(bundle));

  s.store.importStore(backupPath, 'restored');

  assert.ok(!fs.existsSync(path.join(s.dir, 'pwned.txt')));
  assert.ok(fs.existsSync(path.join(s.dir, '.keystore', 'restored', 'pwned.txt')));
  assert.equal(s.store.get('api_key', USER_KEY, 'restored'), 'sk_test_abc123');
});

test('a file that is not a bundle is refused with a reason', t => {
  const s = scratch();
  t.after(s.cleanup);

  assert.throws(() => s.store.importStore(s.file('nope.skb', 'not json at all')), error => {
    assert.equal(error.code, ErrorCodes.BAD_BACKUP);
    assert.match(error.message, /not readable as JSON/);
    return true;
  });

  assert.throws(() => s.store.importStore(s.file('nope2.skb', '{"hello":"world"}')), /not a keystore bundle/);

  assert.throws(
    () => s.store.importStore(s.file('nope3.skb', JSON.stringify({
      format: 'secure-keystore-backup', version: 1, storeName: 'x', files: { 'a.enc': '{}' }
    }))),
    /master\.json not found/
  );

  assert.throws(() => s.store.importStore(path.join(s.dir, 'missing.skb')), /backup file not found/);
});

test('a bundle from a newer format version is refused rather than half-read', t => {
  const s = scratch();
  t.after(s.cleanup);

  const future = s.file('future.skb', JSON.stringify({
    format: 'secure-keystore-backup',
    version: 99,
    storeName: 'future',
    files: { 'master.json': '{}' }
  }));

  assert.throws(() => s.store.importStore(future), /bundle format 99/);
});

test('two values with identical plaintext do not share bytes on disk', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', 'master:m\nsame_a:identical\nsame_b:identical'), USER_KEY, 'prod');

  const dir = path.join(s.dir, '.keystore', 'prod');
  const [a, b] = fs.readdirSync(dir)
    .filter(file => file.endsWith('.enc'))
    .map(file => JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8')));

  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.data.iv, b.data.iv);
  assert.notEqual(a.data.data, b.data.data);
});

test('no plaintext secret is written anywhere under the keystore', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  const dir = path.join(s.dir, '.keystore');
  const files = [
    path.join(dir, 'index.json'),
    ...fs.readdirSync(path.join(dir, 'prod')).map(file => path.join(dir, 'prod', file))
  ];

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    assert.ok(!content.includes('sk_test_abc123'), `${path.basename(file)} leaked a value`);
    assert.ok(!content.includes('TestMasterKey123'), `${path.basename(file)} leaked the master key`);
    assert.ok(!content.includes(USER_KEY), `${path.basename(file)} leaked the user key`);
  }
});

test('a missing store is STORE_NOT_FOUND, an empty directory is STORE_CORRUPT', t => {
  const s = scratch();
  t.after(s.cleanup);

  assert.throws(() => s.store.listKeys('nope'), error => {
    assert.equal(error.code, ErrorCodes.STORE_NOT_FOUND);
    return true;
  });

  fs.mkdirSync(path.join(s.dir, '.keystore', 'hollow'), { recursive: true });
  assert.throws(() => s.store.listKeys('hollow'), error => {
    assert.equal(error.code, ErrorCodes.STORE_CORRUPT);
    return true;
  });
});

test('a missing key is KEY_NOT_FOUND before any decryption is attempted', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.txt', KEYS_TXT), USER_KEY, 'prod');

  // Wrong user key as well - the key check comes first, so this is not a leak
  // of whether the password was right.
  assert.throws(() => s.store.get('absent', 'wrong-key', 'prod'), error => {
    assert.equal(error.code, ErrorCodes.KEY_NOT_FOUND);
    return true;
  });

  assert.throws(() => s.store.get('absent', USER_KEY), error => {
    assert.equal(error.code, ErrorCodes.KEY_NOT_FOUND);
    assert.match(error.message, /not found in any keystore/);
    return true;
  });
});

test('deleteStore refuses a directory that is not a store', t => {
  const s = scratch();
  t.after(s.cleanup);

  const stranger = path.join(s.dir, '.keystore', 'important-data');
  fs.mkdirSync(stranger, { recursive: true });
  fs.writeFileSync(path.join(stranger, 'notes.txt'), 'do not delete me');

  assert.throws(() => s.store.deleteStore('important-data'), error => {
    assert.equal(error.code, ErrorCodes.STORE_CORRUPT);
    return true;
  });
  assert.ok(fs.existsSync(path.join(stranger, 'notes.txt')));
});

test('a 1.0 store - no version field at all - is still readable', t => {
  const s = scratch();
  t.after(s.cleanup);

  // 1.0 wrote no version field and recorded no iteration count. Both are read
  // as what they were: format 2.0's shape, at 100,000 rounds.
  const storeDir = writeLegacyStore(s.keystoreDir, 'ancient', USER_KEY, 'AncientMaster', [
    { key: 'api_key', value: 'sk_ancient_abc' }
  ], 100000);

  const masterFile = path.join(storeDir, 'master.json');
  const metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));
  delete metadata.version;
  delete metadata.iterations;
  fs.writeFileSync(masterFile, JSON.stringify(metadata, null, 2));

  for (const entry of metadata.entries) {
    const record = JSON.parse(fs.readFileSync(path.join(storeDir, entry.file), 'utf8'));
    delete record.iterations;
    fs.writeFileSync(path.join(storeDir, entry.file), JSON.stringify(record, null, 2));
  }

  const reader = new SecureKeystore({ keystoreDir: s.keystoreDir });
  assert.equal(reader.get('api_key', USER_KEY, 'ancient'), 'sk_ancient_abc');

  const info = reader.getStoreInfo('ancient');
  assert.equal(info.version, '1.0');
  assert.equal(info.current, false);
  assert.equal(info.iterations, 100000);
});
