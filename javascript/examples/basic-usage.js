'use strict';

// The shortest useful thing: secure a file, read one key back, read them all.
//
//   node examples/basic-usage.js
//
// It writes to a scratch directory and removes it afterwards, so running it
// leaves nothing behind.

const fs = require('fs');
const os = require('os');
const path = require('path');

const { SecureKeystore } = require('../src');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-keystore-example-'));
const userKey = 'a-long-random-user-key';   // in real life: process.env.USER_KEY

// `logger` is how the library talks. Without one it says nothing at all, which
// is what a server wants and what this example does not.
const store = new SecureKeystore({
  keystoreDir: path.join(dir, '.keystore'),
  logger: message => console.log(`  ${message}`)
});

try {
  const keysFile = path.join(dir, 'keys.env');
  fs.writeFileSync(keysFile, [
    'master=MySuperSecretMasterKey123',
    'api_key=sk_live_abc123def456',
    'jwt_secret=eyJhbGciOiJIUzI1NiJ9',
    'db_url=postgres://user:pass@localhost:5432/app'
  ].join('\n'));

  console.log('Securing:');
  const result = store.secure(keysFile, userKey, 'production');
  console.log(`  keys: ${result.keys.join(', ')}\n`);

  // Delete the plaintext as soon as the store exists. It has served its purpose.
  fs.unlinkSync(keysFile);

  console.log('Reading one value:');
  console.log(`  api_key = ${store.get('api_key', userKey, 'production')}\n`);

  console.log('Reading them all:');
  for (const [key, value] of Object.entries(store.getAll(userKey, 'production'))) {
    console.log(`  ${key} = ${value}`);
  }

  console.log('\nWhat is knowable without the user key:');
  const info = store.getStoreInfo('production');
  console.log(`  stores:     ${store.listStores().join(', ')}`);
  console.log(`  keys:       ${info.keys.join(', ')}`);
  console.log(`  format:     ${info.version}, ${info.iterations} PBKDF2 rounds`);
  console.log('  values:     not without the user key\n');

  console.log('Adding and rotating:');
  store.set('new_key', 'new_value', userKey, 'production');
  store.set('api_key', 'sk_live_rotated', userKey, 'production');
  console.log(`  api_key = ${store.get('api_key', userKey, 'production')}\n`);

  console.log('The wrong user key:');
  try {
    store.get('api_key', 'not-the-right-key', 'production');
  } catch (error) {
    console.log(`  ${error.code}: ${error.message}`);
  }
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
