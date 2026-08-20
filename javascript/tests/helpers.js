'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// A temporary keystore per test, so nothing a test writes can be seen by
// another one and no test depends on the order it runs in.

const { SecureKeystore } = require('../src');

/**
 * Test iteration count.
 *
 * The real default is 600,000, which is the point of it - but at 600,000 a
 * suite that opens fifty stores spends most of a minute inside PBKDF2. Tests
 * that care about the default assert it directly; everything else runs at the
 * floor.
 */
const FAST = 10000;

/**
 * Makes a scratch directory, a keystore inside it, and a cleanup function.
 *
 * @returns {{dir: string, store: SecureKeystore, file: Function, keystoreDir: string, cleanup: Function}}
 */
function scratch(options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-keystore-test-'));
  const keystoreDir = path.join(dir, '.keystore');
  const store = new SecureKeystore({ keystoreDir, iterations: FAST, ...options });

  return {
    dir,
    keystoreDir,
    store,
    /** Writes a file into the scratch directory and returns its path. */
    file(name, content) {
      const target = path.join(dir, name);
      fs.writeFileSync(target, content);
      return target;
    },
    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}

/**
 * Writes a store exactly as version 2.0 wrote one.
 *
 * Hand-rolled rather than produced by an old build, because there is no old
 * build to run - and because writing it out here is the clearest statement of
 * what 2.0 actually was: a 16-byte IV, no additional authenticated data, and
 * PBKDF2 over the master key for every value.
 *
 * @returns {string} the store directory
 */
function writeLegacyStore(keystoreDir, storeName, userKey, masterKey, entries, iterations = FAST) {
  const storeDir = path.join(keystoreDir, storeName);
  fs.mkdirSync(storeDir, { recursive: true });

  const legacyEncrypt = (plaintext, key) => {
    const iv = crypto.randomBytes(16);                    // 2.0 used 16, not 12
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    // No setAAD - 2.0 bound nothing.
    let data = cipher.update(String(plaintext), 'utf8', 'hex');
    data += cipher.final('hex');
    return { iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex'), data };
  };

  const storeSalt = crypto.randomBytes(32);
  const userDerived = crypto.pbkdf2Sync(userKey, storeSalt, iterations, 32, 'sha256');

  const written = entries.map(({ key, value }) => {
    const valueSalt = crypto.randomBytes(32);
    // 2.0 stretched the master key, at full cost, once per value.
    const valueKey = crypto.pbkdf2Sync(masterKey, valueSalt, iterations, 32, 'sha256');
    const stem = String(key).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64);
    const hash = crypto.createHash('sha256').update(String(key), 'utf8').digest('hex').slice(0, 8);
    const file = `${stem}-${hash}.enc`;

    fs.writeFileSync(path.join(storeDir, file), JSON.stringify({
      salt: valueSalt.toString('hex'),
      iterations,
      data: legacyEncrypt(value, valueKey)
    }, null, 2));

    return { key, file };
  });

  fs.writeFileSync(path.join(storeDir, 'master.json'), JSON.stringify({
    version: '2.0',
    created: '2026-01-01T00:00:00.000Z',
    salt: storeSalt.toString('hex'),
    iterations,
    master: legacyEncrypt(masterKey, userDerived),
    entries: written,
    sourceFile: 'legacy.env',
    totalKeys: written.length
  }, null, 2));

  return storeDir;
}

/** The colon-format input every test that needs one starts from. */
const KEYS_TXT = [
  'master:TestMasterKey123',
  'api_key:sk_test_abc123',
  'jwt_secret:test_secret_xyz',
  'db_url:postgres://user:pass@host:5432/db'
].join('\n');

const USER_KEY = 'testUser123!@#';

module.exports = { scratch, writeLegacyStore, KEYS_TXT, USER_KEY, FAST };
