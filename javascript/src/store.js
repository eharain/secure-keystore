'use strict';

const fs = require('fs');
const path = require('path');

const {
  STORE_FORMAT_VERSION,
  STORE_FORMAT_LEGACY,
  STORE_SALT_LENGTH,
  VALUE_SALT_LENGTH,
  LEGACY_KDF_ITERATIONS,
  IV_LENGTH,
  IV_LENGTH_LEGACY,
  CONTEXT_MASTER,
  valueContext,
  ENCODING,
  INDEX_FILE,
  MASTER_FILE,
  VALUE_EXTENSION,
  DEFAULT_BACKUP_EXTENSION
} = require('./constants');
const { resolveOptions } = require('./options');
const { KeystoreError, ErrorCodes } = require('./errors');
const {
  randomSalt,
  stretchPassword,
  deriveFromKey,
  encrypt,
  decrypt,
  safeFileName
} = require('./crypto');
const { parseInput } = require('./parse');
const { buildBundle, readBundle, writeBundle } = require('./backup');
const { encryptValue, decryptValue } = require('./value');

// The store: a directory, and the operations on it.
//
// Two layers of encryption, and it is worth being precise about what the second
// one buys. A user key unlocks the master key; the master key unlocks each
// value. That is not defence in depth against a leaked user key - anyone
// holding the user key reaches everything - it is what lets every value carry
// its own salt and its own derived key, so no two values on disk share any
// material and re-keying one value touches one file.
//
// The user key is a password and is stretched like one. The master key is not:
// it is already a strong secret, so values are derived from it with HKDF, which
// is fast. Format 2.0 stretched the master key too, at full cost, once per
// value - which is why `getAll` on a large store used to take seconds.
//
// The on-disk format is specified in SPEC.md at the root of the repository.
// This build writes 3.0 and reads both 3.0 and 2.0. A store is never half one
// and half the other: writing to a 2.0 store keeps writing 2.0 records until
// `migrate` moves the whole thing across.

/** Reads and parses a store's master.json, or says which of the two is missing. */
function readMetadata(storeDir, storeName) {
  if (!fs.existsSync(storeDir)) {
    throw new KeystoreError(ErrorCodes.STORE_NOT_FOUND, `keystore "${storeName}" not found`);
  }

  const masterFile = path.join(storeDir, MASTER_FILE);
  if (!fs.existsSync(masterFile)) {
    throw new KeystoreError(
      ErrorCodes.STORE_CORRUPT,
      `keystore "${storeName}" has no ${MASTER_FILE} - the directory exists but is not a store`
    );
  }

  let metadata;
  try {
    metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));
  } catch (cause) {
    throw new KeystoreError(
      ErrorCodes.STORE_CORRUPT,
      `${MASTER_FILE} in keystore "${storeName}" is not readable JSON`,
      { cause }
    );
  }

  const major = String(formatOf(metadata)).split('.')[0];
  if (Number(major) > Number(String(STORE_FORMAT_VERSION).split('.')[0])) {
    throw new KeystoreError(
      ErrorCodes.UNSUPPORTED_FORMAT,
      `keystore "${storeName}" is in format ${metadata.version}, and this build reads up to ${STORE_FORMAT_VERSION}`
    );
  }

  return metadata;
}

function writeMetadata(storeDir, metadata) {
  metadata.updated = new Date().toISOString();
  fs.writeFileSync(path.join(storeDir, MASTER_FILE), JSON.stringify(metadata, null, 2));
}

/**
 * The store format a metadata document is in.
 *
 * Absent means 1.0, which is the same on-disk shape as 2.0 - 2.0 only added
 * optional fields - so both take the legacy path.
 */
function formatOf(metadata) {
  return metadata.version || '1.0';
}

/** True if this store predates format 3.0. */
function isLegacy(metadata) {
  return Number(String(formatOf(metadata)).split('.')[0]) < 3;
}

/**
 * The iteration count a store was written with.
 *
 * Absent means it was written before the count was recorded, and every version
 * that did so used exactly LEGACY_KDF_ITERATIONS. Assuming here is safe because
 * a wrong assumption derives a wrong key and GCM refuses it - it cannot decrypt
 * to the wrong answer.
 */
function iterationsOf(record) {
  return Number.isInteger(record.iterations) ? record.iterations : LEGACY_KDF_ITERATIONS;
}

/** The encryption parameters a store's format calls for. */
function shapeOf(metadata) {
  return isLegacy(metadata)
    ? { ivLength: IV_LENGTH_LEGACY, bindContext: false }
    : { ivLength: IV_LENGTH, bindContext: true };
}

/** Stretches the user key and decrypts the store's master key with it. */
function unlockMaster(metadata, userKey, storeName) {
  if (!userKey) {
    throw new KeystoreError(ErrorCodes.INVALID_ARGUMENT, 'a userKey is required to read this store');
  }

  const salt = Buffer.from(metadata.salt, ENCODING);
  const userDerivedKey = stretchPassword(userKey, salt, iterationsOf(metadata));

  try {
    return decrypt(metadata.master, userDerivedKey, {
      aad: shapeOf(metadata).bindContext ? CONTEXT_MASTER : null,
      what: 'master key'
    });
  } catch (error) {
    if (error.code === ErrorCodes.BAD_USER_KEY) {
      throw new KeystoreError(
        ErrorCodes.BAD_USER_KEY,
        `wrong user key for keystore "${storeName}"`,
        { cause: error.cause }
      );
    }
    throw error;
  }
}

/**
 * The key one value is encrypted under.
 *
 * In 3.0 that is HKDF from the master key, with the value's salt and a context
 * naming the key - so a value file moved to another key's name derives a
 * different key entirely. In 2.0 it was PBKDF2 over the master key, at the
 * store's full iteration count, with nothing binding it to the name.
 */
function valueKey(masterKey, salt, keyName, metadata, record) {
  return isLegacy(metadata)
    ? stretchPassword(masterKey, salt, iterationsOf(record))
    : deriveFromKey(masterKey, salt, valueContext(keyName));
}

/** Reads and decrypts one value file, given the store's master key. */
function readValue(storeDir, entry, masterKey, metadata) {
  const valueFile = path.join(storeDir, entry.file);
  if (!fs.existsSync(valueFile)) {
    throw new KeystoreError(
      ErrorCodes.STORE_CORRUPT,
      `key "${entry.key}" is listed in ${MASTER_FILE} but its file ${entry.file} is missing`
    );
  }

  const record = JSON.parse(fs.readFileSync(valueFile, 'utf8'));
  const key = valueKey(masterKey, Buffer.from(record.salt, ENCODING), entry.key, metadata, record);

  return decrypt(record.data, key, {
    aad: shapeOf(metadata).bindContext ? valueContext(entry.key) : null,
    what: `value for "${entry.key}"`
  });
}

/** Encrypts one value under a fresh salt and writes its file. */
function writeValue(storeDir, fileName, keyName, value, masterKey, metadata) {
  const salt = randomSalt(VALUE_SALT_LENGTH);
  const shape = shapeOf(metadata);
  const record = { salt: salt.toString(ENCODING) };

  // The iteration count only means anything to a 2.0 value, where the value key
  // is stretched from the master key. A 3.0 value derives with HKDF, which
  // takes no count, so writing one would be recording a number nothing reads.
  if (isLegacy(metadata)) record.iterations = iterationsOf(metadata);

  const key = valueKey(masterKey, salt, keyName, metadata, record);
  record.data = encrypt(value, key, {
    ivLength: shape.ivLength,
    aad: shape.bindContext ? valueContext(keyName) : null
  });

  fs.writeFileSync(path.join(storeDir, fileName), JSON.stringify(record, null, 2));
}

/**
 * A secure key-value store backed by a directory.
 *
 * One instance binds one keystore directory and one set of options, validated
 * once here rather than on every call. It holds no secret of its own - the user
 * key is passed to each operation that needs it and is never retained - so an
 * instance built at start-up is safe to keep for the life of the process.
 *
 *   const store = new SecureKeystore({ keystoreDir: '/var/lib/app/keys' });
 *   const apiKey = store.get('api_key', process.env.USER_KEY, 'production');
 */
class SecureKeystore {
  /**
   * @param {object} [options]
   * @param {string} [options.keystoreDir]   where stores live. Default `./.keystore`.
   * @param {number} [options.iterations]    PBKDF2 rounds for new stores. Default 600,000.
   * @param {Function|null} [options.logger] called with one line of progress. Default null - silent.
   * @param {boolean} [options.createDir]    create the keystore directory if absent. Default true.
   */
  constructor(options = {}) {
    this.options = resolveOptions(options);
    this.keystoreDir = this.options.keystoreDir;

    if (this.options.createDir && !fs.existsSync(this.keystoreDir)) {
      fs.mkdirSync(this.keystoreDir, { recursive: true });
    }
  }

  /**
   * Encrypts a key-value file into a store, in format 3.0.
   *
   * The input format follows the extension: `.json` an object, `.env` dotenv
   * lines, anything else `key:value` lines with `master:` first. The store name
   * defaults to the input file's base name.
   *
   * Re-securing an existing store replaces it, in 3.0 whatever it was before -
   * the store is being rewritten from scratch, so there is nothing to preserve.
   * The old `.enc` files go first, so a key dropped from the input does not
   * linger on disk as an encrypted orphan that nothing references any more.
   *
   * @returns {{storeName: string, storeDir: string, totalKeys: number, keys: string[]}}
   */
  secure(inputFile, userKey, storeName = null) {
    if (!userKey) {
      throw new KeystoreError(ErrorCodes.INVALID_ARGUMENT, 'secure requires a userKey');
    }

    const { masterKey, entries } = parseInput(inputFile);
    if (!masterKey) {
      throw new KeystoreError(
        ErrorCodes.BAD_INPUT,
        'input must define a master key (e.g. "master:..." in .txt, ' +
        '"master=..." in .env, or a "master" property in .json)'
      );
    }
    if (entries.length === 0) {
      throw new KeystoreError(ErrorCodes.BAD_INPUT, 'no key-value entries found in input file');
    }

    if (!storeName) {
      storeName = path.basename(inputFile, path.extname(inputFile));
    }

    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    } else {
      for (const file of fs.readdirSync(storeDir)) {
        if (file.endsWith(VALUE_EXTENSION) || file === MASTER_FILE) {
          fs.unlinkSync(path.join(storeDir, file));
        }
      }
    }

    const { iterations } = this.options;
    const storeSalt = randomSalt(STORE_SALT_LENGTH);
    const userDerivedKey = stretchPassword(userKey, storeSalt, iterations);

    const metadata = {
      version: STORE_FORMAT_VERSION,
      created: new Date().toISOString(),
      salt: storeSalt.toString(ENCODING),
      iterations,
      master: encrypt(masterKey, userDerivedKey, { ivLength: IV_LENGTH, aad: CONTEXT_MASTER }),
      entries: [],
      sourceFile: path.basename(inputFile),
      totalKeys: entries.length
    };

    metadata.entries = entries.map(entry => {
      const file = safeFileName(entry.key);
      writeValue(storeDir, file, entry.key, entry.value, masterKey, metadata);
      return { key: entry.key, file };
    });

    writeMetadata(storeDir, metadata);
    this._updateIndex(storeName, metadata);
    this._log(`Secured ${entries.length} keys in keystore "${storeName}" at ${storeDir}`);

    return {
      storeName,
      storeDir,
      totalKeys: entries.length,
      keys: entries.map(entry => entry.key)
    };
  }

  /**
   * Decrypts and returns one value.
   *
   * With no store name, every store is searched. That is a convenience for a
   * single-store setup and a trap for a multi-store one, where two stores may
   * hold the same key name and the first match wins - name the store when it
   * matters.
   */
  get(key, userKey, storeName = null) {
    if (!storeName) {
      storeName = this._findStoreForKey(key);
      if (!storeName) {
        throw new KeystoreError(ErrorCodes.KEY_NOT_FOUND, `key "${key}" not found in any keystore`);
      }
    }

    const storeDir = path.join(this.keystoreDir, storeName);
    const metadata = readMetadata(storeDir, storeName);

    const entry = metadata.entries.find(candidate => candidate.key === key);
    if (!entry) {
      throw new KeystoreError(
        ErrorCodes.KEY_NOT_FOUND,
        `key "${key}" not found in keystore "${storeName}"`
      );
    }

    return readValue(storeDir, entry, unlockMaster(metadata, userKey, storeName), metadata);
  }

  /**
   * Decrypts every value in a store into a plain object.
   *
   * The user key is stretched once, not once per value, so this costs one
   * PBKDF2 derivation however many keys the store holds.
   */
  getAll(userKey, storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    const metadata = readMetadata(storeDir, storeName);
    const masterKey = unlockMaster(metadata, userKey, storeName);

    const values = {};
    for (const entry of metadata.entries) {
      values[entry.key] = readValue(storeDir, entry, masterKey, metadata);
    }
    return values;
  }

  /**
   * Adds a key, or replaces the value of one already there.
   *
   * The replacement gets a fresh salt and a fresh IV, so an observer who kept
   * the old file learns nothing by comparing it with the new one.
   *
   * On a store still in format 2.0 this writes a 2.0 record, so the store stays
   * internally consistent. Run `migrate` to move the whole store to 3.0.
   *
   * @returns {{key: string, storeName: string, added: boolean, format: string}}
   */
  set(key, value, userKey, storeName) {
    if (key === undefined || key === null || key === '') {
      throw new KeystoreError(ErrorCodes.INVALID_ARGUMENT, 'set requires a key');
    }

    const storeDir = path.join(this.keystoreDir, storeName);
    const metadata = readMetadata(storeDir, storeName);
    const masterKey = unlockMaster(metadata, userKey, storeName);

    const existing = metadata.entries.find(entry => entry.key === key);
    const file = existing ? existing.file : safeFileName(key);

    writeValue(storeDir, file, key, value, masterKey, metadata);

    if (!existing) {
      metadata.entries.push({ key, file });
      metadata.totalKeys = metadata.entries.length;
    }

    writeMetadata(storeDir, metadata);
    this._updateIndex(storeName, metadata);
    this._log(`Key "${key}" ${existing ? 'updated' : 'added'} in keystore "${storeName}"`);

    return { key, storeName, added: !existing, format: formatOf(metadata) };
  }

  /**
   * Rewrites a whole store in the current format.
   *
   * Every value is decrypted with the old parameters and re-encrypted with the
   * new ones, under a fresh store salt and fresh per-value salts. The master
   * key itself does not change, so nothing outside the store has to be told.
   *
   * Already-current stores are re-encrypted too rather than skipped, which is
   * what makes this the way to raise a store's iteration count as well as its
   * format.
   *
   * The rewrite is not atomic. It writes every new value file before touching
   * master.json, so an interruption leaves the store readable in its old
   * format - but export first anyway.
   *
   * @returns {{storeName: string, from: string, to: string, keys: string[], iterations: number}}
   */
  migrate(storeName, userKey) {
    const storeDir = path.join(this.keystoreDir, storeName);
    const metadata = readMetadata(storeDir, storeName);
    const from = formatOf(metadata);

    // Decrypt everything up front. If any value fails, the store is untouched.
    const masterKey = unlockMaster(metadata, userKey, storeName);
    const values = metadata.entries.map(entry => ({
      key: entry.key,
      value: readValue(storeDir, entry, masterKey, metadata)
    }));

    const { iterations } = this.options;
    const storeSalt = randomSalt(STORE_SALT_LENGTH);
    const userDerivedKey = stretchPassword(userKey, storeSalt, iterations);

    const rewritten = {
      ...metadata,
      version: STORE_FORMAT_VERSION,
      salt: storeSalt.toString(ENCODING),
      iterations,
      master: encrypt(masterKey, userDerivedKey, { ivLength: IV_LENGTH, aad: CONTEXT_MASTER }),
      entries: values.map(({ key }) => ({ key, file: safeFileName(key) })),
      totalKeys: values.length,
      migrated: new Date().toISOString()
    };

    // Value files first: an interruption here leaves master.json describing the
    // old records, which are still on disk under the same names.
    const stale = new Set(fs.readdirSync(storeDir).filter(file => file.endsWith(VALUE_EXTENSION)));
    for (const [index, { key, value }] of values.entries()) {
      const { file } = rewritten.entries[index];
      writeValue(storeDir, file, key, value, masterKey, rewritten);
      stale.delete(file);
    }

    writeMetadata(storeDir, rewritten);
    for (const file of stale) fs.unlinkSync(path.join(storeDir, file));

    this._updateIndex(storeName, rewritten);
    this._log(from === STORE_FORMAT_VERSION
      ? `Keystore "${storeName}" re-encrypted in format ${STORE_FORMAT_VERSION} at ${iterations} iterations`
      : `Keystore "${storeName}" migrated from format ${from} to ${STORE_FORMAT_VERSION}`);

    return {
      storeName,
      from,
      to: STORE_FORMAT_VERSION,
      keys: values.map(({ key }) => key),
      iterations
    };
  }

  /** Removes one key and its encrypted file. */
  deleteKey(key, storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    const metadata = readMetadata(storeDir, storeName);

    const index = metadata.entries.findIndex(entry => entry.key === key);
    if (index === -1) {
      throw new KeystoreError(
        ErrorCodes.KEY_NOT_FOUND,
        `key "${key}" not found in keystore "${storeName}"`
      );
    }

    const [removed] = metadata.entries.splice(index, 1);
    const valueFile = path.join(storeDir, removed.file);
    if (fs.existsSync(valueFile)) {
      fs.unlinkSync(valueFile);
    }

    metadata.totalKeys = metadata.entries.length;
    writeMetadata(storeDir, metadata);
    this._updateIndex(storeName, metadata);
    this._log(`Key "${key}" deleted from keystore "${storeName}"`);

    return { key, storeName };
  }

  /**
   * The names of every store under this keystore directory.
   *
   * A directory counts as a store only if it holds a master.json, so an
   * unrelated directory sitting alongside is not reported as one.
   */
  listStores() {
    if (!fs.existsSync(this.keystoreDir)) return [];
    return fs.readdirSync(this.keystoreDir)
      .filter(name => fs.existsSync(path.join(this.keystoreDir, name, MASTER_FILE)));
  }

  /**
   * The key names in a store.
   *
   * No user key, and none is needed: names live in metadata in the clear. That
   * is a deliberate trade - it is what makes `secure-keystore stores` useful
   * without a password - and it means a key name must not itself be a secret.
   */
  listKeys(storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    return readMetadata(storeDir, storeName).entries.map(entry => entry.key);
  }

  /** Everything about a store that can be known without decrypting anything. */
  getStoreInfo(storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    const metadata = readMetadata(storeDir, storeName);

    return {
      name: storeName,
      path: storeDir,
      version: formatOf(metadata),
      current: !isLegacy(metadata),
      created: metadata.created,
      updated: metadata.updated || metadata.created,
      iterations: iterationsOf(metadata),
      totalKeys: metadata.totalKeys,
      keys: metadata.entries.map(entry => entry.key),
      sourceFile: metadata.sourceFile
    };
  }

  /**
   * Writes a store to a single portable bundle, `.skb` by default.
   *
   * The contents are already encrypted, so the bundle is safe to move through a
   * CI artifact store or an scp. It is pure JavaScript - no `tar`, no shell - so
   * it behaves the same on Windows as anywhere else.
   *
   * @returns {string} the path written
   */
  exportStore(storeName, backupPath = null) {
    const storeDir = path.join(this.keystoreDir, storeName);
    readMetadata(storeDir, storeName);   // refuse early if it is not a store

    if (!backupPath) {
      const stamp = Date.now();
      backupPath = path.join(process.cwd(), `${storeName}-backup-${stamp}${DEFAULT_BACKUP_EXTENSION}`);
    }

    fs.writeFileSync(backupPath, JSON.stringify(buildBundle(storeDir, storeName)));
    this._log(`Store "${storeName}" exported to ${backupPath}`);

    return backupPath;
  }

  /**
   * Restores a bundle, under its own name or a new one.
   *
   * @returns {string} the store name it was imported as
   */
  importStore(backupPath, storeName = null) {
    const bundle = readBundle(backupPath);

    const targetName = storeName || bundle.storeName;
    if (!targetName) {
      throw new KeystoreError(
        ErrorCodes.BAD_BACKUP,
        'cannot determine a target store name: the bundle names none and none was given'
      );
    }

    const targetDir = path.join(this.keystoreDir, targetName);
    writeBundle(bundle, targetDir);
    this._updateIndex(targetName, readMetadata(targetDir, targetName));
    this._log(`Store imported as "${targetName}"`);

    return targetName;
  }

  /** Removes a store and its index entry. There is no undo; export first. */
  deleteStore(storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    readMetadata(storeDir, storeName);   // refuse to delete a directory that is not a store

    fs.rmSync(storeDir, { recursive: true, force: true });

    const indexFile = path.join(this.keystoreDir, INDEX_FILE);
    if (fs.existsSync(indexFile)) {
      const index = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
      delete index.stores[storeName];
      index.updated = new Date().toISOString();
      fs.writeFileSync(indexFile, JSON.stringify(index, null, 2));
    }

    this._log(`Keystore "${storeName}" deleted`);
    return { storeName };
  }

  /** Instance sugar for the stateless encryptValue. */
  encryptValue(plaintext, userKey, options) {
    return encryptValue(plaintext, userKey, options);
  }

  /** Instance sugar for the stateless decryptValue. */
  decryptValue(token, userKey) {
    return decryptValue(token, userKey);
  }

  // ===== internals =====

  _log(message) {
    if (this.options.logger) this.options.logger(message);
  }

  /**
   * Rewrites this store's entry in the keystore-wide catalogue.
   *
   * The catalogue holds names and counts and no secrets, which is what makes it
   * safe to read without a user key - and what makes it merely a convenience:
   * every operation reads the store's own master.json for anything that matters.
   */
  _updateIndex(storeName, metadata) {
    const indexFile = path.join(this.keystoreDir, INDEX_FILE);
    let index = { stores: {} };

    if (fs.existsSync(indexFile)) {
      try {
        index = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
        if (!index.stores) index.stores = {};
      } catch (error) {
        // A corrupt catalogue is not worth failing a write over - it holds
        // nothing that is not also in each store's own metadata. Rebuild it.
        index = { stores: {} };
      }
    }

    index.stores[storeName] = {
      version: formatOf(metadata),
      created: metadata.created,
      totalKeys: metadata.totalKeys,
      keys: metadata.entries.map(entry => entry.key),
      sourceFile: metadata.sourceFile
    };
    index.updated = new Date().toISOString();

    fs.writeFileSync(indexFile, JSON.stringify(index, null, 2));
  }

  /** The first store holding this key, or null. */
  _findStoreForKey(key) {
    for (const storeName of this.listStores()) {
      try {
        if (this.listKeys(storeName).includes(key)) return storeName;
      } catch (error) {
        continue;   // a store we cannot read is not a store that holds the key
      }
    }
    return null;
  }
}

module.exports = SecureKeystore;
module.exports._internals = { formatOf, isLegacy, shapeOf, iterationsOf, STORE_FORMAT_LEGACY };
