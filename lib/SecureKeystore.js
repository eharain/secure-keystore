const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class SecureKeystore {
  constructor(options = {}) {
    this.keystoreDir = options.keystoreDir || path.join(process.cwd(), '.keystore');
    this.algorithm = 'aes-256-gcm';
    this.encoding = 'hex';
    
    // Create keystore directory if it doesn't exist
    if (!fs.existsSync(this.keystoreDir)) {
      fs.mkdirSync(this.keystoreDir, { recursive: true });
    }
  }

  /**
   * Secure a key-value file and store it in keystore
   */
  secure(inputFile, userKey, storeName = null) {
    const { masterKey, entries } = this._parseInput(inputFile);

    if (!masterKey) {
      throw new Error(
        'Input must define a master key (e.g. "master:..." in .txt, ' +
        '"master=..." in .env, or a "master" property in .json)'
      );
    }
    if (entries.length === 0) {
      throw new Error('No key-value entries found in input file');
    }

    if (!storeName) {
      storeName = path.basename(inputFile, path.extname(inputFile));
    }

    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      fs.mkdirSync(storeDir, { recursive: true });
    } else {
      // Remove stale files from a previous version of this store so that
      // re-securing does not leave orphaned .enc files behind.
      for (const file of fs.readdirSync(storeDir)) {
        if (file.endsWith('.enc') || file === 'master.json') {
          fs.unlinkSync(path.join(storeDir, file));
        }
      }
    }

    const salt1 = crypto.randomBytes(32);
    const userDerivedKey = crypto.pbkdf2Sync(userKey, salt1, 100000, 32, 'sha256');
    const encryptedMaster = this._encrypt(masterKey, userDerivedKey);

    const encryptedEntries = entries.map(entry => {
      const keySalt = crypto.randomBytes(32);

      const masterDerivedKey = crypto.pbkdf2Sync(masterKey, keySalt, 100000, 32, 'sha256');
      const encrypted = this._encrypt(entry.value, masterDerivedKey);

      const fileName = this._safeFileName(entry.key);
      const keyFile = path.join(storeDir, fileName);
      fs.writeFileSync(keyFile, JSON.stringify({
        salt: keySalt.toString(this.encoding),
        data: encrypted
      }, null, 2));

      return {
        key: entry.key,
        file: fileName
      };
    });

    const metadata = {
      version: '2.0',
      created: new Date().toISOString(),
      salt: salt1.toString(this.encoding),
      master: encryptedMaster,
      entries: encryptedEntries,
      sourceFile: path.basename(inputFile),
      totalKeys: entries.length
    };

    const masterFile = path.join(storeDir, 'master.json');
    fs.writeFileSync(masterFile, JSON.stringify(metadata, null, 2));

    this._updateIndex(storeName, metadata);

    console.log(`✅ Secured ${entries.length} keys in keystore: ${storeName}`);
    console.log(`📁 Location: ${storeDir}`);
    
    return {
      storeName,
      storeDir,
      totalKeys: entries.length,
      keys: entries.map(e => e.key)
    };
  }

  /**
   * Get a value by key
   */
  get(key, userKey, storeName = null) {
    if (!storeName) {
      storeName = this._findStoreForKey(key);
      if (!storeName) {
        throw new Error(`Key "${key}" not found in any keystore`);
      }
    }

    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      throw new Error(`Keystore "${storeName}" not found`);
    }

    const masterFile = path.join(storeDir, 'master.json');
    if (!fs.existsSync(masterFile)) {
      throw new Error(`Master file not found in keystore "${storeName}"`);
    }

    const metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));

    const salt1 = Buffer.from(metadata.salt, this.encoding);
    const userDerivedKey = crypto.pbkdf2Sync(userKey, salt1, 100000, 32, 'sha256');
    const masterKey = this._decrypt(metadata.master, userDerivedKey);

    const entry = metadata.entries.find(e => e.key === key);
    if (!entry) {
      throw new Error(`Key "${key}" not found in keystore "${storeName}"`);
    }

    const keyFile = path.join(storeDir, entry.file);
    if (!fs.existsSync(keyFile)) {
      throw new Error(`Encrypted file not found: ${entry.file}`);
    }

    const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
    const keySalt = Buffer.from(keyData.salt, this.encoding);
    
    const masterDerivedKey = crypto.pbkdf2Sync(masterKey, keySalt, 100000, 32, 'sha256');
    return this._decrypt(keyData.data, masterDerivedKey);
  }

  /**
   * Get all keys and values from a store
   */
  getAll(userKey, storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      throw new Error(`Keystore "${storeName}" not found`);
    }

    const masterFile = path.join(storeDir, 'master.json');
    const metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));

    const salt1 = Buffer.from(metadata.salt, this.encoding);
    const userDerivedKey = crypto.pbkdf2Sync(userKey, salt1, 100000, 32, 'sha256');
    const masterKey = this._decrypt(metadata.master, userDerivedKey);

    const result = {};
    for (const entry of metadata.entries) {
      const keyFile = path.join(storeDir, entry.file);
      const keyData = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      const keySalt = Buffer.from(keyData.salt, this.encoding);
      
      const masterDerivedKey = crypto.pbkdf2Sync(masterKey, keySalt, 100000, 32, 'sha256');
      result[entry.key] = this._decrypt(keyData.data, masterDerivedKey);
    }

    return result;
  }

  /**
   * Add or update a key
   */
  set(key, value, userKey, storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      throw new Error(`Keystore "${storeName}" not found`);
    }

    const masterFile = path.join(storeDir, 'master.json');
    const metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));

    const salt1 = Buffer.from(metadata.salt, this.encoding);
    const userDerivedKey = crypto.pbkdf2Sync(userKey, salt1, 100000, 32, 'sha256');
    const masterKey = this._decrypt(metadata.master, userDerivedKey);

    const keySalt = crypto.randomBytes(32);

    const masterDerivedKey = crypto.pbkdf2Sync(masterKey, keySalt, 100000, 32, 'sha256');
    const encrypted = this._encrypt(value, masterDerivedKey);

    const existing = metadata.entries.find(e => e.key === key);
    if (existing) {
      const keyFile = path.join(storeDir, existing.file);
      fs.writeFileSync(keyFile, JSON.stringify({
        salt: keySalt.toString(this.encoding),
        data: encrypted
      }, null, 2));
    } else {
      const fileName = this._safeFileName(key);
      const keyFile = path.join(storeDir, fileName);
      fs.writeFileSync(keyFile, JSON.stringify({
        salt: keySalt.toString(this.encoding),
        data: encrypted
      }, null, 2));
      
      metadata.entries.push({
        key: key,
        file: fileName
      });
      metadata.totalKeys = metadata.entries.length;
    }

    fs.writeFileSync(masterFile, JSON.stringify(metadata, null, 2));
    this._updateIndex(storeName, metadata);

    console.log(`✅ Key "${key}" ${existing ? 'updated' : 'added'} in keystore "${storeName}"`);
  }

  /**
   * List all stores
   */
  listStores() {
    const stores = fs.readdirSync(this.keystoreDir)
      .filter(dir => {
        const masterFile = path.join(this.keystoreDir, dir, 'master.json');
        return fs.existsSync(masterFile);
      });
    return stores;
  }

  /**
   * List all keys in a store
   */
  listKeys(storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      throw new Error(`Keystore "${storeName}" not found`);
    }

    const masterFile = path.join(storeDir, 'master.json');
    const metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));
    return metadata.entries.map(e => e.key);
  }

  /**
   * Get store information
   */
  getStoreInfo(storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      throw new Error(`Keystore "${storeName}" not found`);
    }

    const masterFile = path.join(storeDir, 'master.json');
    const metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));

    return {
      name: storeName,
      path: storeDir,
      created: metadata.created,
      totalKeys: metadata.totalKeys,
      keys: metadata.entries.map(e => e.key),
      sourceFile: metadata.sourceFile
    };
  }

  /**
   * Delete a single key from a store
   */
  deleteKey(key, storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      throw new Error(`Keystore "${storeName}" not found`);
    }

    const masterFile = path.join(storeDir, 'master.json');
    const metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));

    const index = metadata.entries.findIndex(e => e.key === key);
    if (index === -1) {
      throw new Error(`Key "${key}" not found in keystore "${storeName}"`);
    }

    const [removed] = metadata.entries.splice(index, 1);
    const keyFile = path.join(storeDir, removed.file);
    if (fs.existsSync(keyFile)) {
      fs.unlinkSync(keyFile);
    }

    metadata.totalKeys = metadata.entries.length;
    fs.writeFileSync(masterFile, JSON.stringify(metadata, null, 2));
    this._updateIndex(storeName, metadata);

    console.log(`🗑️ Key "${key}" deleted from keystore "${storeName}"`);
  }

  /**
   * Export a store for backup.
   *
   * Produces a single self-contained JSON bundle (default extension ".skb").
   * Pure JavaScript — no external `tar` binary, so it works identically on
   * Windows, macOS and Linux and is not vulnerable to shell injection.
   */
  exportStore(storeName, backupPath = null) {
    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      throw new Error(`Keystore "${storeName}" not found`);
    }

    if (!backupPath) {
      backupPath = path.join(process.cwd(), `${storeName}-backup-${Date.now()}.skb`);
    }

    const bundle = {
      format: 'secure-keystore-backup',
      version: 1,
      storeName,
      files: {}
    };

    for (const file of fs.readdirSync(storeDir)) {
      bundle.files[file] = fs.readFileSync(path.join(storeDir, file), 'utf8');
    }

    fs.writeFileSync(backupPath, JSON.stringify(bundle));
    console.log(`📦 Store exported to: ${backupPath}`);
    return backupPath;
  }

  /**
   * Import a store from a backup bundle created by exportStore().
   */
  importStore(backupPath, storeName = null) {
    if (!fs.existsSync(backupPath)) {
      throw new Error(`Backup file not found: ${backupPath}`);
    }

    let bundle;
    try {
      bundle = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
    } catch (error) {
      throw new Error(`Invalid backup file: ${backupPath} is not a valid keystore bundle`);
    }

    if (!bundle || bundle.format !== 'secure-keystore-backup' || !bundle.files) {
      throw new Error(`Invalid backup file: ${backupPath} is not a keystore bundle`);
    }
    if (!bundle.files['master.json']) {
      throw new Error('Invalid backup: master.json not found');
    }

    const targetName = storeName || bundle.storeName;
    if (!targetName) {
      throw new Error('Cannot determine target store name from backup');
    }

    const targetDir = path.join(this.keystoreDir, targetName);
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }

    for (const [file, content] of Object.entries(bundle.files)) {
      // Use basename to neutralise any path-traversal entries in a crafted bundle.
      fs.writeFileSync(path.join(targetDir, path.basename(file)), content);
    }

    const masterFile = path.join(targetDir, 'master.json');
    const metadata = JSON.parse(fs.readFileSync(masterFile, 'utf8'));
    this._updateIndex(targetName, metadata);

    console.log(`📥 Store imported as: ${targetName}`);
    return targetName;
  }

  /**
   * Delete a store
   */
  deleteStore(storeName) {
    const storeDir = path.join(this.keystoreDir, storeName);
    if (!fs.existsSync(storeDir)) {
      throw new Error(`Keystore "${storeName}" not found`);
    }

    const files = fs.readdirSync(storeDir);
    for (const file of files) {
      fs.unlinkSync(path.join(storeDir, file));
    }
    fs.rmdirSync(storeDir);

    const indexFile = path.join(this.keystoreDir, 'index.json');
    if (fs.existsSync(indexFile)) {
      const index = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
      delete index.stores[storeName];
      fs.writeFileSync(indexFile, JSON.stringify(index, null, 2));
    }

    console.log(`🗑️ Keystore "${storeName}" deleted`);
  }

  // ===== Private Methods =====

  /**
   * Read and parse an input file into { masterKey, entries }.
   * Format is chosen by file extension:
   *   .json -> a JSON object of key/value pairs (with a "master" property)
   *   .env  -> dotenv-style KEY=value lines (with a "master" line)
   *   else  -> the default colon format: "master:..." then "key:value" lines
   */
  _parseInput(inputFile) {
    const content = fs.readFileSync(inputFile, 'utf8');
    const ext = path.extname(inputFile).toLowerCase();

    if (ext === '.json') return this._parseJson(content);
    if (ext === '.env') return this._parseEnv(content);
    return this._parseColon(content);
  }

  _parseColon(content) {
    const lines = content.split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0);

    if (lines.length === 0) {
      throw new Error('Input file is empty');
    }

    const firstLine = lines[0].split(':');
    if (firstLine[0] !== 'master') {
      throw new Error('First line must be "master:your_master_key"');
    }
    const masterKey = firstLine.slice(1).join(':');

    const entries = [];
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(':');
      if (parts.length < 2) continue;
      entries.push({ key: parts[0], value: parts.slice(1).join(':') });
    }

    return { masterKey, entries };
  }

  _parseEnv(content) {
    let masterKey = null;
    const entries = [];

    for (let line of content.split('\n')) {
      line = line.trim();
      if (!line || line.startsWith('#')) continue;
      if (line.startsWith('export ')) line = line.slice('export '.length).trim();

      const eq = line.indexOf('=');
      if (eq === -1) continue;

      const key = line.slice(0, eq).trim();
      let value = line.slice(eq + 1).trim();
      if (value.length >= 2 &&
          ((value[0] === '"' && value[value.length - 1] === '"') ||
           (value[0] === "'" && value[value.length - 1] === "'"))) {
        value = value.slice(1, -1);
      }

      if (!key) continue;
      if (key === 'master') { masterKey = value; continue; }
      entries.push({ key, value });
    }

    return { masterKey, entries };
  }

  _parseJson(content) {
    let obj;
    try {
      obj = JSON.parse(content);
    } catch (error) {
      throw new Error('Invalid JSON input file');
    }
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
      throw new Error('JSON input must be an object of key-value pairs');
    }

    let masterKey = null;
    const entries = [];
    for (const [key, value] of Object.entries(obj)) {
      const strValue = typeof value === 'string' ? value : JSON.stringify(value);
      if (key === 'master') { masterKey = strValue; continue; }
      entries.push({ key, value: strValue });
    }

    return { masterKey, entries };
  }

  /**
   * Build a filesystem-safe, collision-resistant filename for a key.
   * Strips characters that are unsafe in paths (preventing traversal and
   * invalid Windows filenames) and appends a short hash of the original key
   * to keep distinct keys from colliding after sanitisation.
   */
  _safeFileName(key) {
    const raw = String(key);
    const safe = raw.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64);
    const hash = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 8);
    return `${safe}-${hash}.enc`;
  }

  _encrypt(plaintext, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', this.encoding);
    encrypted += cipher.final(this.encoding);
    const authTag = cipher.getAuthTag();

    return {
      iv: iv.toString(this.encoding),
      authTag: authTag.toString(this.encoding),
      data: encrypted
    };
  }

  _decrypt(encryptedData, key) {
    const iv = Buffer.from(encryptedData.iv, this.encoding);
    const authTag = Buffer.from(encryptedData.authTag, this.encoding);
    
    const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData.data, this.encoding, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  _updateIndex(storeName, metadata) {
    const indexFile = path.join(this.keystoreDir, 'index.json');
    let index = { stores: {}, updated: new Date().toISOString() };
    
    if (fs.existsSync(indexFile)) {
      index = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
    }
    
    index.stores[storeName] = {
      created: metadata.created,
      totalKeys: metadata.totalKeys,
      keys: metadata.entries.map(e => e.key),
      sourceFile: metadata.sourceFile
    };
    index.updated = new Date().toISOString();
    
    fs.writeFileSync(indexFile, JSON.stringify(index, null, 2));
  }

  _findStoreForKey(key) {
    const stores = this.listStores();
    for (const store of stores) {
      try {
        const keys = this.listKeys(store);
        if (keys.includes(key)) {
          return store;
        }
      } catch (error) {
        continue;
      }
    }
    return null;
  }
}

module.exports = SecureKeystore;