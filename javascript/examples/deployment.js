'use strict';

// Getting a store onto a server.
//
//   node examples/deployment.js
//
// The bundle is already encrypted, so this is the whole of it: export, move the
// file however you move files, import. There is no key exchange step, because
// the user key never travels with the store - it arrives separately, as an
// environment variable on the target machine.

const fs = require('fs');
const os = require('os');
const path = require('path');

const { SecureKeystore } = require('../src');

/**
 * Export, import and transfer, wrapped in the shape a deploy script wants.
 *
 * Nothing here is privileged - it is all `exportStore` and `importStore` - and
 * it is in examples/ rather than in the library because every deployment names
 * its directories differently.
 */
class KeystoreDeployer {
  constructor(options = {}) {
    this.keystoreDir = options.keystoreDir || path.join(process.cwd(), '.keystore');
    this.backupDir = options.backupDir || path.join(process.cwd(), 'backups');
    this.log = options.logger || (() => {});

    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }
  }

  _store(keystoreDir = this.keystoreDir) {
    return new SecureKeystore({ keystoreDir, logger: this.log });
  }

  /**
   * Writes a store to a bundle in the backup directory.
   *
   * The name carries a stamp so that yesterday's bundle is still there when
   * today's turns out to be the one with the missing key.
   */
  export(storeName, stamp = new Date().toISOString().replace(/[:.]/g, '-')) {
    const store = this._store();
    store.getStoreInfo(storeName);   // fail here rather than half way through

    return store.exportStore(storeName, path.join(this.backupDir, `${storeName}-${stamp}.skb`));
  }

  /** Restores a bundle on the target machine. */
  import(backupPath, storeName) {
    const store = this._store();

    if (store.listStores().includes(storeName)) {
      this.log(`Store "${storeName}" already exists and will be replaced`);
    }

    const imported = store.importStore(backupPath, storeName);
    this.log(`Store "${imported}" holds ${store.listKeys(imported).length} keys`);
    return imported;
  }

  /** Export from one keystore directory, import into another, tidy up. */
  transfer(storeName, sourceDir, targetDir) {
    const bundle = path.join(this.backupDir, `${storeName}-transfer.skb`);

    this._store(sourceDir).exportStore(storeName, bundle);
    this._store(targetDir).importStore(bundle, storeName);
    fs.unlinkSync(bundle);

    return this._store(targetDir);
  }

  /**
   * Reads every key back, to prove the store the deployment just landed is one
   * the application can actually open.
   *
   * Worth running as the last step of a deploy: a bundle that copied cleanly
   * but was written under a different user key fails here, in the deploy, and
   * not at three in the morning.
   */
  verify(storeName, userKey) {
    const values = this._store().getAll(userKey, storeName);
    const count = Object.keys(values).length;

    this.log(`Verified ${count} keys in "${storeName}"`);
    return count;
  }
}

module.exports = KeystoreDeployer;

if (require.main === module) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-keystore-deploy-'));
  const userKey = 'a-long-random-user-key';

  try {
    const sourceDir = path.join(root, 'developer', '.keystore');
    const targetDir = path.join(root, 'server', '.keystore');

    const keysFile = path.join(root, 'keys.env');
    fs.writeFileSync(keysFile, 'master=MasterKey\napi_key=sk_live_abc123\njwt_secret=jwt_xyz');

    console.log('On the developer machine:');
    new SecureKeystore({ keystoreDir: sourceDir, logger: m => console.log(`  ${m}`) })
      .secure(keysFile, userKey, 'production');
    fs.unlinkSync(keysFile);

    const deployer = new KeystoreDeployer({
      keystoreDir: sourceDir,
      backupDir: path.join(root, 'backups'),
      logger: message => console.log(`  ${message}`)
    });

    console.log('\nExporting a bundle to carry across:');
    const bundle = deployer.export('production', 'demo');
    console.log(`  ${(fs.statSync(bundle).size / 1024).toFixed(1)} KB, already encrypted`);

    console.log('\nOn the server:');
    deployer.transfer('production', sourceDir, targetDir);

    console.log('\nVerifying the deploy:');
    const onServer = new KeystoreDeployer({ keystoreDir: targetDir, backupDir: path.join(root, 'backups'), logger: m => console.log(`  ${m}`) });
    onServer.verify('production', userKey);

    console.log('\nAnd with the wrong user key, which is what a bad deploy looks like:');
    try {
      onServer.verify('production', 'wrong-key');
    } catch (error) {
      console.log(`  ${error.code}: ${error.message}`);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
