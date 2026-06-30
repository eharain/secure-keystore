const SecureKeystore = require('../index');
const path = require('path');
const fs = require('fs');

class KeystoreDeployer {
  constructor(options = {}) {
    this.keystoreDir = options.keystoreDir || './.keystore';
    this.backupDir = options.backupDir || './backups';
    
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }
  }

  /**
   * Export keystore for transfer
   */
  exportStore(storeName, userKey) {
    console.log(`📤 Exporting keystore "${storeName}"...`);
    const store = new SecureKeystore({ keystoreDir: this.keystoreDir });
    
    // Verify access
    store.listKeys(storeName);
    
    const timestamp = Date.now();
    const backupFile = path.join(this.backupDir, `${storeName}-${timestamp}.tar`);
    
    store.exportStore(storeName, backupFile);
    return backupFile;
  }

  /**
   * Import keystore on target server
   */
  importStore(backupPath, storeName, userKey) {
    console.log(`📥 Importing keystore "${storeName}"...`);
    const store = new SecureKeystore({ keystoreDir: this.keystoreDir });
    
    // Check if store already exists
    if (store.listStores().includes(storeName)) {
      console.log(`⚠️ Store "${storeName}" already exists. Overwriting...`);
    }
    
    store.importStore(backupPath, storeName);
    
    // Verify import
    const keys = store.listKeys(storeName);
    console.log(`✅ Store "${storeName}" imported with ${keys.length} keys`);
    return store;
  }

  /**
   * Transfer keystore between servers (simulated)
   */
  transferStore(storeName, sourceDir, targetDir, userKey) {
    console.log(`🔄 Transferring "${storeName}" from ${sourceDir} to ${targetDir}`);
    
    // Export from source
    const sourceStore = new SecureKeystore({ keystoreDir: sourceDir });
    const backupFile = path.join(this.backupDir, `${storeName}-transfer.tar`);
    sourceStore.exportStore(storeName, backupFile);
    
    // Import to target
    const targetStore = new SecureKeystore({ keystoreDir: targetDir });
    targetStore.importStore(backupFile, storeName);
    
    // Cleanup
    if (fs.existsSync(backupFile)) {
      fs.unlinkSync(backupFile);
    }
    
    console.log(`✅ Transfer complete`);
    return targetStore;
  }
}

// Usage Example
async function main() {
  const deployer = new KeystoreDeployer({
    keystoreDir: './.keystore',
    backupDir: './backups'
  });
  
  const userKey = 'myUserKey123';
  const storeName = 'production';
  
  try {
    // Option 1: Export only
    const backup = deployer.exportStore(storeName, userKey);
    console.log(`📦 Backup created: ${backup}`);
    
    // Option 2: Simulate transfer
    const targetKeystore = await deployer.transferStore(
      storeName,
      './.keystore',
      './.keystore-target',
      userKey
    );
    
    // Verify transfer
    const keys = targetKeystore.listKeys(storeName);
    console.log(`📋 Keys in target: ${keys.join(', ')}`);
    
  } catch (error) {
    console.error('❌ Deployment failed:', error.message);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = KeystoreDeployer;