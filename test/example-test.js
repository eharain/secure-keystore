const SecureKeystore = require('../lib/SecureKeystore');
const fs = require('fs');
const path = require('path');

// Simple test script
async function runTests() {
  console.log('🧪 Running tests...\n');
  
  const testDir = path.join(process.cwd(), 'test-temp');
  const keystoreDir = path.join(testDir, '.keystore');
  const store = new SecureKeystore({ keystoreDir });
  
  const userKey = 'testUser123!@#';
  const storeName = 'test-store';
  
  // Create test file
  const testFile = path.join(testDir, 'test-keys.txt');
  if (!fs.existsSync(testDir)) {
    fs.mkdirSync(testDir, { recursive: true });
  }
  
  fs.writeFileSync(testFile, `
master:TestMasterKey123
api_key:sk_test_abc123
jwt_secret:test_secret_xyz
db_password:test_pass_123
  `.trim());
  
  try {
    // Test 1: Secure
    console.log('📝 Test 1: Securing keys...');
    const result = store.secure(testFile, userKey, storeName);
    console.log('✅ Secured:', result.keys);
    
    // Test 2: Get
    console.log('\n🔑 Test 2: Getting keys...');
    const apiKey = store.get('api_key', userKey, storeName);
    console.log('✅ API Key:', apiKey);
    
    // Test 3: Set
    console.log('\n✏️ Test 3: Setting new key...');
    store.set('new_key', 'new_value', userKey, storeName);
    const newKey = store.get('new_key', userKey, storeName);
    console.log('✅ New key value:', newKey);
    
    // Test 4: List
    console.log('\n📋 Test 4: Listing keys...');
    const keys = store.listKeys(storeName);
    console.log('✅ Keys:', keys);
    
    // Test 5: Export
    console.log('\n📦 Test 5: Exporting...');
    const backup = store.exportStore(storeName, path.join(testDir, 'backup.tar'));
    console.log('✅ Backup:', backup);
    
    // Test 6: Import
    console.log('\n📥 Test 6: Importing...');
    const newStoreName = 'test-store-imported';
    store.importStore(backup, newStoreName);
    const importedKeys = store.listKeys(newStoreName);
    console.log('✅ Imported keys:', importedKeys);

    // Test 7: Delete a single key
    console.log('\n🗑️ Test 7: Deleting a key...');
    store.deleteKey('new_key', storeName);
    const afterDelete = store.listKeys(storeName);
    if (afterDelete.includes('new_key')) {
      throw new Error('deleteKey did not remove the key');
    }
    console.log('✅ Keys after delete:', afterDelete);

    // Test 8: Keys with unsafe characters must not escape the store dir
    console.log('\n🛡️ Test 8: Unsafe key names...');
    const evilKey = '../escape:key';
    store.set(evilKey, 'evil_value', userKey, storeName);
    const evilValue = store.get(evilKey, userKey, storeName);
    if (evilValue !== 'evil_value') {
      throw new Error('Round-trip failed for unsafe key name');
    }
    const escaped = fs.existsSync(path.join(testDir, '.keystore', 'escape:key'));
    if (escaped) {
      throw new Error('Unsafe key name escaped the store directory');
    }
    console.log('✅ Unsafe key stored and retrieved safely');

    // Test 9: .env and .json input formats
    console.log('\n📄 Test 9: .env and .json formats...');

    const envFile = path.join(testDir, 'keys.env');
    fs.writeFileSync(envFile, [
      '# sample env',
      'master=EnvMaster',
      'export api_key=env_api',
      'jwt_secret="env_jwt"'
    ].join('\n'));
    store.secure(envFile, userKey, 'env-store');
    if (store.get('api_key', userKey, 'env-store') !== 'env_api' ||
        store.get('jwt_secret', userKey, 'env-store') !== 'env_jwt') {
      throw new Error('.env parsing failed');
    }
    console.log('✅ .env parsed (export prefix + quotes handled)');

    const jsonFile = path.join(testDir, 'keys.json');
    fs.writeFileSync(jsonFile, JSON.stringify({
      master: 'JsonMaster',
      api_key: 'json_api',
      port: 8080
    }));
    store.secure(jsonFile, userKey, 'json-store');
    if (store.get('api_key', userKey, 'json-store') !== 'json_api' ||
        store.get('port', userKey, 'json-store') !== '8080') {
      throw new Error('.json parsing failed');
    }
    console.log('✅ .json parsed (non-string values coerced)');

    console.log('\n🎉 All tests passed!');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
  } finally {
    // Cleanup
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  }
}

runTests();