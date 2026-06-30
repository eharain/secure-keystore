const SecureKeystore = require('../index');

// Initialize with default keystore directory
const store = new SecureKeystore();

const userKey = 'myUserKey123';
const storeName = 'production';

// Secure a file
console.log('📝 Securing keys...');
const result = store.secure('./keys.txt', userKey, storeName);
console.log('Keys secured:', result.keys);

// Get a specific key
console.log('\n🔑 Getting specific keys...');
try {
  const apiKey = store.get('api_key', userKey, storeName);
  console.log('API Key:', apiKey);
  
  const jwtSecret = store.get('jwt_secret', userKey, storeName);
  console.log('JWT Secret:', jwtSecret);
} catch (error) {
  console.error('Error:', error.message);
}

// Get all keys
console.log('\n📋 All keys:');
const allKeys = store.getAll(userKey, storeName);
for (const [key, value] of Object.entries(allKeys)) {
  console.log(`  ${key}: ${value}`);
}

// List stores
console.log('\n📂 Available stores:', store.listStores());

// Store info
const info = store.getStoreInfo(storeName);
console.log('\n📊 Store info:', info);