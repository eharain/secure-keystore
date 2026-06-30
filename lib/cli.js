#!/usr/bin/env node
const SecureKeystore = require('./SecureKeystore');
const fs = require('fs');

const args = process.argv.slice(2);

function showHelp() {
  console.log(`
🔐 Keystore Manager - Secure Key Management System

Usage:
  secure secure <input-file> <user-key> [store-name]
  secure get <key> <user-key> [store-name]
  secure list <store-name> <user-key>
  secure set <key> <value> <user-key> <store-name>
  secure delete <key> <store-name>
  secure all <store-name> <user-key>
  secure info <store-name>
  secure stores
  secure export <store-name> [backup-path]
  secure import <backup-path> [store-name]
  secure delete-store <store-name>
  secure --help

Examples:
  secure secure keys.txt myUserKey123
  secure secure keys.txt myUserKey123 production
  secure get api_key myUserKey123
  secure get api_key myUserKey123 production
  secure stores
  secure list production myUserKey123
  secure set new_key new_value myUserKey123 production
  secure all production myUserKey123
  secure info production
  secure delete api_key production
  secure export production ./backup.skb
  secure import ./backup.skb production
  secure delete-store production
`);
}

if (args.includes('--help') || args.length === 0) {
  showHelp();
  process.exit(0);
}

const command = args[0];
const store = new SecureKeystore();

try {
  switch (command) {
    case 'secure': {
      const inputFile = args[1];
      const userKey = args[2];
      const storeName = args[3] || null;
      
      if (!inputFile || !userKey) {
        console.error('❌ Usage: secure secure <input-file> <user-key> [store-name]');
        process.exit(1);
      }
      
      if (!fs.existsSync(inputFile)) {
        console.error(`❌ File not found: ${inputFile}`);
        process.exit(1);
      }
      
      const result = store.secure(inputFile, userKey, storeName);
      console.log(`\n📋 Secured ${result.totalKeys} keys:`);
      result.keys.forEach(k => console.log(`  - ${k}`));
      break;
    }
    
    case 'get': {
      const key = args[1];
      const userKey = args[2];
      const storeName = args[3] || null;
      
      if (!key || !userKey) {
        console.error('❌ Usage: secure get <key> <user-key> [store-name]');
        process.exit(1);
      }
      
      const value = store.get(key, userKey, storeName);
      console.log(`✅ ${key}: ${value}`);
      break;
    }
    
    case 'list': {
      const storeName = args[1];
      const userKey = args[2];
      
      if (!storeName || !userKey) {
        console.error('❌ Usage: secure list <store-name> <user-key>');
        process.exit(1);
      }
      
      const keys = store.listKeys(storeName);
      console.log(`📋 Keys in "${storeName}":`);
      keys.forEach(k => console.log(`  - ${k}`));
      break;
    }
    
    case 'set': {
      const key = args[1];
      const value = args[2];
      const userKey = args[3];
      const storeName = args[4];
      
      if (!key || !value || !userKey || !storeName) {
        console.error('❌ Usage: secure set <key> <value> <user-key> <store-name>');
        process.exit(1);
      }
      
      store.set(key, value, userKey, storeName);
      break;
    }
    
    case 'all': {
      const storeName = args[1];
      const userKey = args[2];
      
      if (!storeName || !userKey) {
        console.error('❌ Usage: secure all <store-name> <user-key>');
        process.exit(1);
      }
      
      const all = store.getAll(userKey, storeName);
      console.log(`📋 All keys in "${storeName}":`);
      for (const [key, value] of Object.entries(all)) {
        console.log(`  ${key}: ${value}`);
      }
      break;
    }
    
    case 'info': {
      const storeName = args[1];
      
      if (!storeName) {
        console.error('❌ Usage: secure info <store-name>');
        process.exit(1);
      }
      
      const info = store.getStoreInfo(storeName);
      console.log('📊 Store Information:');
      console.log(`  Name: ${info.name}`);
      console.log(`  Path: ${info.path}`);
      console.log(`  Created: ${info.created}`);
      console.log(`  Total Keys: ${info.totalKeys}`);
      console.log(`  Keys: ${info.keys.join(', ')}`);
      console.log(`  Source File: ${info.sourceFile}`);
      break;
    }
    
    case 'stores': {
      const stores = store.listStores();
      if (stores.length === 0) {
        console.log('📭 No stores found');
      } else {
        console.log('📋 Available stores:');
        for (const s of stores) {
          const info = store.getStoreInfo(s);
          console.log(`  - ${s} (${info.totalKeys} keys)`);
        }
      }
      break;
    }
    
    case 'export': {
      const storeName = args[1];
      const backupPath = args[2] || null;
      
      if (!storeName) {
        console.error('❌ Usage: secure export <store-name> [backup-path]');
        process.exit(1);
      }
      
      store.exportStore(storeName, backupPath);
      break;
    }
    
    case 'import': {
      const backupPath = args[1];
      const storeName = args[2] || null;
      
      if (!backupPath) {
        console.error('❌ Usage: secure import <backup-path> [store-name]');
        process.exit(1);
      }
      
      store.importStore(backupPath, storeName);
      break;
    }
    
    case 'delete': {
      const key = args[1];
      const storeName = args[2];

      if (!key || !storeName) {
        console.error('❌ Usage: secure delete <key> <store-name>');
        process.exit(1);
      }

      store.deleteKey(key, storeName);
      break;
    }

    case 'delete-store': {
      const storeName = args[1];
      
      if (!storeName) {
        console.error('❌ Usage: secure delete-store <store-name>');
        process.exit(1);
      }
      
      store.deleteStore(storeName);
      break;
    }
    
    default:
      console.error(`❌ Unknown command: ${command}`);
      showHelp();
      process.exit(1);
  }
} catch (error) {
  console.error('❌ Error:', error.message);
  process.exit(1);
}