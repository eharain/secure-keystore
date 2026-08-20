#!/usr/bin/env node
'use strict';

// The command line.
//
// Every line this package prints is printed here. The library used to
// console.log its way through an operation, which made it unusable from a
// server that had opinions about its own logging, and made this file's output
// impossible to change without changing the library. The library now takes a
// logger; the command line passes one that writes to stdout.

const fs = require('fs');
const path = require('path');
const { SecureKeystore, KeystoreError, VERSION } = require('../src');

const NAME = 'secure-keystore';

function showHelp() {
  process.stdout.write(`
${NAME} ${VERSION} - encrypted secrets at rest, with no service to run

Usage:
  ${NAME} secure <input-file> <user-key> [store-name]
  ${NAME} get <key> <user-key> [store-name]
  ${NAME} all <store-name> <user-key>
  ${NAME} set <key> <value> <user-key> <store-name>
  ${NAME} migrate <store-name> <user-key>
  ${NAME} list <store-name>
  ${NAME} stores
  ${NAME} info <store-name>
  ${NAME} delete <key> <store-name>
  ${NAME} delete-store <store-name>
  ${NAME} export <store-name> [backup-path]
  ${NAME} import <backup-path> [store-name]
  ${NAME} encrypt <value> <user-key>
  ${NAME} decrypt <token> <user-key>
  ${NAME} --help | --version

Options:
  --keystore <dir>     where stores live (default ./.keystore)
  --iterations <n>     PBKDF2 rounds for new or migrated stores (default 600000)
  --json               print machine-readable JSON instead of prose
  --quiet              print results only, no progress

Examples:
  ${NAME} secure keys.env "$USER_KEY" production
  ${NAME} get api_key "$USER_KEY" production
  ${NAME} stores
  ${NAME} migrate production "$USER_KEY"
  ${NAME} export production ./backups/prod.skb
  ${NAME} encrypt "sk_live_abc123" "$USER_KEY"

A key name is not a secret: 'list', 'stores' and 'info' read metadata and need
no user key. 'get', 'all', 'set' and 'migrate' decrypt, and do.
`);
}

/**
 * Pulls the flags out of argv and leaves the positional arguments behind.
 *
 * Written by hand rather than pulled in, because this package has no
 * dependencies and one small parser is a cheaper thing to own than an argument
 * library with a release cadence of its own.
 */
function parseArgs(argv) {
  const flags = {
    keystore: null,
    iterations: null,
    json: false,
    quiet: false,
    help: false,
    version: false
  };
  const positional = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--keystore': flags.keystore = argv[++i]; break;
      case '--iterations': flags.iterations = Number(argv[++i]); break;
      case '--json': flags.json = true; break;
      case '--quiet': flags.quiet = true; break;
      case '--help': case '-h': flags.help = true; break;
      case '--version': case '-v': flags.version = true; break;
      default:
        if (arg.startsWith('--keystore=')) flags.keystore = arg.slice('--keystore='.length);
        else if (arg.startsWith('--iterations=')) flags.iterations = Number(arg.slice('--iterations='.length));
        else positional.push(arg);
    }
  }

  return { flags, positional };
}

function usage(line) {
  process.stderr.write(`Usage: ${NAME} ${line}\n`);
  process.exit(1);
}

const { flags, positional } = parseArgs(process.argv.slice(2));

if (flags.version) {
  process.stdout.write(`${VERSION}\n`);
  process.exit(0);
}
if (flags.help || positional.length === 0) {
  showHelp();
  process.exit(0);
}

const [command, ...args] = positional;

// Everything printed goes through these two, so --json and --quiet are honoured
// in one place rather than at thirty call sites. Each command hands over both
// forms of its result at once: `text` for a person, everything else for a
// script. `text` is dropped from the JSON, where it would only be noise.
const out = data => {
  if (!flags.json) return void process.stdout.write(`${data.text}\n`);
  const { text, ...machine } = data;
  process.stdout.write(`${JSON.stringify(machine, null, 2)}\n`);
};
const progress = flags.quiet || flags.json ? null : message => process.stdout.write(`${message}\n`);

const store = new SecureKeystore({
  ...(flags.keystore ? { keystoreDir: path.resolve(flags.keystore) } : {}),
  ...(flags.iterations ? { iterations: flags.iterations } : {}),
  logger: progress
});

try {
  switch (command) {
    case 'secure': {
      const [inputFile, userKey, storeName = null] = args;
      if (!inputFile || !userKey) usage('secure <input-file> <user-key> [store-name]');
      if (!fs.existsSync(inputFile)) {
        process.stderr.write(`File not found: ${inputFile}\n`);
        process.exit(1);
      }

      // The logger already said how many keys went where; this is the list, one
      // key per line, so it pipes into anything.
      const result = store.secure(inputFile, userKey, storeName);
      out({ ...result, text: result.keys.join('\n') });
      break;
    }

    case 'get': {
      const [key, userKey, storeName = null] = args;
      if (!key || !userKey) usage('get <key> <user-key> [store-name]');

      const value = store.get(key, userKey, storeName);
      // Bare value on stdout, so `X=$(secure-keystore get x "$K" prod)` works.
      out({ key, value, text: value });
      break;
    }

    case 'all': {
      const [storeName, userKey] = args;
      if (!storeName || !userKey) usage('all <store-name> <user-key>');

      const values = store.getAll(userKey, storeName);
      out({
        store: storeName,
        values,
        text: Object.entries(values).map(([key, value]) => `${key}=${value}`).join('\n')
      });
      break;
    }

    case 'set': {
      const [key, value, userKey, storeName] = args;
      if (!key || value === undefined || !userKey || !storeName) {
        usage('set <key> <value> <user-key> <store-name>');
      }

      const result = store.set(key, value, userKey, storeName);
      out({ ...result, text: `Key "${key}" ${result.added ? 'added to' : 'updated in'} "${storeName}"` });
      break;
    }

    case 'migrate': {
      const [storeName, userKey] = args;
      if (!storeName || !userKey) usage('migrate <store-name> <user-key>');

      const result = store.migrate(storeName, userKey);
      out({
        ...result,
        text: result.from === result.to
          ? `Store "${storeName}" re-encrypted in format ${result.to} at ${result.iterations} iterations`
          : `Store "${storeName}" migrated from format ${result.from} to ${result.to}`
      });
      break;
    }

    case 'list': {
      const [storeName] = args;
      if (!storeName) usage('list <store-name>');

      const keys = store.listKeys(storeName);
      out({ store: storeName, keys, text: keys.join('\n') });
      break;
    }

    case 'stores': {
      const stores = store.listStores().map(name => store.getStoreInfo(name));
      out({
        stores,
        text: stores.length === 0
          ? 'No stores found'
          : stores.map(info => `${info.name}  (${info.totalKeys} keys)`).join('\n')
      });
      break;
    }

    case 'info': {
      const [storeName] = args;
      if (!storeName) usage('info <store-name>');

      const info = store.getStoreInfo(storeName);
      out({
        ...info,
        text: [
          `Name:        ${info.name}`,
          `Path:        ${info.path}`,
          `Format:      ${info.version}${info.current ? '' : '  (run migrate to bring it to 3.0)'}`,
          `Created:     ${info.created}`,
          `Updated:     ${info.updated}`,
          `Iterations:  ${info.iterations}`,
          `Total keys:  ${info.totalKeys}`,
          `Keys:        ${info.keys.join(', ')}`,
          `Source file: ${info.sourceFile}`
        ].join('\n')
      });
      break;
    }

    case 'delete': {
      const [key, storeName] = args;
      if (!key || !storeName) usage('delete <key> <store-name>');

      store.deleteKey(key, storeName);
      out({ key, store: storeName, deleted: true, text: `Key "${key}" deleted from "${storeName}"` });
      break;
    }

    case 'delete-store': {
      const [storeName] = args;
      if (!storeName) usage('delete-store <store-name>');

      store.deleteStore(storeName);
      out({ store: storeName, deleted: true, text: `Keystore "${storeName}" deleted` });
      break;
    }

    case 'export': {
      const [storeName, backupPath = null] = args;
      if (!storeName) usage('export <store-name> [backup-path]');

      const written = store.exportStore(storeName, backupPath);
      out({ store: storeName, path: written, text: written });
      break;
    }

    case 'import': {
      const [backupPath, storeName = null] = args;
      if (!backupPath) usage('import <backup-path> [store-name]');

      const imported = store.importStore(backupPath, storeName);
      out({ store: imported, text: `Store imported as "${imported}"` });
      break;
    }

    case 'encrypt': {
      const [value, userKey] = args;
      if (value === undefined || !userKey) usage('encrypt <value> <user-key>');

      // --iterations applies here too, and matters more: a token pays the cost
      // per value, where a store pays it once.
      const token = store.encryptValue(value, userKey, flags.iterations ? { iterations: flags.iterations } : undefined);
      out({ token, text: token });
      break;
    }

    case 'decrypt': {
      const [token, userKey] = args;
      if (!token || !userKey) usage('decrypt <token> <user-key>');

      const value = store.decryptValue(token, userKey);
      out({ value, text: value });
      break;
    }

    default:
      process.stderr.write(`Unknown command: ${command}\n\n`);
      showHelp();
      process.exit(1);
  }
} catch (error) {
  // A KeystoreError carries a code, and the code is the useful half of it in a
  // script - so it is printed, and it is what --json reports.
  if (flags.json) {
    process.stderr.write(`${JSON.stringify({
      error: error.message,
      code: error instanceof KeystoreError ? error.code : 'UNKNOWN'
    }, null, 2)}\n`);
  } else if (error instanceof KeystoreError) {
    process.stderr.write(`${error.code}: ${error.message}\n`);
  } else {
    process.stderr.write(`${error.message}\n`);
  }
  process.exit(1);
}
