'use strict';

const fs = require('fs');
const path = require('path');
const { BACKUP_FORMAT, BACKUP_VERSION, MASTER_FILE } = require('./constants');
const { KeystoreError, ErrorCodes } = require('./errors');

// Export and import, as one JSON bundle.
//
// An earlier version shelled out to `tar`, which meant the feature worked on
// the author's machine and on no Windows machine at all, and passed a store
// name into a shell. A bundle is a JSON object of filename to contents: no
// external binary, no shell, identical bytes on every platform.
//
// The contents are already encrypted. A bundle is therefore safe to put through
// a CI artifact store or an scp, and useless to anyone who intercepts it
// without the user key.

/**
 * Reads every file in a store directory into a bundle object.
 *
 * @param {string} storeDir
 * @param {string} storeName
 * @returns {object} the bundle, ready to be serialised
 */
function buildBundle(storeDir, storeName) {
  const bundle = {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    storeName,
    files: {}
  };

  for (const file of fs.readdirSync(storeDir)) {
    bundle.files[file] = fs.readFileSync(path.join(storeDir, file), 'utf8');
  }

  return bundle;
}

/**
 * Reads a bundle off disk and checks it is one of ours before any of it is
 * believed.
 *
 * The checks are in the order that matters: a file that is not JSON, a JSON
 * document that is not a bundle, and a bundle with no master.json are three
 * different mistakes and each says so.
 *
 * @param {string} backupPath
 * @returns {object} the parsed bundle
 * @throws {KeystoreError} with code BAD_BACKUP
 */
function readBundle(backupPath) {
  if (!fs.existsSync(backupPath)) {
    throw new KeystoreError(ErrorCodes.BAD_BACKUP, `backup file not found: ${backupPath}`);
  }

  let bundle;
  try {
    bundle = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
  } catch (cause) {
    throw new KeystoreError(
      ErrorCodes.BAD_BACKUP,
      `invalid backup file: ${backupPath} is not readable as JSON`,
      { cause }
    );
  }

  if (!bundle || bundle.format !== BACKUP_FORMAT || !bundle.files) {
    throw new KeystoreError(
      ErrorCodes.BAD_BACKUP,
      `invalid backup file: ${backupPath} is not a keystore bundle`
    );
  }
  if (bundle.version > BACKUP_VERSION) {
    throw new KeystoreError(
      ErrorCodes.UNSUPPORTED_FORMAT,
      `backup was written in bundle format ${bundle.version}, and this build reads up to ${BACKUP_VERSION}`
    );
  }
  if (!bundle.files[MASTER_FILE]) {
    throw new KeystoreError(ErrorCodes.BAD_BACKUP, `invalid backup: ${MASTER_FILE} not found in bundle`);
  }

  return bundle;
}

/**
 * Writes a bundle's files into a target directory.
 *
 * Every name is reduced to its basename first. A bundle is an untrusted file
 * that arrived over a wire, and `"files": {"../../.ssh/authorized_keys": "..."}`
 * is a bundle someone could write by hand.
 *
 * @param {object} bundle
 * @param {string} targetDir
 */
function writeBundle(bundle, targetDir) {
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }
  for (const [file, content] of Object.entries(bundle.files)) {
    fs.writeFileSync(path.join(targetDir, path.basename(file)), content);
  }
}

module.exports = { buildBundle, readBundle, writeBundle };
