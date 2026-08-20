'use strict';

const path = require('path');
const {
  DEFAULT_KEYSTORE_DIRNAME,
  DEFAULT_KDF_ITERATIONS,
  MIN_KDF_ITERATIONS
} = require('./constants');
const { KeystoreError, ErrorCodes } = require('./errors');

// What a keystore is allowed to do.
//
// The empty object is a usable set of options - every field has a default that
// is safe on any machine - so `new SecureKeystore()` is the common case and
// stays a one-liner. Change what you need:
//
//   const store = new SecureKeystore({ keystoreDir: '/var/lib/app/keys' });
//
// Options are validated once, in the constructor, rather than on every call.
// A typo therefore surfaces where it was written instead of as a store that
// quietly ends up somewhere unexpected.

/** Returns the options used when none are given. */
function defaultOptions() {
  return {
    keystoreDir: path.join(process.cwd(), DEFAULT_KEYSTORE_DIRNAME),
    iterations: DEFAULT_KDF_ITERATIONS,
    logger: null,
    createDir: true
  };
}

/**
 * Checks that a resolved set of options makes sense.
 *
 * @param {object} options
 * @throws {KeystoreError} with code INVALID_OPTIONS
 */
function validateOptions(options) {
  if (typeof options.keystoreDir !== 'string' || options.keystoreDir.length === 0) {
    throw new KeystoreError(
      ErrorCodes.INVALID_OPTIONS,
      `keystoreDir must be a non-empty path, not ${JSON.stringify(options.keystoreDir)}`
    );
  }
  if (!Number.isInteger(options.iterations) || options.iterations < MIN_KDF_ITERATIONS) {
    throw new KeystoreError(
      ErrorCodes.INVALID_OPTIONS,
      `iterations must be a whole number of at least ${MIN_KDF_ITERATIONS}, not ${options.iterations}`
    );
  }
  if (options.logger !== null && typeof options.logger !== 'function') {
    throw new KeystoreError(
      ErrorCodes.INVALID_OPTIONS,
      'logger must be a function taking one message, or null to stay silent'
    );
  }
  if (typeof options.createDir !== 'boolean') {
    throw new KeystoreError(ErrorCodes.INVALID_OPTIONS, 'createDir must be true or false');
  }
  return options;
}

/**
 * Merges what the caller gave over the defaults and validates the result.
 *
 * An unknown key is an error rather than a silent no-op: `{ keystoreDirectory }`
 * used to mean "write to the current directory and say nothing about it", which
 * is the worst possible reading of a typo.
 *
 * @param {object} [given]
 * @returns {object} a complete, validated set of options
 */
function resolveOptions(given = {}) {
  if (given === null || typeof given !== 'object' || Array.isArray(given)) {
    throw new KeystoreError(ErrorCodes.INVALID_OPTIONS, 'options must be an object');
  }

  const defaults = defaultOptions();
  const unknown = Object.keys(given).filter(key => !(key in defaults));
  if (unknown.length > 0) {
    throw new KeystoreError(
      ErrorCodes.INVALID_OPTIONS,
      `unknown option${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')} - ` +
      `known options are ${Object.keys(defaults).join(', ')}`
    );
  }

  return validateOptions({ ...defaults, ...given });
}

module.exports = { defaultOptions, validateOptions, resolveOptions };
