'use strict';

const fs = require('fs');
const path = require('path');
const { MASTER_ENTRY_KEY } = require('./constants');
const { KeystoreError, ErrorCodes } = require('./errors');

// Reading an input file into { masterKey, entries }.
//
// Three formats, chosen by extension, all saying the same thing: a master key
// and a list of key-value pairs. They are parsed here rather than in the store
// so that each one can be tested against a string, with no directory involved -
// which is how the `export ` prefix and the quoted-value cases below came to be
// covered at all.

/** The format names {@link parseText} understands. */
const Formats = { COLON: 'colon', ENV: 'env', JSON: 'json' };

/**
 * The format an input file will be read as, from its extension.
 * `.json` and `.env` are named; everything else is the colon format.
 */
function formatFor(inputFile) {
  const ext = path.extname(inputFile).toLowerCase();
  if (ext === '.json') return Formats.JSON;
  if (ext === '.env') return Formats.ENV;
  return Formats.COLON;
}

/**
 * Reads a file and parses it as whatever its extension says it is.
 *
 * @param {string} inputFile
 * @returns {{masterKey: string|null, entries: Array<{key: string, value: string}>}}
 */
function parseInput(inputFile) {
  let content;
  try {
    content = fs.readFileSync(inputFile, 'utf8');
  } catch (cause) {
    throw new KeystoreError(ErrorCodes.BAD_INPUT, `could not read input file: ${inputFile}`, { cause });
  }
  return parseText(content, formatFor(inputFile));
}

/**
 * Parses input text in a named format. The file-free half of {@link parseInput}.
 *
 * @param {string} content
 * @param {string} format  one of {@link Formats}
 */
function parseText(content, format) {
  switch (format) {
    case Formats.JSON: return parseJson(content);
    case Formats.ENV: return parseEnv(content);
    case Formats.COLON: return parseColon(content);
    default:
      throw new KeystoreError(ErrorCodes.BAD_INPUT, `unknown input format: ${format}`);
  }
}

/**
 * The default format: `master:<key>` on the first line, then `key:value` lines.
 *
 * A value may itself contain colons - only the first one splits - so a URL or a
 * connection string needs no escaping.
 */
function parseColon(content) {
  const lines = content.split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0);

  if (lines.length === 0) {
    throw new KeystoreError(ErrorCodes.BAD_INPUT, 'input file is empty');
  }

  const first = lines[0].split(':');
  if (first[0] !== MASTER_ENTRY_KEY) {
    throw new KeystoreError(
      ErrorCodes.BAD_INPUT,
      `first line must be "${MASTER_ENTRY_KEY}:your_master_key"`
    );
  }
  const masterKey = first.slice(1).join(':');

  const entries = [];
  for (let i = 1; i < lines.length; i++) {
    const parts = lines[i].split(':');
    if (parts.length < 2) continue;
    entries.push({ key: parts[0], value: parts.slice(1).join(':') });
  }

  return { masterKey, entries };
}

/**
 * dotenv syntax: `KEY=value`, with `#` comments, an optional `export ` prefix,
 * and matched single or double quotes stripped from the value. The `master=`
 * line may appear anywhere, unlike the colon format where it must come first.
 */
function parseEnv(content) {
  let masterKey = null;
  const entries = [];

  for (let line of content.split('\n')) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('export ')) line = line.slice('export '.length).trim();

    const eq = line.indexOf('=');
    if (eq === -1) continue;

    const key = line.slice(0, eq).trim();
    if (!key) continue;

    let value = line.slice(eq + 1).trim();
    if (value.length >= 2 &&
        ((value[0] === '"' && value[value.length - 1] === '"') ||
         (value[0] === "'" && value[value.length - 1] === "'"))) {
      value = value.slice(1, -1);
    }

    if (key === MASTER_ENTRY_KEY) { masterKey = value; continue; }
    entries.push({ key, value });
  }

  return { masterKey, entries };
}

/**
 * A flat JSON object, with `master` as one of its properties.
 *
 * Values that are not strings are stringified rather than refused, so a port
 * number or a feature flag lifted straight out of an existing config file goes
 * in without being quoted first. Everything comes back out as a string, which
 * is what the store holds.
 */
function parseJson(content) {
  let object;
  try {
    object = JSON.parse(content);
  } catch (cause) {
    throw new KeystoreError(ErrorCodes.BAD_INPUT, 'invalid JSON input file', { cause });
  }
  if (typeof object !== 'object' || object === null || Array.isArray(object)) {
    throw new KeystoreError(ErrorCodes.BAD_INPUT, 'JSON input must be an object of key-value pairs');
  }

  let masterKey = null;
  const entries = [];
  for (const [key, value] of Object.entries(object)) {
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    if (key === MASTER_ENTRY_KEY) { masterKey = text; continue; }
    entries.push({ key, value: text });
  }

  return { masterKey, entries };
}

module.exports = { Formats, formatFor, parseInput, parseText };
