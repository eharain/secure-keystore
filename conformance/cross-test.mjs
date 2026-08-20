#!/usr/bin/env node
// Every implementation writes; every implementation reads what all the others
// wrote.
//
//   node conformance/cross-test.mjs            # whatever is runnable here
//   node conformance/cross-test.mjs --json     # machine-readable
//   node conformance/cross-test.mjs --keep     # leave the scratch directory
//
// The fixture corpus (manifest.json) pins one direction: bytes written once, by
// JavaScript, decrypted by everyone. That catches a reader that is wrong. It
// cannot catch a *writer* that is wrong in a way its own reader agrees with -
// the two halves of one implementation can be consistently, privately incorrect
// and the corpus would never know.
//
// This closes that. Each implementation writes a store, a token and a bundle,
// and every implementation reads all of them. An N x N matrix, where the corpus
// is one row.
//
// It drives the command lines rather than the libraries, because the CLI is the
// one interface all six share - so it tests the format, the verbs, the flags and
// the --json contract in one pass.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const flags = new Set(process.argv.slice(2));
const asJson = flags.has('--json');
const keep = flags.has('--keep');

// ── What we encrypt ──────────────────────────────────────────────────────────
//
// Chosen to break things, and deliberately the same shapes the fixture corpus
// uses: an empty value, the format's own delimiter, unicode past the BMP, a
// value that looks like a token but is not.
//
// Values go in through `set` rather than an input file, because the input
// formats cannot carry a leading space or an empty value faithfully - that is a
// property of the input format, not of the store, and the corpus covers it
// separately.

const USER_KEY = 'cross-test-🔐-£€-ключ-!@#:;';
const MASTER_KEY = 'cross-test-master';

const VALUES = {
  api_key: 'sk_live_abc123',
  empty: '',
  colons: ':::',
  delimited: 'a:b:c:d:e:f',
  unicode: '🔐 ключ ñ 日本語',
  json_ish: '{"nested":{"a":[1,2,3]},"b":null}',
  long: 'x'.repeat(3000),
  looks_like_token: 'skv2:not:really:a:token:at:all',
  spaces: '  leading and trailing  '
};

// Key names that must survive sanitising without colliding.
const AWKWARD_KEYS = {
  'a/b': 'slash',
  'a_b': 'underscore - must not collide with a/b',
  '../escape': 'traversal',
  'ключ': 'unicode key name'
};

const ALL = { ...VALUES, ...AWKWARD_KEYS };

// Low on purpose: this runs 6 writers x 6 readers and the iteration count is
// not what is under test.
const ITERATIONS = 10000;

// ── The implementations ──────────────────────────────────────────────────────
//
// Each is a command prefix. Override any of them with the environment variable,
// which is how CI points at built binaries.

const IMPLEMENTATIONS = [
  {
    id: 'javascript',
    env: 'SK_JAVASCRIPT',
    command: [process.execPath, join(ROOT, 'javascript', 'bin', 'cli.js')]
  },
  {
    id: 'go',
    env: 'SK_GO',
    command: [join(ROOT, 'go', 'secure-keystore.exe')],
    fallback: [join(ROOT, 'go', 'secure-keystore')]
  },
  {
    id: 'dotnet',
    env: 'SK_DOTNET',
    command: [
      'dotnet',
      join(ROOT, 'dotnet', 'src', 'TechStyle.SecureKeystore.Cli', 'bin', 'Debug', 'net8.0', 'secure-keystore.dll')
    ]
  },
  {
    id: 'python',
    env: 'SK_PYTHON',
    command: [process.env.SK_PYTHON_EXE || 'python', '-m', 'secure_keystore']
  },
  {
    id: 'php',
    env: 'SK_PHP',
    command: [process.env.SK_PHP_EXE || 'php', join(ROOT, 'php', 'bin', 'secure-keystore')]
  },
  {
    id: 'rust',
    env: 'SK_RUST',
    command: [join(ROOT, 'rust', 'target', 'debug', 'secure-keystore.exe')],
    fallback: [join(ROOT, 'rust', 'target', 'debug', 'secure-keystore')]
  }
];

function resolveCommand(implementation) {
  const override = process.env[implementation.env];
  if (override) return override.split(' ').filter(Boolean);

  const [head] = implementation.command;
  if (head.includes('/') || head.includes('\\')) {
    if (existsSync(head)) return implementation.command;
    if (implementation.fallback && existsSync(implementation.fallback[0])) return implementation.fallback;
    return null;
  }

  return implementation.command;   // on PATH, or it will fail the probe below
}

/** Runs one implementation's CLI. Returns { status, stdout, stderr }. */
function run(command, args, { allowFailure = false } = {}) {
  const [executable, ...prefix] = command;

  try {
    const stdout = execFileSync(executable, [...prefix, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024
    });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    if (!allowFailure) {
      const detail = (error.stderr || error.stdout || error.message || '').trim();
      throw new Error(`${executable} ${args.join(' ')}\n${detail}`);
    }
    return {
      status: error.status ?? 1,
      stdout: error.stdout || '',
      stderr: error.stderr || String(error.message)
    };
  }
}

function runJson(command, args, options) {
  const result = run(command, ['--json', ...args], options);
  const text = (result.stdout || result.stderr).trim();

  try {
    return { ...result, data: JSON.parse(text) };
  } catch {
    throw new Error(`expected JSON from ${args.join(' ')}, got:\n${text.slice(0, 400)}`);
  }
}

/** True if the command runs at all. */
function probe(command) {
  try {
    return run(command, ['--version'], { allowFailure: true }).status === 0;
  } catch {
    return false;
  }
}

// ── The run ──────────────────────────────────────────────────────────────────

const scratch = mkdtempSync(join(tmpdir(), 'secure-keystore-cross-'));
const keystore = join(scratch, '.keystore');
mkdirSync(keystore, { recursive: true });

const log = asJson ? () => {} : (line = '') => process.stdout.write(`${line}\n`);

const available = [];
const missing = [];

for (const implementation of IMPLEMENTATIONS) {
  const command = resolveCommand(implementation);
  if (command && probe(command)) {
    available.push({ ...implementation, command });
  } else {
    missing.push(implementation.id);
  }
}

if (available.length === 0) {
  process.stderr.write('No implementations are runnable. Build them first.\n');
  process.exit(1);
}

log(`secure-keystore cross-implementation test`);
log(`${available.length} runnable: ${available.map(one => one.id).join(', ')}`);
if (missing.length) log(`${missing.length} skipped: ${missing.join(', ')}`);
log();

const failures = [];
const artefacts = [];

function record(kind, writer, reader, detail) {
  failures.push({ kind, writer, reader, detail });
}

// ── Phase 1: every implementation writes ─────────────────────────────────────

log('Writing:');

for (const writer of available) {
  const store = `${writer.id}-store`;
  const input = join(scratch, `${writer.id}.env`);

  // The input file only carries the master key and one placeholder; every
  // awkward value goes in through `set`, which is the path that must agree.
  writeFileSync(input, `master=${MASTER_KEY}\nplaceholder=x\n`, 'utf8');

  try {
    run(writer.command, ['--keystore', keystore, '--iterations', String(ITERATIONS), '--quiet', 'secure', input, USER_KEY, store]);

    for (const [key, value] of Object.entries(ALL)) {
      run(writer.command, ['--keystore', keystore, '--iterations', String(ITERATIONS), '--quiet', 'set', key, value, USER_KEY, store]);
    }

    run(writer.command, ['--keystore', keystore, '--quiet', 'delete', 'placeholder', store]);

    const token = run(writer.command, ['--iterations', String(ITERATIONS), '--quiet', 'encrypt', VALUES.unicode, USER_KEY]).stdout.trim();

    const bundle = join(scratch, `${writer.id}.skb`);
    run(writer.command, ['--keystore', keystore, '--quiet', 'export', store, bundle]);

    artefacts.push({ writer: writer.id, store, token, bundle });
    log(`  ${writer.id.padEnd(11)} store + token + bundle`);
  } catch (error) {
    record('write', writer.id, '-', error.message);
    log(`  ${writer.id.padEnd(11)} FAILED TO WRITE - ${error.message.split('\n')[0]}`);
  }
}

// ── Phase 2: every implementation reads everything ───────────────────────────

log();
log('Reading (rows are readers, columns are writers):');
log();

const width = 12;
const header = ['reader'.padEnd(width), ...artefacts.map(a => a.writer.padEnd(width))].join('');
log(`  ${header}`);
log(`  ${'-'.repeat(header.length)}`);

const matrix = {};

for (const reader of available) {
  matrix[reader.id] = {};
  const cells = [];

  for (const artefact of artefacts) {
    const problems = [];

    // 2a. The store: read every value back and compare exactly.
    try {
      const { data } = runJson(reader.command, ['--keystore', keystore, 'all', artefact.store, USER_KEY]);
      const values = data.values || {};

      for (const [key, expected] of Object.entries(ALL)) {
        if (!(key in values)) problems.push(`store: missing ${key}`);
        else if (values[key] !== expected) problems.push(`store: ${key} differs`);
      }

      const extra = Object.keys(values).filter(key => !(key in ALL));
      if (extra.length) problems.push(`store: unexpected ${extra.join(',')}`);
    } catch (error) {
      problems.push(`store: ${error.message.split('\n').pop()}`);
    }

    // 2b. The token.
    try {
      const { data } = runJson(reader.command, ['decrypt', artefact.token, USER_KEY]);
      if (data.value !== VALUES.unicode) problems.push('token: value differs');
    } catch (error) {
      problems.push(`token: ${error.message.split('\n').pop()}`);
    }

    // 2c. The bundle, imported into a keystore of the reader's own.
    try {
      const target = join(scratch, `import-${reader.id}-${artefact.writer}`);
      run(reader.command, ['--keystore', target, '--quiet', 'import', artefact.bundle, 'imported']);

      const { data } = runJson(reader.command, ['--keystore', target, 'all', 'imported', USER_KEY]);
      const values = data.values || {};

      for (const [key, expected] of Object.entries(ALL)) {
        if (values[key] !== expected) problems.push(`bundle: ${key} differs`);
      }
    } catch (error) {
      problems.push(`bundle: ${error.message.split('\n').pop()}`);
    }

    matrix[reader.id][artefact.writer] = problems;
    if (problems.length) {
      for (const problem of problems) record('read', artefact.writer, reader.id, problem);
    }

    cells.push((problems.length ? `FAIL(${problems.length})` : 'ok').padEnd(width));
  }

  log(`  ${reader.id.padEnd(width)}${cells.join('')}`);
}

// ── Phase 3: cross-language migration ────────────────────────────────────────
//
// One implementation migrates a store another one wrote, and a third reads the
// result. Migration rewrites every value under fresh salts, so this exercises
// the write path against bytes the writer never produced.

log();
log('Migrating (writer -> migrator -> every reader):');

const migrationFailures = [];

for (const artefact of artefacts) {
  for (const migrator of available) {
    if (migrator.id === artefact.writer) continue;   // covered by each suite already

    const store = `mig-${artefact.writer}-by-${migrator.id}`;
    const target = join(scratch, `mig-${artefact.writer}-${migrator.id}`);

    try {
      run(migrator.command, ['--keystore', target, '--quiet', 'import', artefact.bundle, store]);
      run(migrator.command, ['--keystore', target, '--iterations', String(ITERATIONS), '--quiet', 'migrate', store, USER_KEY]);

      for (const reader of available) {
        const { data } = runJson(reader.command, ['--keystore', target, 'all', store, USER_KEY]);
        const values = data.values || {};

        for (const [key, expected] of Object.entries(ALL)) {
          if (values[key] !== expected) {
            migrationFailures.push(`${artefact.writer} -> ${migrator.id} -> ${reader.id}: ${key} differs`);
            record('migrate', artefact.writer, reader.id, `via ${migrator.id}: ${key} differs`);
          }
        }
      }
    } catch (error) {
      migrationFailures.push(`${artefact.writer} -> ${migrator.id}: ${error.message.split('\n').pop()}`);
      record('migrate', artefact.writer, migrator.id, error.message.split('\n').pop());
    }
  }
}

const migrationCount = artefacts.length * Math.max(0, available.length - 1);
log(`  ${migrationCount} migrations, each read back by all ${available.length}: ` +
  (migrationFailures.length ? `${migrationFailures.length} FAILED` : 'all ok'));

// ── Phase 4: a wrong key is refused, everywhere ──────────────────────────────
//
// Reading correctly is half of it. An implementation that returned something for
// a wrong key would be worse than one that could not read at all.

log();
log('Refusing (a wrong user key, on every writer\'s store):');

let refusalFailures = 0;

for (const reader of available) {
  for (const artefact of artefacts) {
    const result = run(reader.command, ['--keystore', keystore, '--json', 'all', artefact.store, 'the-wrong-key'], { allowFailure: true });
    const output = `${result.stdout}${result.stderr}`;

    if (result.status === 0) {
      record('refusal', artefact.writer, reader.id, 'accepted a wrong user key');
      refusalFailures++;
    } else if (!output.includes('BAD_USER_KEY')) {
      record('refusal', artefact.writer, reader.id, `refused, but not with BAD_USER_KEY: ${output.trim().slice(0, 120)}`);
      refusalFailures++;
    }
  }
}

log(`  ${available.length * artefacts.length} attempts: ` +
  (refusalFailures ? `${refusalFailures} did not refuse with BAD_USER_KEY` : 'all refused with BAD_USER_KEY'));

// ── Report ───────────────────────────────────────────────────────────────────

if (!keep) rmSync(scratch, { recursive: true, force: true });

if (asJson) {
  process.stdout.write(`${JSON.stringify({
    available: available.map(one => one.id),
    skipped: missing,
    matrix,
    failures,
    ok: failures.length === 0
  }, null, 2)}\n`);
} else {
  log();
  if (failures.length === 0) {
    const combinations = available.length * artefacts.length;
    log(`PASS - ${combinations} reader/writer combinations, ${migrationCount} cross-language migrations,`);
    log(`       ${Object.keys(ALL).length} values each, and every wrong key refused.`);
    if (missing.length) log(`       Skipped (not runnable here): ${missing.join(', ')}.`);
  } else {
    log(`FAIL - ${failures.length} problems:`);
    for (const failure of failures.slice(0, 40)) {
      log(`  [${failure.kind}] ${failure.writer} written, ${failure.reader} reading: ${failure.detail}`);
    }
    if (failures.length > 40) log(`  ... and ${failures.length - 40} more`);
  }
  if (keep) log(`\nScratch kept at ${scratch}`);
}

process.exit(failures.length === 0 ? 0 : 1);
