'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const {
  encryptValue,
  decryptValue,
  isEncryptedValue,
  tokenVersion,
  ErrorCodes,
  VALUE_TOKEN_PREFIX
} = require('../src');
const { FAST } = require('./helpers');

const USER_KEY = 'user-key-for-tokens';

// Every call here passes a low iteration count. The real default is 600,000,
// which is the point of it - and which would make this file take a minute. The
// count is asserted separately, once.
const fast = { iterations: FAST };

/**
 * Writes a token exactly as skv1 wrote one: 16-byte salt, 16-byte IV, 100,000
 * rounds, no additional authenticated data. There is no old build to produce
 * one, so the shape is spelled out here.
 */
function legacyToken(plaintext, userKey) {
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(userKey, salt, 100000, 32, 'sha256');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let data = cipher.update(String(plaintext), 'utf8', 'hex');
  data += cipher.final('hex');

  return ['skv1', salt.toString('hex'), iv.toString('hex'), cipher.getAuthTag().toString('hex'), data].join(':');
}

test('a token round-trips', () => {
  const token = encryptValue('sk_live_abc123', USER_KEY, fast);
  assert.equal(decryptValue(token, USER_KEY), 'sk_live_abc123');
});

test('a token is prefixed, has six fields, and records its own cost', () => {
  const token = encryptValue('secret', USER_KEY, fast);
  const parts = token.split(':');

  assert.ok(token.startsWith(`${VALUE_TOKEN_PREFIX}:`));
  assert.equal(VALUE_TOKEN_PREFIX, 'skv2');
  assert.equal(parts.length, 6);
  assert.ok(isEncryptedValue(token));

  // skv1's mistake, corrected: the count is in the token, so it can change.
  assert.equal(Number(parts[1]), FAST);
  assert.equal(parts[2].length, 32);   // 16-byte salt
  assert.equal(parts[3].length, 24);   // 12-byte IV, the length every platform takes
  assert.equal(parts[4].length, 32);   // 16-byte tag
});

test('the default cost follows current guidance', () => {
  // The one place the real default is paid, so that it is asserted somewhere.
  const token = encryptValue('secret', USER_KEY);
  assert.equal(Number(token.split(':')[1]), 600000);
  assert.equal(decryptValue(token, USER_KEY), 'secret');
});

test('the recorded count is what decryption uses, whatever the default is', () => {
  // A token written cheaply still reads back on a build whose default is 600k -
  // which is the entire reason the count is in the token.
  const cheap = encryptValue('secret', USER_KEY, { iterations: FAST });
  assert.equal(decryptValue(cheap, USER_KEY), 'secret');

  const dearer = encryptValue('secret', USER_KEY, { iterations: 20000 });
  assert.equal(Number(dearer.split(':')[1]), 20000);
  assert.equal(decryptValue(dearer, USER_KEY), 'secret');
});

test('an skv1 token still decrypts', () => {
  const token = legacyToken('written_by_1_x', USER_KEY);

  assert.ok(isEncryptedValue(token));
  assert.equal(tokenVersion(token), 'skv1');
  assert.equal(decryptValue(token, USER_KEY), 'written_by_1_x');
});

test('an skv1 token under the wrong key is refused, not guessed at', () => {
  const token = legacyToken('secret', USER_KEY);

  assert.throws(() => decryptValue(token, 'wrong-key'), error => {
    assert.equal(error.code, ErrorCodes.BAD_USER_KEY);
    return true;
  });
});

test('tokenVersion tells the two apart, and says null for anything else', () => {
  assert.equal(tokenVersion(encryptValue('x', USER_KEY, fast)), 'skv2');
  assert.equal(tokenVersion(legacyToken('x', USER_KEY)), 'skv1');
  assert.equal(tokenVersion('plain text'), null);
  assert.equal(tokenVersion(null), null);
});

test('the same secret encrypts to different bytes every time', () => {
  const a = encryptValue('same', USER_KEY, fast);
  const b = encryptValue('same', USER_KEY, fast);

  assert.notEqual(a, b);
  assert.equal(decryptValue(a, USER_KEY), decryptValue(b, USER_KEY));
});

test('empty and absent values pass straight through', () => {
  assert.equal(encryptValue('', USER_KEY, fast), '');
  assert.equal(encryptValue(null, USER_KEY, fast), null);
  assert.equal(encryptValue(undefined, USER_KEY, fast), undefined);
});

test('decryptValue passes a plain string through unchanged', () => {
  assert.equal(decryptValue('not encrypted', USER_KEY), 'not encrypted');
  assert.equal(decryptValue(null, USER_KEY), null);
  assert.ok(!isEncryptedValue('not encrypted'));
});

test('the wrong user key is refused, not guessed at', () => {
  const token = encryptValue('secret', USER_KEY, fast);

  assert.throws(() => decryptValue(token, 'wrong-key'), error => {
    assert.equal(error.code, ErrorCodes.BAD_USER_KEY);
    return true;
  });
});

test('a tampered ciphertext fails the auth tag', () => {
  const token = encryptValue('secret', USER_KEY, fast);
  const parts = token.split(':');
  parts[5] = parts[5].replace(/^./, char => (char === 'a' ? 'b' : 'a'));

  assert.throws(() => decryptValue(parts.join(':'), USER_KEY), error => {
    assert.equal(error.code, ErrorCodes.BAD_USER_KEY);
    return true;
  });
});

test('a token whose recorded count has been edited fails, rather than nearly working', () => {
  const token = encryptValue('secret', USER_KEY, fast);
  const parts = token.split(':');
  parts[1] = String(FAST + 1);

  assert.throws(() => decryptValue(parts.join(':'), USER_KEY), error => {
    assert.equal(error.code, ErrorCodes.BAD_USER_KEY);
    return true;
  });
});

test('a token with the wrong number of fields is a BAD_TOKEN', () => {
  assert.throws(() => decryptValue(`${VALUE_TOKEN_PREFIX}:only:three`, USER_KEY), error => {
    assert.equal(error.code, ErrorCodes.BAD_TOKEN);
    return true;
  });

  assert.throws(() => decryptValue('skv1:too:few', USER_KEY), error => {
    assert.equal(error.code, ErrorCodes.BAD_TOKEN);
    return true;
  });
});

test('a token whose count is not a number is a BAD_TOKEN', () => {
  assert.throws(() => decryptValue(`${VALUE_TOKEN_PREFIX}:lots:aa:bb:cc:dd`, USER_KEY), error => {
    assert.equal(error.code, ErrorCodes.BAD_TOKEN);
    assert.match(error.message, /iteration count/);
    return true;
  });
});

test('a missing user key is refused on both sides', () => {
  assert.throws(() => encryptValue('secret', '', fast), error => {
    assert.equal(error.code, ErrorCodes.INVALID_ARGUMENT);
    return true;
  });

  const token = encryptValue('secret', USER_KEY, fast);
  assert.throws(() => decryptValue(token, ''), error => {
    assert.equal(error.code, ErrorCodes.INVALID_ARGUMENT);
    return true;
  });
});

test('an absurdly low iteration count is refused', () => {
  assert.throws(() => encryptValue('secret', USER_KEY, { iterations: 1 }), error => {
    assert.equal(error.code, ErrorCodes.INVALID_ARGUMENT);
    return true;
  });
});

test('unicode and long values survive the round trip', () => {
  const cases = ['🔐 ключ', 'x'.repeat(10000), 'line\nbreak\ttab', '{"json":"value"}', ':::colons:::'];

  for (const value of cases) {
    assert.equal(decryptValue(encryptValue(value, USER_KEY, fast), USER_KEY), value);
  }
});
