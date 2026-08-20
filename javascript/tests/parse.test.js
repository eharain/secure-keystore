'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { ErrorCodes } = require('../src');
const { Formats, formatFor, parseText } = require('../src/parse');
const { scratch, USER_KEY } = require('./helpers');

test('the format follows the extension', () => {
  assert.equal(formatFor('keys.json'), Formats.JSON);
  assert.equal(formatFor('keys.env'), Formats.ENV);
  assert.equal(formatFor('keys.txt'), Formats.COLON);
  assert.equal(formatFor('keys'), Formats.COLON);
  assert.equal(formatFor('KEYS.JSON'), Formats.JSON);
});

test('colon format takes the master key from the first line only', () => {
  const parsed = parseText('master:m1\napi:a1\njwt:j1', Formats.COLON);

  assert.equal(parsed.masterKey, 'm1');
  assert.deepEqual(parsed.entries, [
    { key: 'api', value: 'a1' },
    { key: 'jwt', value: 'j1' }
  ]);
});

test('colon format splits on the first colon, so a value may hold more', () => {
  const parsed = parseText('master:m1\nurl:https://host:443/path', Formats.COLON);
  assert.deepEqual(parsed.entries, [{ key: 'url', value: 'https://host:443/path' }]);
});

test('colon format refuses input that does not start with master', () => {
  assert.throws(() => parseText('api:a1\nmaster:m1', Formats.COLON), error => {
    assert.equal(error.code, ErrorCodes.BAD_INPUT);
    assert.match(error.message, /first line must be "master:/);
    return true;
  });

  assert.throws(() => parseText('   \n\n', Formats.COLON), /input file is empty/);
});

test('env format handles comments, export prefixes and quotes', () => {
  const parsed = parseText([
    '# a comment',
    '',
    'master=EnvMaster',
    'export api_key=env_api',
    'jwt_secret="quoted"',
    "db_password='single'",
    'no_equals_sign',
    '=novalue'
  ].join('\n'), Formats.ENV);

  assert.equal(parsed.masterKey, 'EnvMaster');
  assert.deepEqual(parsed.entries, [
    { key: 'api_key', value: 'env_api' },
    { key: 'jwt_secret', value: 'quoted' },
    { key: 'db_password', value: 'single' }
  ]);
});

test('env format finds master wherever it appears', () => {
  const parsed = parseText('api=a\nmaster=m\njwt=j', Formats.ENV);
  assert.equal(parsed.masterKey, 'm');
  assert.equal(parsed.entries.length, 2);
});

test('json format stringifies values that are not strings', () => {
  const parsed = parseText(JSON.stringify({
    master: 'JsonMaster',
    api_key: 'json_api',
    port: 8080,
    enabled: true,
    nested: { a: 1 }
  }), Formats.JSON);

  assert.equal(parsed.masterKey, 'JsonMaster');
  assert.deepEqual(parsed.entries, [
    { key: 'api_key', value: 'json_api' },
    { key: 'port', value: '8080' },
    { key: 'enabled', value: 'true' },
    { key: 'nested', value: '{"a":1}' }
  ]);
});

test('json format refuses an array and refuses broken JSON', () => {
  assert.throws(() => parseText('[1,2,3]', Formats.JSON), /must be an object/);
  assert.throws(() => parseText('{oops}', Formats.JSON), error => {
    assert.equal(error.code, ErrorCodes.BAD_INPUT);
    return true;
  });
});

test('every format reaches the store and reads back the same', t => {
  const s = scratch();
  t.after(s.cleanup);

  s.store.secure(s.file('keys.env', 'master=EnvMaster\nexport api_key=env_api\njwt="env_jwt"'), USER_KEY, 'env-store');
  assert.equal(s.store.get('api_key', USER_KEY, 'env-store'), 'env_api');
  assert.equal(s.store.get('jwt', USER_KEY, 'env-store'), 'env_jwt');

  s.store.secure(s.file('keys.json', JSON.stringify({ master: 'JsonMaster', api_key: 'json_api', port: 8080 })), USER_KEY, 'json-store');
  assert.equal(s.store.get('api_key', USER_KEY, 'json-store'), 'json_api');
  assert.equal(s.store.get('port', USER_KEY, 'json-store'), '8080');
});

test('input with no master key is refused before anything is written', t => {
  const s = scratch();
  t.after(s.cleanup);

  assert.throws(() => s.store.secure(s.file('keys.env', 'api_key=a'), USER_KEY, 'no-master'), error => {
    assert.equal(error.code, ErrorCodes.BAD_INPUT);
    assert.match(error.message, /must define a master key/);
    return true;
  });

  assert.deepEqual(s.store.listStores(), []);
});

test('input with a master key and nothing else is refused', t => {
  const s = scratch();
  t.after(s.cleanup);

  assert.throws(
    () => s.store.secure(s.file('keys.env', 'master=only'), USER_KEY, 'empty'),
    /no key-value entries/
  );
});
