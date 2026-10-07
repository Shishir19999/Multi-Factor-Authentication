// Pure unit tests: RFC 4226 / RFC 6238 vectors, base32, backup codes, password policy. No DB, no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Encode, base32Decode, hotp, totp, verifyTotp, otpauthUrl, generateSecret } from '../totp.js';
import { generateBackupCodes, hashBackupCode, consumeBackupCode, normalizeBackupCode } from '../backupCodes.js';
import { validatePassword } from '../password.js';

const sha1Key = Buffer.from('12345678901234567890');
const sha256Key = Buffer.from('12345678901234567890123456789012');
const sha512Key = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234');

test('RFC 4226 appendix D HOTP vectors', () => {
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  expected.forEach((code, i) => assert.equal(hotp(sha1Key, i), code));
});

test('RFC 6238 appendix B TOTP vectors (8 digits, SHA1/SHA256/SHA512)', () => {
  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [t, a, b, c] of vectors) {
    assert.equal(totp(sha1Key, t * 1000, { digits: 8 }), a, `sha1 @${t}`);
    assert.equal(totp(sha256Key, t * 1000, { digits: 8, algorithm: 'sha256' }), b, `sha256 @${t}`);
    assert.equal(totp(sha512Key, t * 1000, { digits: 8, algorithm: 'sha512' }), c, `sha512 @${t}`);
  }
});

test('base32 round trips and matches RFC 4648 vectors', () => {
  assert.equal(base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI');
  assert.equal(base32Decode('MZXW6YTBOI=====').toString(), 'foobar');
  assert.equal(base32Decode('mzxw 6ytb-oi').toString(), 'foobar');
  assert.throws(() => base32Decode('abc1'));
  const secret = generateSecret();
  assert.match(secret, /^[A-Z2-7]{32}$/);
  assert.equal(base32Encode(base32Decode(secret)), secret);
});

test('verifyTotp accepts the +-1 step window only and returns the step', () => {
  const secret = base32Encode(sha1Key);
  const now = 1111111109 * 1000;
  const code = totp(sha1Key, now);
  assert.equal(verifyTotp(secret, code, { timeMs: now }), Math.floor(now / 30000));
  assert.notEqual(verifyTotp(secret, code, { timeMs: now + 30000 }), null);
  assert.equal(verifyTotp(secret, code, { timeMs: now + 90000 }), null);
  assert.equal(verifyTotp(secret, 'abcdef', { timeMs: now }), null);
  assert.equal(verifyTotp(secret, '12345', { timeMs: now }), null);
});

test('otpauth URL carries secret and issuer', () => {
  const url = otpauthUrl({ secret: 'ABCDEFGH', email: 'you@example.com', issuer: 'Demo App' });
  assert.equal(url, 'otpauth://totp/Demo%20App:you%40example.com?secret=ABCDEFGH&issuer=Demo%20App&algorithm=SHA1&digits=6&period=30');
});

test('backup codes: unique, hashed, single use, tolerant formatting', () => {
  const codes = generateBackupCodes();
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10);
  codes.forEach((c) => assert.match(c, /^[a-z2-9]{5}-[a-z2-9]{5}$/));
  const hashes = codes.map(hashBackupCode);
  assert.ok(!hashes.includes(codes[0]));
  const rest = consumeBackupCode(hashes, codes[3].toUpperCase().replace('-', ' '));
  assert.equal(rest.length, 9);
  assert.equal(consumeBackupCode(rest, codes[3]), null, 'already used');
  assert.equal(consumeBackupCode(hashes, 'nope'), null);
  assert.equal(normalizeBackupCode(' ABCDE-fghjk '), 'abcdefghjk');
});

test('password policy', () => {
  assert.match(validatePassword('short1'), /at least 8/);
  assert.match(validatePassword('onlyletters'), /letter and one number/);
  assert.match(validatePassword('12345678'), /letter and one number/);
  assert.match(validatePassword('a1'.repeat(40)), /at most/);
  assert.equal(validatePassword('secret12'), null);
  assert.match(validatePassword(undefined), /required/);
});
