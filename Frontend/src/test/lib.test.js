import { describe, expect, it } from 'vitest';
import { base32Decode, base32Encode, hotp, totp, verifyTotp, otpauthUrl, secondsRemaining } from '../lib/totp';
import { passwordRules, passwordStrength, passwordValid } from '../lib/password';
import { parallaxShift, isLowPower } from '../lib/motion';

const ascii = (s) => new TextEncoder().encode(s);

describe('totp', () => {
  it('matches RFC 4226 HOTP vectors', async () => {
    const key = ascii('12345678901234567890');
    expect(await hotp(key, 0)).toBe('755224');
    expect(await hotp(key, 1)).toBe('287082');
    expect(await hotp(key, 9)).toBe('520489');
  });
  it('matches RFC 6238 vectors (8 digits)', async () => {
    const key = ascii('12345678901234567890');
    expect(await totp(key, 59000, { digits: 8 })).toBe('94287082');
    expect(await totp(key, 1111111109000, { digits: 8 })).toBe('07081804');
  });
  it('round-trips base32', () => {
    const bytes = ascii('foobar');
    expect(base32Encode(bytes)).toBe('MZXW6YTBOI');
    expect([...base32Decode('MZXW6YTBOI')]).toEqual([...bytes]);
  });
  it('verifies within +-1 step only', async () => {
    const secret = base32Encode(ascii('12345678901234567890'));
    const now = 1_700_000_000_000;
    const code = await totp(base32Decode(secret), now);
    expect(await verifyTotp(secret, code, { timeMs: now + 30000 })).toBeTruthy();
    expect(await verifyTotp(secret, code, { timeMs: now + 120000 })).toBeFalsy();
  });
  it('builds an otpauth URL and a countdown', () => {
    const url = otpauthUrl({ secret: 'JBSWY3DPEHPK3PXP', email: 'you@example.com' });
    expect(url.startsWith('otpauth://totp/')).toBe(true);
    expect(url).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(secondsRemaining(0)).toBe(30);
    expect(secondsRemaining(29000)).toBe(1);
  });
});

describe('password', () => {
  it('flags unmet rules and scores strength', () => {
    expect(passwordValid('abc')).toBe(false);
    expect(passwordValid('Str0ng!Passw0rd')).toBe(true);
    expect(passwordRules('').some((r) => r.ok)).toBe(false);
    expect(passwordStrength('Str0ng!Passw0rd-xyz').score).toBeGreaterThan(passwordStrength('abc').score);
    expect(passwordStrength('').empty).toBe(true);
  });
});

describe('motion', () => {
  it('clamps the parallax shift', () => {
    expect(parallaxShift(100, 0.1)).toBe(-10);
    expect(parallaxShift(10000, 0.5)).toBe(-60);
    expect(parallaxShift(-10000, 0.5)).toBe(60);
  });
  it('detects low-power devices', () => {
    expect(isLowPower({ connection: { saveData: true } })).toBe(true);
    expect(isLowPower({ deviceMemory: 1 })).toBe(true);
    expect(isLowPower({ deviceMemory: 8, hardwareConcurrency: 8 })).toBe(false);
  });
});
