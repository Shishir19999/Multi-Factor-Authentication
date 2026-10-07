// RFC 4226 (HOTP) and RFC 6238 (TOTP) with RFC 4648 base32 secrets. Pure functions, unit-tested.
import crypto from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('Invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export const generateSecret = (bytes = 20) => base32Encode(crypto.randomBytes(bytes));

export function hotp(secretBuf, counter, { digits = 6, algorithm = 'sha1' } = {}) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac(algorithm, secretBuf).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function totp(secretBuf, timeMs = Date.now(), { step = 30, ...opts } = {}) {
  return hotp(secretBuf, Math.floor(timeMs / 1000 / step), opts);
}

// Returns the matching time step (number) or null. `window` = accepted steps either side of now.
export function verifyTotp(secretBase32, code, { timeMs = Date.now(), window = 1, step = 30, digits = 6 } = {}) {
  const given = String(code ?? '').replace(/\s/g, '');
  if (given.length !== digits || !/^[0-9]+$/.test(given)) return null;
  const secret = base32Decode(secretBase32);
  const center = Math.floor(timeMs / 1000 / step);
  for (let i = -window; i <= window; i++) {
    const expected = hotp(secret, center + i, { digits });
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(given))) return center + i;
  }
  return null;
}

export function otpauthUrl({ secret, email, issuer = 'Multi Factor Authentication' }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(email)}`;
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
