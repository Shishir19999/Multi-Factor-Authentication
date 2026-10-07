// RFC 4226 (HOTP) / RFC 6238 (TOTP) on top of WebCrypto, plus RFC 4648 base32. Works in browsers and Node 20+.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HASHES = { sha1: 'SHA-1', sha256: 'SHA-256', sha512: 'SHA-512' };

export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
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
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('Invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function generateSecret(bytes = 20) {
  return base32Encode(crypto.getRandomValues(new Uint8Array(bytes)));
}

// Groups a base32 secret in blocks of four for easier manual entry.
export const formatSecret = (secret) => secret.replace(/(.{4})/g, '$1 ').trim();

export async function hotp(keyBytes, counter, { digits = 6, algorithm = 'sha1' } = {}) {
  const msg = new ArrayBuffer(8);
  new DataView(msg).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: HASHES[algorithm] }, false, ['sign']);
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const offset = hmac[hmac.length - 1] & 0xf;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function totp(keyBytes, timeMs = Date.now(), { step = 30, ...opts } = {}) {
  return hotp(keyBytes, Math.floor(timeMs / 1000 / step), opts);
}

export const totpFromSecret = (secretBase32, timeMs = Date.now(), opts) => totp(base32Decode(secretBase32), timeMs, opts);

// Resolves to the matching time step or null; `window` is the number of accepted steps either side of now.
export async function verifyTotp(secretBase32, code, { timeMs = Date.now(), window = 1, step = 30, digits = 6 } = {}) {
  const given = String(code ?? '').replace(/\s/g, '');
  if (given.length !== digits || !/^\d+$/.test(given)) return null;
  const key = base32Decode(secretBase32);
  const center = Math.floor(timeMs / 1000 / step);
  for (let i = -window; i <= window; i++) {
    if ((await hotp(key, center + i, { digits })) === given) return center + i;
  }
  return null;
}

export const secondsRemaining = (timeMs = Date.now(), step = 30) => step - (Math.floor(timeMs / 1000) % step);

export function otpauthUrl({ secret, email, issuer = 'Multi Factor Authentication' }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(email)}`;
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
