// Minimal CBOR (RFC 8949) encoder/decoder: just what WebAuthn attestation objects and COSE keys use
// (unsigned/negative integers, byte and text strings, arrays, maps, booleans, null).
const textEnc = new TextEncoder();
const textDec = new TextDecoder();

function head(major, n) {
  if (n < 24) return [(major << 5) | n];
  if (n < 0x100) return [(major << 5) | 24, n];
  if (n < 0x10000) return [(major << 5) | 25, n >> 8, n & 0xff];
  return [(major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function encode(value) {
  if (value === null) return Uint8Array.of(0xf6);
  if (value === true) return Uint8Array.of(0xf5);
  if (value === false) return Uint8Array.of(0xf4);
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('CBOR: only integers are supported');
    return Uint8Array.from(value >= 0 ? head(0, value) : head(1, -1 - value));
  }
  if (typeof value === 'string') { const b = textEnc.encode(value); return concat([Uint8Array.from(head(3, b.length)), b]); }
  if (value instanceof Uint8Array) return concat([Uint8Array.from(head(2, value.length)), value]);
  if (Array.isArray(value)) return concat([Uint8Array.from(head(4, value.length)), ...value.map(encode)]);
  if (value instanceof Map) return concat([Uint8Array.from(head(5, value.size)), ...[...value].flatMap(([k, v]) => [encode(k), encode(v)])]);
  throw new Error('CBOR: unsupported value');
}

// Decodes one item starting at `offset`. Returns [value, nextOffset]. Maps decode to Map.
export function decodeAt(bytes, offset = 0) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const first = bytes[offset];
  if (first === undefined) throw new Error('CBOR: unexpected end');
  const major = first >> 5;
  const info = first & 31;
  let pos = offset + 1;
  let n = info;
  if (info === 24) { n = bytes[pos]; pos += 1; }
  else if (info === 25) { n = view.getUint16(pos); pos += 2; }
  else if (info === 26) { n = view.getUint32(pos); pos += 4; }
  else if (info > 26 && major !== 7) throw new Error('CBOR: lengths above 4 GiB are not supported');
  if (major === 0) return [n, pos];
  if (major === 1) return [-1 - n, pos];
  if (major === 2) return [bytes.slice(pos, pos + n), pos + n];
  if (major === 3) return [textDec.decode(bytes.subarray(pos, pos + n)), pos + n];
  if (major === 4) {
    const arr = [];
    for (let i = 0; i < n; i++) { const [v, next] = decodeAt(bytes, pos); arr.push(v); pos = next; }
    return [arr, pos];
  }
  if (major === 5) {
    const map = new Map();
    for (let i = 0; i < n; i++) {
      const [k, afterKey] = decodeAt(bytes, pos);
      const [v, afterValue] = decodeAt(bytes, afterKey);
      map.set(k, v);
      pos = afterValue;
    }
    return [map, pos];
  }
  if (major === 7) {
    if (info === 20) return [false, pos];
    if (info === 21) return [true, pos];
    if (info === 22 || info === 23) return [null, pos];
  }
  throw new Error('CBOR: unsupported item');
}

export const decode = (bytes) => decodeAt(bytes, 0)[0];
