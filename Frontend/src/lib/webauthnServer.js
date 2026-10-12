// Server side of WebAuthn, running in the browser for the Live preview only. It performs the same checks the real
// API does through @simplewebauthn/server: challenge, origin, RP id hash, user presence + verification, public-key
// extraction, signature (ES256 / RS256) and the signature counter. Attestation is "none".
import { decodeAt } from './cbor.js';
import { b64uToBytes, bytesToB64u } from '../shared/b64u.js';

const enc = new TextEncoder();
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

export const PUBKEY_PARAMS = [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }];

function parseClientData(json, type, expectedChallenge, expectedOrigin) {
  const cd = JSON.parse(new TextDecoder().decode(b64uToBytes(json)));
  if (cd.type !== type) throw new Error('Unexpected ceremony type');
  if (cd.challenge !== expectedChallenge) throw new Error('Challenge mismatch');
  if (cd.origin !== expectedOrigin) throw new Error(`Unexpected origin "${cd.origin}"`);
  return cd;
}

async function checkAuthData(authData, rpId, { needAttested }) {
  if (authData.length < 37) throw new Error('Authenticator data is too short');
  if (!same(authData.subarray(0, 32), await sha256(enc.encode(rpId)))) throw new Error('Relying party mismatch');
  const flags = authData[32];
  if (!(flags & 0x01)) throw new Error('User presence is required');
  if (!(flags & 0x04)) throw new Error('User verification is required');
  if (needAttested && !(flags & 0x40)) throw new Error('No credential in the response');
  return { flags, counter: new DataView(authData.buffer, authData.byteOffset).getUint32(33) };
}

// response: RegistrationResponseJSON. Returns what the preview database stores for the new passkey.
export async function verifyRegistration({ response, expectedChallenge, expectedOrigin, rpId }) {
  parseClientData(response.response.clientDataJSON, 'webauthn.create', expectedChallenge, expectedOrigin);
  const [att] = decodeAt(b64uToBytes(response.response.attestationObject), 0);
  const authData = att.get('authData');
  if (!(authData instanceof Uint8Array)) throw new Error('Malformed attestation');
  const { flags, counter } = await checkAuthData(authData, rpId, { needAttested: true });
  const view = new DataView(authData.buffer, authData.byteOffset);
  const idLen = view.getUint16(53);
  const credId = authData.slice(55, 55 + idLen);
  const [cose] = decodeAt(authData, 55 + idLen);
  const alg = cose.get(3);
  if (![-7, -257].includes(alg)) throw new Error('Unsupported algorithm');
  if (bytesToB64u(credId) !== response.id) throw new Error('Credential id mismatch');
  const keyBytes = authData.slice(55 + idLen);
  return {
    credentialId: response.id, publicKey: bytesToB64u(keyBytes), counter, alg,
    transports: response.response.transports || [], backedUp: !!(flags & 0x10), deviceType: flags & 0x08 ? 'multiDevice' : 'singleDevice',
  };
}

// ECDSA signatures from authenticators are ASN.1 DER; WebCrypto wants raw r||s.
export function derToRaw(der, size = 32) {
  let p = 2;
  if (der[1] & 0x80) p = 2 + (der[1] & 0x7f);
  const readInt = () => {
    const len = der[p + 1];
    let int = der.slice(p + 2, p + 2 + len);
    p += 2 + len;
    while (int.length > size && int[0] === 0) int = int.slice(1);
    const out = new Uint8Array(size);
    out.set(int, size - int.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  return Uint8Array.from([...r, ...s]);
}

export function rawToDer(raw) {
  const half = raw.length / 2;
  const trim = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let out = b.slice(i);
    if (out[0] & 0x80) out = Uint8Array.from([0, ...out]);
    return out;
  };
  const r = trim(raw.slice(0, half));
  const s = trim(raw.slice(half));
  const body = [0x02, r.length, ...r, 0x02, s.length, ...s];
  return Uint8Array.from([0x30, body.length, ...body]);
}

async function importPublicKey(coseB64u) {
  const cose = decodeAt(b64uToBytes(coseB64u), 0)[0];
  const alg = cose.get(3);
  if (alg === -7) {
    const jwk = { kty: 'EC', crv: 'P-256', x: bytesToB64u(cose.get(-2)), y: bytesToB64u(cose.get(-3)), ext: true };
    return { alg, key: await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']) };
  }
  const jwk = { kty: 'RSA', n: bytesToB64u(cose.get(-1)), e: bytesToB64u(cose.get(-2)), alg: 'RS256', ext: true };
  return { alg, key: await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']) };
}

// credential: { publicKey (base64url COSE), counter }. Returns { newCounter }.
export async function verifyAssertion({ response, expectedChallenge, expectedOrigin, rpId, credential }) {
  parseClientData(response.response.clientDataJSON, 'webauthn.get', expectedChallenge, expectedOrigin);
  const authData = b64uToBytes(response.response.authenticatorData);
  const { counter } = await checkAuthData(authData, rpId, { needAttested: false });
  const clientHash = await sha256(b64uToBytes(response.response.clientDataJSON));
  const signed = Uint8Array.from([...authData, ...clientHash]);
  const sig = b64uToBytes(response.response.signature);
  const { alg, key } = await importPublicKey(credential.publicKey);
  const ok = alg === -7
    ? await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRaw(sig), signed)
    : await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sig, signed);
  if (!ok) throw new Error('Signature check failed');
  if ((counter > 0 || credential.counter > 0) && counter <= credential.counter) throw new Error('Signature counter did not increase (cloned authenticator?)');
  return { newCounter: counter };
}
