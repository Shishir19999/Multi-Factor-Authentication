// Browser side of passkeys. Uses the real WebAuthn API (navigator.credentials) when it is available. In the Live
// preview only, a clearly labelled software authenticator (WebCrypto, stored in localStorage) can stand in when
// the browser has no WebAuthn support or the visitor prefers it. Both produce the standard JSON response shape.
import { b64uToBytes, bytesToB64u } from '../shared/b64u.js';
import { encode } from './cbor.js';
import { rawToDer } from './webauthnServer.js';

const SIM_KEY = 'mfa_sim_passkeys';
const enc = new TextEncoder();
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

export const realPasskeysAvailable = () => typeof window !== 'undefined' && !!window.isSecureContext
  && typeof window.PublicKeyCredential === 'function' && !!navigator.credentials?.create && !!navigator.credentials?.get;

// ---- real browser API ----
const buf = (b64u) => b64uToBytes(b64u);
const out = (b) => bytesToB64u(new Uint8Array(b));

async function createReal(options) {
  const publicKey = {
    ...options,
    challenge: buf(options.challenge),
    user: { ...options.user, id: buf(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: buf(c.id) })),
  };
  const cred = await navigator.credentials.create({ publicKey });
  if (!cred) throw new Error('No passkey was created.');
  return {
    id: cred.id, rawId: out(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults?.() || {},
    response: { clientDataJSON: out(cred.response.clientDataJSON), attestationObject: out(cred.response.attestationObject), transports: cred.response.getTransports?.() || [] },
  };
}

async function getReal(options) {
  const publicKey = {
    challenge: buf(options.challenge), rpId: options.rpId, timeout: options.timeout, userVerification: options.userVerification || 'required',
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: buf(c.id) })),
  };
  const cred = await navigator.credentials.get({ publicKey });
  if (!cred) throw new Error('No passkey was used.');
  return {
    id: cred.id, rawId: out(cred.rawId), type: cred.type, clientExtensionResults: cred.getClientExtensionResults?.() || {},
    response: {
      clientDataJSON: out(cred.response.clientDataJSON), authenticatorData: out(cred.response.authenticatorData), signature: out(cred.response.signature),
      userHandle: cred.response.userHandle ? out(cred.response.userHandle) : undefined,
    },
  };
}

// ---- simulated authenticator (Live preview only) ----
const readSim = () => { try { return JSON.parse(localStorage.getItem(SIM_KEY) || '[]'); } catch { return []; } };
const writeSim = (list) => { try { localStorage.setItem(SIM_KEY, JSON.stringify(list)); } catch { /* storage blocked */ } };

export const hasSimulatedPasskey = (rpId) => readSim().some((k) => k.rpId === rpId);
export const clearSimulatedPasskeys = () => { try { localStorage.removeItem(SIM_KEY); } catch { /* ignore */ } };

function authData(rpHash, flags, counter, extra = new Uint8Array(0)) {
  const head = new Uint8Array(37);
  head.set(rpHash, 0);
  head[32] = flags;
  new DataView(head.buffer).setUint32(33, counter);
  return Uint8Array.from([...head, ...extra]);
}

async function createSimulated(options) {
  const rpId = options.rp.id;
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const credId = crypto.getRandomValues(new Uint8Array(32));
  const cose = encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, b64uToBytes(pub.x)], [-3, b64uToBytes(pub.y)]]));
  const idLen = Uint8Array.of(0, credId.length);
  const data = authData(await sha256(enc.encode(rpId)), 0x45, 0, Uint8Array.from([...new Uint8Array(16), ...idLen, ...credId, ...cose]));
  const clientData = enc.encode(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: location.origin, crossOrigin: false }));
  writeSim([...readSim(), { credId: bytesToB64u(credId), rpId, userHandle: options.user.id, userName: options.user.name, jwk: priv, counter: 0 }]);
  const id = bytesToB64u(credId);
  return {
    id, rawId: id, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: {},
    response: {
      clientDataJSON: bytesToB64u(clientData),
      attestationObject: bytesToB64u(encode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', data]]))),
      transports: ['internal'],
    },
  };
}

async function getSimulated(options) {
  const allowed = (options.allowCredentials || []).map((c) => c.id);
  const list = readSim().filter((k) => k.rpId === options.rpId && (allowed.length === 0 || allowed.includes(k.credId)));
  const entry = list.at(-1);
  if (!entry) throw Object.assign(new Error('No simulated passkey found for this site.'), { name: 'NotAllowedError' });
  entry.counter += 1;
  writeSim(readSim().map((k) => (k.credId === entry.credId ? entry : k)));
  const data = authData(await sha256(enc.encode(options.rpId)), 0x05, entry.counter);
  const clientData = enc.encode(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: location.origin, crossOrigin: false }));
  const key = await crypto.subtle.importKey('jwk', entry.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, Uint8Array.from([...data, ...(await sha256(clientData))])));
  return {
    id: entry.credId, rawId: entry.credId, type: 'public-key', clientExtensionResults: {},
    response: { clientDataJSON: bytesToB64u(clientData), authenticatorData: bytesToB64u(data), signature: bytesToB64u(rawToDer(raw)), userHandle: entry.userHandle },
  };
}

// options are the JSON options produced by the server (real or preview). simulate: use the software authenticator.
export const createPasskey = (options, { simulate = false } = {}) => (simulate ? createSimulated(options) : createReal(options));
export const getPasskey = (options, { simulate = false } = {}) => (simulate ? getSimulated(options) : getReal(options));

export function passkeyErrorMessage(error) {
  const n = error?.name;
  if (n === 'NotAllowedError' || n === 'AbortError') return 'The passkey prompt was cancelled or timed out. Try again.';
  if (n === 'InvalidStateError') return 'This passkey is already registered on this device.';
  if (n === 'NotSupportedError' || n === 'SecurityError') return 'This browser or page cannot use passkeys here.';
  return error?.message || 'Something went wrong with the passkey.';
}
