// Test helpers: bearer-transport request wrapper, a capture mailer and a software passkey authenticator.
import crypto from 'node:crypto';
import supertest from 'supertest';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { bytesToB64u, b64uToBytes } from '../shared/b64u.js';

// Non-browser clients ask for the session token in the JSON body (browsers get an HttpOnly cookie instead).
export function request(app) {
  const r = supertest(app);
  return new Proxy(r, {
    get: (target, key) => (['get', 'post', 'put', 'patch', 'delete'].includes(key)
      ? (...args) => target[key](...args).set('X-Auth-Transport', 'bearer')
      : target[key]),
  });
}

export const cookieAgent = (app) => supertest.agent(app);

// mail(kind, data) function that records every message instead of sending it.
export function captureMail() {
  const box = [];
  const fn = async (kind, data) => { box.push({ kind, ...data }); };
  fn.box = box;
  fn.last = (kind) => [...box].reverse().find((m) => m.kind === kind);
  fn.clear = () => { box.length = 0; };
  return fn;
}

export const noBreach = async () => ({ status: 'safe' });

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();

export class SoftAuthenticator {
  constructor({ rpID = 'localhost', origin = 'http://localhost:5173' } = {}) {
    this.rpID = rpID;
    this.origin = origin;
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.privateKey = privateKey;
    this.jwk = publicKey.export({ format: 'jwk' });
    this.credentialId = new Uint8Array(crypto.randomBytes(32));
    this.counter = 0;
  }

  get id() { return bytesToB64u(this.credentialId); }

  #authData(flags, extra = Buffer.alloc(0)) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    return Buffer.concat([sha256(this.rpID), Buffer.from([flags]), counter, extra]);
  }

  // options: PublicKeyCredentialCreationOptionsJSON
  create(options, { origin = this.origin } = {}) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }));
    const cose = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, b64uToBytes(this.jwk.x)], [-3, b64uToBytes(this.jwk.y)]]));
    const len = Buffer.alloc(2);
    len.writeUInt16BE(this.credentialId.length);
    const authData = this.#authData(0x45, Buffer.concat([Buffer.alloc(16), len, Buffer.from(this.credentialId), Buffer.from(cose)]));
    const attestationObject = isoCBOR.encode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', new Uint8Array(authData)]]));
    return {
      id: this.id, rawId: this.id, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform',
      response: { clientDataJSON: bytesToB64u(new Uint8Array(clientDataJSON)), attestationObject: bytesToB64u(attestationObject), transports: ['internal'] },
    };
  }

  // options: PublicKeyCredentialRequestOptionsJSON
  get(options, { origin = this.origin, uv = true } = {}) {
    this.counter += 1;
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }));
    const authData = this.#authData(uv ? 0x05 : 0x01);
    const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
    return {
      id: this.id, rawId: this.id, type: 'public-key', clientExtensionResults: {},
      response: {
        clientDataJSON: bytesToB64u(new Uint8Array(clientDataJSON)), authenticatorData: bytesToB64u(new Uint8Array(authData)),
        signature: bytesToB64u(new Uint8Array(signature)),
      },
    };
  }
}
