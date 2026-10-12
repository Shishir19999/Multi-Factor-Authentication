import { describe, expect, it } from 'vitest';
import { encode, decode, decodeAt } from '../lib/cbor';
import { derToRaw, rawToDer, verifyAssertion, verifyRegistration } from '../lib/webauthnServer';
import { createPasskey, getPasskey, clearSimulatedPasskeys } from '../lib/webauthnClient';
import { bytesToB64u } from '../shared/b64u';

describe('cbor', () => {
  it('round-trips integers, strings, bytes, arrays, maps and booleans', () => {
    const value = new Map([[1, 2], [3, -7], [-1, 1], ['fmt', 'none'], ['x', Uint8Array.from([1, 2, 3])], ['list', [0, 23, 24, 255, 256, 65535, 65536, -25]], ['flag', true], ['nil', null]]);
    const back = decode(encode(value));
    expect(back.get(3)).toBe(-7);
    expect(back.get('fmt')).toBe('none');
    expect([...back.get('x')]).toEqual([1, 2, 3]);
    expect(back.get('list')).toEqual([0, 23, 24, 255, 256, 65535, 65536, -25]);
    expect(back.get('flag')).toBe(true);
    expect(back.get('nil')).toBeNull();
  });
  it('matches known encodings and reports the next offset', () => {
    expect([...encode(24)]).toEqual([0x18, 0x18]);
    expect([...encode(-7)]).toEqual([0x26]);
    expect([...encode('abc')]).toEqual([0x63, 0x61, 0x62, 0x63]);
    const seq = Uint8Array.from([...encode(1), ...encode('a')]);
    expect(decodeAt(seq, 0)).toEqual([1, 1]);
    expect(decodeAt(seq, 1)[0]).toBe('a');
    expect(() => decode(Uint8Array.of(0xff))).toThrow();
    expect(() => encode(1.5)).toThrow();
  });
});

describe('ECDSA signature encodings', () => {
  it('converts DER <-> raw (including leading-zero and high-bit integers)', () => {
    const raw = new Uint8Array(64).map((_, i) => (i === 0 ? 0x80 : i === 32 ? 0x00 : i + 1));
    const der = rawToDer(raw);
    expect(der[0]).toBe(0x30);
    expect([...derToRaw(der)]).toEqual([...raw]);
    const small = new Uint8Array(64); small[31] = 5; small[63] = 9;
    expect([...derToRaw(rawToDer(small))]).toEqual([...small]);
  });
});

describe('simulated authenticator against the in-browser verifier', () => {
  const rpId = location.hostname;
  const rp = { id: rpId, name: 'Test' };
  const challenge = () => bytesToB64u(crypto.getRandomValues(new Uint8Array(32)));
  const creation = (c) => ({ rp, user: { id: bytesToB64u(new Uint8Array(32)), name: 'a@example.com', displayName: 'a' }, challenge: c, pubKeyCredParams: [{ type: 'public-key', alg: -7 }] });

  it('verifies registration and assertions, tracks the counter and rejects tampering', async () => {
    clearSimulatedPasskeys();
    const c1 = challenge();
    const reg = await createPasskey(creation(c1), { simulate: true });
    const info = await verifyRegistration({ response: reg, expectedChallenge: c1, expectedOrigin: location.origin, rpId });
    expect(info.credentialId).toBe(reg.id);
    expect(info.alg).toBe(-7);
    expect(info.counter).toBe(0);
    await expect(verifyRegistration({ response: reg, expectedChallenge: challenge(), expectedOrigin: location.origin, rpId })).rejects.toThrow(/Challenge/);
    await expect(verifyRegistration({ response: reg, expectedChallenge: c1, expectedOrigin: 'https://evil.example', rpId })).rejects.toThrow(/origin/);
    await expect(verifyRegistration({ response: reg, expectedChallenge: c1, expectedOrigin: location.origin, rpId: 'other.example' })).rejects.toThrow(/Relying party/);

    const credential = { publicKey: info.publicKey, counter: info.counter };
    const c2 = challenge();
    const get = await getPasskey({ challenge: c2, rpId }, { simulate: true });
    const ok = await verifyAssertion({ response: get, expectedChallenge: c2, expectedOrigin: location.origin, rpId, credential });
    expect(ok.newCounter).toBe(1);
    // replaying the same assertion with the updated counter fails (cloned-authenticator check)
    await expect(verifyAssertion({ response: get, expectedChallenge: c2, expectedOrigin: location.origin, rpId, credential: { ...credential, counter: 1 } })).rejects.toThrow(/counter/);
    // flipped signature
    const forged = structuredClone(get);
    forged.response.signature = forged.response.signature.slice(0, -3) + 'AAA';
    await expect(verifyAssertion({ response: forged, expectedChallenge: c2, expectedOrigin: location.origin, rpId, credential })).rejects.toThrow();
    // another key cannot answer for this credential
    clearSimulatedPasskeys();
    const reg2 = await createPasskey(creation(challenge()), { simulate: true });
    const other = await getPasskey({ challenge: c2, rpId }, { simulate: true });
    expect(other.id).not.toBe(reg2.id === reg.id ? 'x' : reg.id);
    await expect(verifyAssertion({ response: other, expectedChallenge: c2, expectedOrigin: location.origin, rpId, credential })).rejects.toThrow();
  });

  it('asks for a stored credential and honours allowCredentials', async () => {
    clearSimulatedPasskeys();
    await expect(getPasskey({ challenge: challenge(), rpId }, { simulate: true })).rejects.toThrow(/No simulated passkey/);
    const reg = await createPasskey(creation(challenge()), { simulate: true });
    await expect(getPasskey({ challenge: challenge(), rpId, allowCredentials: [{ id: 'nope', type: 'public-key' }] }, { simulate: true })).rejects.toThrow();
    expect((await getPasskey({ challenge: challenge(), rpId, allowCredentials: [{ id: reg.id, type: 'public-key' }] }, { simulate: true })).id).toBe(reg.id);
  });
});
