// Thin wrapper around @simplewebauthn/server: relying-party config plus the four ceremonies used by the API.
import {
  generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { b64uToBytes } from '../shared/b64u.js';

// WEBAUTHN_RP_ID is the registrable domain (default "localhost"); WEBAUTHN_ORIGIN lists the exact browser origins.
export function webauthnConfig(env = process.env, overrides = {}) {
  const origins = (env.WEBAUTHN_ORIGIN || env.CORS_ORIGIN || 'http://localhost:5173').split(',').map((s) => s.trim()).filter(Boolean);
  return { rpID: env.WEBAUTHN_RP_ID || 'localhost', rpName: env.WEBAUTHN_RP_NAME || 'Multi Factor Authentication', origins, ...overrides };
}

export const registrationOptions = (cfg, user) => generateRegistrationOptions({
  rpName: cfg.rpName,
  rpID: cfg.rpID,
  userName: user.email,
  userID: b64uToBytes(user.webauthnUserId),
  attestationType: 'none',
  excludeCredentials: user.passkeys.map((p) => ({ id: p.credentialId, transports: p.transports })),
  authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
  supportedAlgorithmIDs: [-7, -257],
});

export const verifyRegistration = (cfg, response, expectedChallenge) => verifyRegistrationResponse({
  response, expectedChallenge, expectedOrigin: cfg.origins, expectedRPID: cfg.rpID, requireUserVerification: true,
});

export const authenticationOptions = (cfg, passkeys = []) => generateAuthenticationOptions({
  rpID: cfg.rpID,
  userVerification: 'required',
  allowCredentials: passkeys.map((p) => ({ id: p.credentialId, transports: p.transports })),
});

export const verifyAuthentication = (cfg, response, expectedChallenge, passkey) => verifyAuthenticationResponse({
  response,
  expectedChallenge,
  expectedOrigin: cfg.origins,
  expectedRPID: cfg.rpID,
  requireUserVerification: true,
  credential: { id: passkey.credentialId, publicKey: b64uToBytes(passkey.publicKey), counter: passkey.counter || 0, transports: passkey.transports },
});
