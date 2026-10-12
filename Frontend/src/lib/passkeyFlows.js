// The three passkey ceremonies, each = server options -> browser (or simulated) authenticator -> server verify.
import { api } from '../api';
import { createPasskey, getPasskey } from './webauthnClient';
import { wantsSimulation } from './passkeyMode';

// Sign in with a passkey (no password) or use one as the second step after the password (purpose "mfa").
export async function passkeySignIn({ purpose = 'login', email, trust } = {}) {
  const { challengeId, options } = await api.passkeyOptions({ purpose, email });
  const response = await getPasskey(options, { simulate: wantsSimulation() });
  return api.passkeyVerify({ purpose, challengeId, response, email, trust });
}

export async function passkeyRegister(name) {
  const { challengeId, options } = await api.passkeyRegisterOptions();
  const response = await createPasskey(options, { simulate: wantsSimulation() });
  return api.passkeyRegisterVerify({ challengeId, response, name });
}

export async function passkeyStepUp() {
  const { challengeId, options } = await api.passkeyStepUpOptions();
  const response = await getPasskey(options, { simulate: wantsSimulation() });
  return api.passkeyStepUpVerify({ challengeId, response });
}
