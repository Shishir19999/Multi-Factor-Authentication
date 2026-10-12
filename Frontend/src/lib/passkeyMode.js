// Passkey mode. Real mode always uses the browser's WebAuthn. The Live preview can use a clearly labelled
// software authenticator when the browser has no WebAuthn support (or when the visitor chooses it).
import { IS_PREVIEW } from '../config';
import { realPasskeysAvailable } from './webauthnClient';

const KEY = 'mfa_sim_passkey_pref';

export const canSimulate = IS_PREVIEW;
export const realAvailable = () => realPasskeysAvailable();

export function wantsSimulation() {
  if (!IS_PREVIEW) return false;
  if (!realPasskeysAvailable()) return true;
  try { return localStorage.getItem(KEY) === '1'; } catch { return false; }
}

export function setWantsSimulation(on) {
  try { localStorage.setItem(KEY, on ? '1' : '0'); } catch { /* ignore */ }
}
