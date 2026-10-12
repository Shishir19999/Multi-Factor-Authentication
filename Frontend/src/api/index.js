// Single entry point for all server calls. The implementation is chosen at build time:
// VITE_DEMO=true builds the Live preview (in-browser backend), otherwise the Express API.
import { IS_PREVIEW } from '../config';
import { clearToken, getDeviceToken, setDeviceToken } from '../auth/auth';
import { ApiError } from './errors';

let implPromise;
const getImpl = () => {
  implPromise ??= IS_PREVIEW
    ? import('./previewApi.js').then((m) => m.previewApi)
    : import('./realApi.js').then((m) => m.realApi);
  return implPromise;
};

export const UNAUTHORIZED_EVENT = 'mfa:unauthorized';
export const ACTION_REQUIRED_EVENT = 'mfa:action-required';

// The step-up dialog registers itself here; it resolves once the visitor re-confirmed (and rejects when cancelled).
let stepUpHandler = null;
export const setStepUpHandler = (fn) => { stepUpHandler = fn; };

// Calls that need a signed-in user. A 401 signs the visitor out everywhere in the UI; STEP_UP_REQUIRED opens the
// re-confirmation dialog and retries once; ACTION_REQUIRED tells the app the account has pending requirements.
function guarded(name) {
  const run = async (args) => (await getImpl())[name](...args);
  return async (...args) => {
    try {
      return await run(args);
    } catch (error) {
      if (error instanceof ApiError) {
        if (error.status === 401 || error.data?.code === 'ACCOUNT_LOCKED') {
          clearToken();
          window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
        } else if (error.data?.code === 'ACTION_REQUIRED') {
          window.dispatchEvent(new CustomEvent(ACTION_REQUIRED_EVENT, { detail: error.data.requirements }));
        } else if (error.data?.code === 'STEP_UP_REQUIRED' && stepUpHandler) {
          await stepUpHandler(error.data.stepUp); // throws a cancellation error when dismissed
          return run(args);
        }
      }
      throw error;
    }
  };
};

const open = (name) => async (...args) => (await getImpl())[name](...args);

export const api = {
  getPolicy: open('getPolicy'),
  register: open('register'),
  login: async (p) => (await getImpl()).login({ ...p, deviceToken: getDeviceToken(p.email) }),
  verifyCode: async (p) => {
    const res = await (await getImpl()).verifyCode(p);
    if (res.deviceToken) setDeviceToken(p.email, res.deviceToken);
    return res;
  },
  resendCode: open('resendCode'),
  passkeyOptions: open('passkeyOptions'),
  passkeyVerify: async (p) => {
    const res = await (await getImpl()).passkeyVerify(p);
    if (res.deviceToken && p.email) setDeviceToken(p.email, res.deviceToken);
    return res;
  },
  recoverRequest: open('recoverRequest'),
  recoverReset: open('recoverReset'),
  recoverAssist: open('recoverAssist'),
  alertRespondByLink: open('alertRespondByLink'),
  logout: async () => { try { await (await getImpl()).logout(); } catch { /* already signed out */ } },
  ...Object.fromEntries([
    'me', 'security', 'activity', 'exportActivity', 'sessions', 'renameSession', 'revokeSession', 'revokeOtherSessions', 'revokeAllSessions', 'revokeTrustedDevices',
    'stepUp', 'changePassword', 'setMethod', 'totpSetup', 'totpEnable', 'regenerateBackupCodes',
    'passkeys', 'passkeyRegisterOptions', 'passkeyRegisterVerify', 'renamePasskey', 'removePasskey', 'passkeyStepUpOptions', 'passkeyStepUpVerify',
    'tokens', 'createToken', 'revokeToken', 'alerts', 'respondAlert', 'setRecoveryEmail', 'verifyRecoveryEmail', 'removeRecoveryEmail',
    'adminStats', 'adminUsers', 'adminUser', 'adminAction', 'adminAudit', 'adminAuditExport', 'adminGetPolicy', 'adminSetPolicy', 'adminTestMail',
  ].map((n) => [n, guarded(n)])),
  callWithToken: open('callWithToken'),
};
