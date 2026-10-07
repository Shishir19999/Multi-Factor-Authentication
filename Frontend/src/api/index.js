// Single entry point for all server calls. The implementation is chosen at build time:
// VITE_DEMO=true -> in-browser demo backend, otherwise the Express API.
import { IS_DEMO } from '../config';
import { clearToken, getDeviceToken, setDeviceToken } from '../auth/auth';
import { ApiError } from './errors';

let implPromise;
const getImpl = () => {
  implPromise ??= IS_DEMO
    ? import('./demoApi.js').then((m) => m.demoApi)
    : import('./realApi.js').then((m) => m.realApi);
  return implPromise;
};

export const UNAUTHORIZED_EVENT = 'mfa:unauthorized';

// Calls that require a signed-in user: a 401 signs the visitor out everywhere in the UI.
function guarded(name) {
  return async (...args) => {
    try {
      return await (await getImpl())[name](...args);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        clearToken();
        window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
      }
      throw error;
    }
  };
}

const open = (name) => async (...args) => (await getImpl())[name](...args);

export const api = {
  register: open('register'),
  login: async (p) => (await getImpl()).login({ ...p, deviceToken: getDeviceToken(p.email) }),
  verifyCode: async (p) => {
    const res = await (await getImpl()).verifyCode(p);
    if (res.deviceToken) setDeviceToken(p.email, res.deviceToken);
    return res;
  },
  resendCode: open('resendCode'),
  recoverRequest: open('recoverRequest'),
  recoverReset: open('recoverReset'),
  me: guarded('me'),
  logout: async () => { try { await (await getImpl()).logout(); } catch { /* already signed out */ } },
  security: guarded('security'),
  activity: guarded('activity'),
  sessions: guarded('sessions'),
  revokeSession: guarded('revokeSession'),
  revokeOtherSessions: guarded('revokeOtherSessions'),
  revokeTrustedDevices: guarded('revokeTrustedDevices'),
  changePassword: guarded('changePassword'),
  setMethod: guarded('setMethod'),
  totpSetup: guarded('totpSetup'),
  totpEnable: guarded('totpEnable'),
  regenerateBackupCodes: guarded('regenerateBackupCodes'),
};
