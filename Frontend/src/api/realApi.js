// Talks to the Express backend. Same interface as demoApi.js.
import axios from 'axios';
import { API_URL } from '../config';
import { getToken } from '../auth/auth';
import { ApiError } from './errors';

const http = axios.create({ baseURL: API_URL });

async function call(method, url, data, { auth = true } = {}) {
  try {
    const res = await http.request({
      method,
      url,
      data,
      headers: auth && getToken() ? { Authorization: `Bearer ${getToken()}` } : undefined,
    });
    if (res.data && res.data.success === false) {
      throw new ApiError(res.data.message || 'Request failed', { status: 200, data: res.data });
    }
    return res.data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error.response) {
      const d = error.response.data || {};
      throw new ApiError(d.message || 'Request failed', { status: error.response.status, data: d });
    }
    throw new ApiError('Cannot reach the server. Check your connection and try again.', { status: 0 });
  }
}

export const realApi = {
  register: ({ email, password }) => call('post', '/auth/register', { email, password }, { auth: false }),

  async login({ email, password, deviceToken }) {
    const d = await call('post', '/auth/login', { email, password, deviceToken: deviceToken || undefined }, { auth: false });
    if (d.token) return { step: 'done', method: d.method, token: d.token, user: d.user };
    return { step: 'code', method: d.method || 'email', resendCooldownSeconds: d.resendCooldownSeconds };
  },

  async verifyCode({ email, code, trust }) {
    const d = await call('post', '/auth/verify-otp', { email, otp: code, trust: trust || undefined }, { auth: false });
    return { token: d.token, user: d.user, deviceToken: d.deviceToken };
  },

  async resendCode({ email }) {
    const d = await call('post', '/auth/resend-otp', { email }, { auth: false });
    return { resendCooldownSeconds: d.resendCooldownSeconds };
  },

  async me() { return (await call('get', '/auth/me')).user; },
  logout: () => call('post', '/auth/logout'),
  async security() { return (await call('get', '/auth/security')).security; },
  async activity() { return (await call('get', '/auth/activity')).events; },
  async sessions() { return (await call('get', '/auth/sessions')).sessions; },
  revokeSession: (id) => call('delete', `/auth/sessions/${encodeURIComponent(id)}`),
  revokeOtherSessions: () => call('post', '/auth/sessions/revoke-others'),
  revokeTrustedDevices: () => call('delete', '/auth/trusted-devices'),
  changePassword: ({ currentPassword, newPassword }) => call('post', '/auth/change-password', { currentPassword, newPassword }),
  async setMethod({ method, password }) { return (await call('post', '/auth/2fa/method', { method, password })).security; },
  async totpSetup({ password }) {
    const d = await call('post', '/auth/2fa/totp/setup', { password });
    return { secret: d.secret, otpauthUrl: d.otpauthUrl };
  },
  async totpEnable({ code }) {
    const d = await call('post', '/auth/2fa/totp/enable', { code });
    return { backupCodes: d.backupCodes, security: d.security };
  },
  async regenerateBackupCodes({ password }) { return (await call('post', '/auth/backup-codes/regenerate', { password })).backupCodes; },
  recoverRequest: ({ email }) => call('post', '/auth/recover/request', { email }, { auth: false }),
  recoverReset: ({ email, code, newPassword }) => call('post', '/auth/recover/reset', { email, code, newPassword }, { auth: false }),
};
