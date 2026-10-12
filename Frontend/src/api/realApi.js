// Talks to the Express backend. Same interface as previewApi.js. The session is an HttpOnly cookie
// (withCredentials) and every state-changing request carries the CSRF token returned at sign-in.
import axios from 'axios';
import { API_URL } from '../config';
import { getCsrf, setCsrf } from '../auth/auth';
import { ApiError } from './errors';

const http = axios.create({ baseURL: API_URL, withCredentials: true });
const SAFE = new Set(['get', 'head', 'options']);

function toError(error) {
  if (error instanceof ApiError) return error;
  if (error.response) {
    let d = error.response.data;
    if (typeof d === 'string') { try { d = JSON.parse(d); } catch { d = {}; } }
    return new ApiError(d?.message || 'Request failed', { status: error.response.status, data: d || {} });
  }
  return new ApiError('Cannot reach the server. Check your connection and try again.', { status: 0 });
}

async function call(method, url, data, { params, text = false } = {}) {
  try {
    const res = await http.request({
      method, url, data, params,
      headers: !SAFE.has(method) && getCsrf() ? { 'X-CSRF-Token': getCsrf() } : undefined,
      ...(text ? { responseType: 'text', transformResponse: (x) => x } : {}),
    });
    if (!text && res.data && res.data.success === false) throw new ApiError(res.data.message || 'Request failed', { status: 200, data: res.data });
    return res.data;
  } catch (error) {
    throw toError(error);
  }
}

const session = (d) => { if (d.csrfToken) setCsrf(d.csrfToken); return { token: 'cookie', user: d.user, deviceToken: d.deviceToken, alert: d.alert }; };
const exported = async (url, params, filename, mime) => ({ filename, mime, text: await call('get', url, undefined, { params, text: true }) });

export const realApi = {
  async getPolicy() { return (await call('get', '/auth/policy')).policy; },
  register: ({ email, password }) => call('post', '/auth/register', { email, password }),

  async login({ email, password, deviceToken }) {
    const d = await call('post', '/auth/login', { email, password, deviceToken: deviceToken || undefined });
    if (d.user) return { step: 'done', method: d.method, ...session(d) };
    return { step: 'code', method: d.method || 'email', passkeys: !!d.passkeys, resendCooldownSeconds: d.resendCooldownSeconds };
  },

  async verifyCode({ email, code, trust }) { return session(await call('post', '/auth/verify-otp', { email, otp: code, trust: trust || undefined })); },
  async resendCode({ email }) { return { resendCooldownSeconds: (await call('post', '/auth/resend-otp', { email })).resendCooldownSeconds }; },

  async passkeyOptions({ purpose, email }) { const d = await call('post', '/auth/passkeys/options', { purpose, email }); return { challengeId: d.challengeId, options: d.options }; },
  async passkeyVerify(body) { return session(await call('post', '/auth/passkeys/verify', body)); },

  recoverRequest: ({ email }) => call('post', '/auth/recover/request', { email }),
  recoverReset: ({ email, code, newPassword }) => call('post', '/auth/recover/reset', { email, code, newPassword }),
  recoverAssist: ({ email, message }) => call('post', '/auth/recover/assist', { email, message }),
  alertRespondByLink: ({ t, answer }) => call('post', '/auth/alerts/respond', { t, answer }),

  async me() { const d = await call('get', '/auth/me'); if (d.csrfToken) setCsrf(d.csrfToken); return d.user; },
  async logout() { try { return await call('post', '/auth/logout'); } finally { setCsrf(null); } },
  async security() { return (await call('get', '/auth/security')).security; },
  async activity(params) { return (await call('get', '/auth/activity', undefined, { params })).events; },
  exportActivity: ({ format = 'csv' }) => exported('/auth/activity/export', { format }, format === 'json' ? 'account-activity.json' : 'account-activity.csv', format === 'json' ? 'application/json' : 'text/csv'),
  async sessions() { return (await call('get', '/auth/sessions')).sessions; },
  renameSession: (id, name) => call('patch', `/auth/sessions/${encodeURIComponent(id)}`, { name }),
  revokeSession: (id) => call('delete', `/auth/sessions/${encodeURIComponent(id)}`),
  revokeOtherSessions: () => call('post', '/auth/sessions/revoke-others'),
  async revokeAllSessions() { const d = await call('post', '/auth/sessions/revoke-all'); setCsrf(null); return d; },
  revokeTrustedDevices: () => call('delete', '/auth/trusted-devices'),
  stepUp: (body) => call('post', '/auth/stepup', body),
  changePassword: ({ currentPassword, newPassword }) => call('post', '/auth/change-password', { currentPassword, newPassword }),
  async setMethod({ method }) { return (await call('post', '/auth/2fa/method', { method })).security; },
  async totpSetup() { const d = await call('post', '/auth/2fa/totp/setup', {}); return { secret: d.secret, otpauthUrl: d.otpauthUrl }; },
  async totpEnable({ code }) { const d = await call('post', '/auth/2fa/totp/enable', { code }); return { backupCodes: d.backupCodes, security: d.security }; },
  async regenerateBackupCodes() { return (await call('post', '/auth/backup-codes/regenerate', {})).backupCodes; },

  async passkeys() { return (await call('get', '/auth/passkeys')).passkeys; },
  async passkeyRegisterOptions() { const d = await call('post', '/auth/passkeys/register/options', {}); return { challengeId: d.challengeId, options: d.options }; },
  async passkeyRegisterVerify(body) { return (await call('post', '/auth/passkeys/register/verify', body)).passkeys; },
  renamePasskey: (id, name) => call('patch', `/auth/passkeys/${encodeURIComponent(id)}`, { name }),
  async removePasskey(id) { return (await call('delete', `/auth/passkeys/${encodeURIComponent(id)}`)).passkeys; },
  async passkeyStepUpOptions() { const d = await call('post', '/auth/passkeys/stepup/options', {}); return { challengeId: d.challengeId, options: d.options }; },
  passkeyStepUpVerify: (body) => call('post', '/auth/passkeys/stepup/verify', body),

  async tokens() { return (await call('get', '/auth/tokens')).tokens; },
  async createToken(body) { const d = await call('post', '/auth/tokens', body); return { token: d.token, tokenInfo: d.tokenInfo }; },
  revokeToken: (id) => call('delete', `/auth/tokens/${encodeURIComponent(id)}`),
  // The "try it" box: the request carries only the token, never the session cookie.
  async callWithToken({ token, route }) {
    const [method, url] = route.split(' ');
    try {
      const res = await axios.request({ baseURL: API_URL, url, method, headers: { Authorization: `Bearer ${token}` }, withCredentials: false, validateStatus: () => true });
      return { status: res.status, body: res.data };
    } catch (error) {
      throw toError(error);
    }
  },

  async alerts() { return (await call('get', '/auth/alerts')).alerts; },
  respondAlert: ({ id, answer }) => call('post', `/auth/alerts/${encodeURIComponent(id)}/respond`, { answer }),
  setRecoveryEmail: ({ email }) => call('post', '/auth/recovery-email', { email }),
  async verifyRecoveryEmail({ code }) { return (await call('post', '/auth/recovery-email/verify', { code })).security; },
  async removeRecoveryEmail() { return (await call('delete', '/auth/recovery-email')).security; },

  async adminStats() { return (await call('get', '/admin/stats')).stats; },
  async adminUsers(params) { const d = await call('get', '/admin/users', undefined, { params }); return { users: d.users, total: d.total, page: d.page, pages: d.pages }; },
  async adminUser(id) { const d = await call('get', `/admin/users/${encodeURIComponent(id)}`); return { user: d.user, events: d.events }; },
  async adminAction(id, action, body) { return (await call('post', `/admin/users/${encodeURIComponent(id)}/${action}`, body || {})).user; },
  async adminAudit(params) { const d = await call('get', '/admin/audit', undefined, { params }); return { events: d.events, total: d.total, page: d.page, pages: d.pages }; },
  adminAuditExport: (params) => exported('/admin/audit/export', params, 'audit-log.csv', 'text/csv'),
  async adminGetPolicy() { return (await call('get', '/admin/policy')).policy; },
  async adminSetPolicy(policy) { const d = await call('put', '/admin/policy', policy); return { policy: d.policy, changed: d.changed }; },
  async adminTestMail() { return { message: (await call('post', '/admin/test-mail', {})).message }; },
};
