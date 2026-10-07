// In-browser demo backend. Same interface and behaviour rules as the Express API (realApi.js):
// PBKDF2-hashed passwords (WebCrypto), e-mail codes delivered to the demo inbox, real RFC 6238 TOTP,
// backup codes, sessions, sign-in log, lockout and recovery. All data lives in localStorage.
import { ApiError } from './errors';
import { getToken } from '../auth/auth';
import { loadDb, saveDb, pushMail } from './demoStore';
import { DEMO_ACCOUNTS, DEMO_BACKUP_CODE, DEMO_PASSWORD, DEMO_TOTP_SECRET } from './demoAccounts';
import { generateSecret, otpauthUrl, verifyTotp } from '../lib/totp';
import { passwordRules } from '../lib/password';

const FAST = import.meta.env.MODE === 'test';
const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;
const RESEND_COOLDOWN_S = 30;
const MAX_LOGIN_FAILURES = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const RECOVERY_TTL_MS = 15 * 60 * 1000;
const TRUSTED_MS = 30 * 24 * 60 * 60 * 1000;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 100000;
const MAX_LOG = 50;
const MAX_SESSIONS = 10;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const latency = () => (FAST ? Promise.resolve() : sleep(160 + Math.random() * 300));
const now = () => Date.now();
const iso = (ms = now()) => new Date(ms).toISOString();
const norm = (e) => String(e || '').trim().toLowerCase();

// ---- crypto helpers (WebCrypto) ----
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
const randomHex = (bytes) => toHex(crypto.getRandomValues(new Uint8Array(bytes)));
const enc = new TextEncoder();
const sha256 = async (text) => toHex(await crypto.subtle.digest('SHA-256', enc.encode(text)));

export async function hashPassword(password, saltHex = randomHex(16), iterations = PBKDF2_ITERATIONS) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: fromHex(saltHex), iterations, hash: 'SHA-256' }, key, 256);
  return `pbkdf2$${iterations}$${saltHex}$${toHex(bits)}`;
}

export async function verifyPassword(password, stored) {
  const [, iterations, salt] = stored.split('$');
  return (await hashPassword(password, salt, Number(iterations))) === stored;
}

const randomCode = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
const BACKUP_CHARS = 'abcdefghjkmnpqrstuvwxyz23456789';
export function generateBackupCodes(count = 10) {
  return Array.from({ length: count }, () => {
    let s = '';
    for (const b of crypto.getRandomValues(new Uint8Array(10))) s += BACKUP_CHARS[b % BACKUP_CHARS.length];
    return `${s.slice(0, 5)}-${s.slice(5)}`;
  });
}
const normBackup = (c) => String(c ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
const hashBackup = (c) => sha256(normBackup(c));

// ---- database ----
const FAKE_UA = {
  firefoxWin: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
  safariIos: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  chromeMac: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36',
};

const fakeIp = () => `203.0.113.${1 + Math.floor(Math.random() * 253)}`;
const ago = (mins) => now() - mins * 60000;

async function seedUser(account) {
  const alice = account.method === 'totp';
  return {
    email: account.email,
    password: await hashPassword(DEMO_PASSWORD),
    method: account.method,
    totpSecret: alice ? DEMO_TOTP_SECRET : null,
    pendingTotpSecret: null,
    lastTotpStep: -1,
    backupCodes: alice ? [await hashBackup(DEMO_BACKUP_CODE)] : [],
    trusted: [],
    failedLogins: 0,
    lockUntil: 0,
    recovery: null,
    createdAt: iso(ago(60 * 24 * 40)),
    sessions: [
      { id: randomHex(16), createdAt: iso(ago(60 * 26)), lastSeen: iso(ago(60 * 3)), ip: '198.51.100.24', userAgent: FAKE_UA.firefoxWin },
      { id: randomHex(16), createdAt: iso(ago(60 * 50)), lastSeen: iso(ago(60 * 20)), ip: '203.0.113.77', userAgent: FAKE_UA.safariIos },
    ],
    events: [
      { id: randomHex(6), at: iso(ago(60 * 3)), event: 'login', ok: true, ip: '198.51.100.24', userAgent: FAKE_UA.firefoxWin },
      { id: randomHex(6), at: iso(ago(60 * 20)), event: 'login', ok: true, ip: '203.0.113.77', userAgent: FAKE_UA.safariIos },
      { id: randomHex(6), at: iso(ago(60 * 30)), event: 'login-failed', ok: false, ip: '192.0.2.15', userAgent: FAKE_UA.chromeMac },
      { id: randomHex(6), at: iso(ago(60 * 24 * 6)), event: 'password-changed', ok: true, ip: '198.51.100.24', userAgent: FAKE_UA.firefoxWin },
    ],
  };
}

let seeding = null;
async function db() {
  let data = loadDb();
  if (!data) {
    seeding ??= (async () => {
      const users = {};
      for (const a of DEMO_ACCOUNTS) users[a.email] = await seedUser(a);
      const fresh = { users, pending: {} };
      saveDb(fresh);
      return fresh;
    })().finally(() => { seeding = null; });
    data = await seeding;
  }
  return data;
}

const deviceInfo = () => ({ ip: fakeIp(), userAgent: typeof navigator === 'undefined' ? '' : navigator.userAgent });

function logEvent(user, event, ok) {
  user.events.unshift({ id: randomHex(6), at: iso(), event, ok, ...deviceInfo() });
  user.events = user.events.slice(0, MAX_LOG);
}

function userFor(data, email) {
  return data.users[norm(email)] || null;
}

async function startSession(data, user, { trust = false } = {}) {
  const cutoff = now() - SESSION_TTL_MS;
  user.sessions = user.sessions.filter((s) => new Date(s.createdAt).getTime() > cutoff);
  const id = randomHex(24);
  user.sessions.push({ id, createdAt: iso(), lastSeen: iso(), ...deviceInfo() });
  user.sessions = user.sessions.slice(-MAX_SESSIONS);
  let deviceToken;
  if (trust && user.method !== 'none') {
    deviceToken = randomHex(32);
    user.trusted = user.trusted.filter((d) => d.expires > now()).slice(-9);
    user.trusted.push({ hash: await sha256(deviceToken), expires: now() + TRUSTED_MS });
  }
  logEvent(user, 'login', true);
  user.failedLogins = 0;
  user.lockUntil = 0;
  delete data.pending[user.email];
  saveDb(data);
  return { token: id, user: publicUser(user), ...(deviceToken ? { deviceToken } : {}) };
}

const publicUser = (u) => ({ id: u.email, email: u.email, twoFactorMethod: u.method, createdAt: u.createdAt });
const securityOf = (u) => ({
  email: u.email,
  twoFactorMethod: u.method,
  backupCodesRemaining: u.backupCodes.length,
  trustedDevices: u.trusted.filter((d) => d.expires > now()).length,
  createdAt: u.createdAt,
});

async function authed() {
  const data = await db();
  const token = getToken();
  if (token) {
    for (const user of Object.values(data.users)) {
      const session = user.sessions.find((s) => s.id === token);
      if (session && new Date(session.createdAt).getTime() > now() - SESSION_TTL_MS) {
        session.lastSeen = iso();
        return { data, user, session };
      }
    }
  }
  throw new ApiError('Session expired. Please sign in again.', { status: 401 });
}

async function reauth(user, password, message = 'Password is incorrect') {
  if (!password || !(await verifyPassword(password, user.password))) throw new ApiError(message, { status: 403 });
}

function checkNewPassword(pw) {
  const failed = passwordRules(pw).find((r) => !r.ok);
  if (failed) throw new ApiError(`Password needs: ${failed.label.toLowerCase()}`, { status: 400 });
}

function sendLoginCode(data, user) {
  const code = randomCode();
  data.pending[user.email] = { kind: 'email', code, expires: now() + OTP_TTL_MS, attempts: 0, sentAt: now() };
  pushMail({
    to: user.email,
    subject: 'Your verification code',
    text: 'Use this code to finish signing in. It is valid for 5 minutes. If you did not try to sign in, change your password.',
    code,
  });
}

export const demoApi = {
  async register({ email, password }) {
    await latency();
    const data = await db();
    if (!/^\S+@\S+\.\S+$/.test((email || '').trim())) throw new ApiError('A valid email is required');
    checkNewPassword(password);
    const key = norm(email);
    if (data.users[key]) throw new ApiError('Email already exists');
    data.users[key] = {
      email: key, password: await hashPassword(password), method: 'email', totpSecret: null, pendingTotpSecret: null,
      lastTotpStep: -1, backupCodes: [], trusted: [], failedLogins: 0, lockUntil: 0, recovery: null,
      createdAt: iso(), sessions: [], events: [],
    };
    saveDb(data);
    return { success: true, message: 'User registered successfully' };
  },

  async login({ email, password, deviceToken }) {
    await latency();
    const data = await db();
    const user = userFor(data, email);
    if (!user) {
      await hashPassword(String(password)); // keep timing similar to a real check
      throw new ApiError('Invalid credentials', { status: 200 });
    }
    if (user.lockUntil > now()) {
      const retryAfterSeconds = Math.ceil((user.lockUntil - now()) / 1000);
      throw new ApiError(
        `Account temporarily locked after too many failed attempts. Try again in ${Math.ceil(retryAfterSeconds / 60)} minute(s) or reset your password.`,
        { status: 423, data: { locked: true, retryAfterSeconds } },
      );
    }
    if (!(await verifyPassword(password || '', user.password))) {
      user.failedLogins += 1;
      logEvent(user, 'login-failed', false);
      const left = MAX_LOGIN_FAILURES - user.failedLogins;
      if (left <= 0) { user.lockUntil = now() + LOCKOUT_MS; user.failedLogins = 0; }
      saveDb(data);
      throw new ApiError(
        left > 0 ? 'Invalid credentials' : 'Too many failed attempts. The account is locked for 15 minutes.',
        { status: 200, data: left > 0 && left <= 2 ? { attemptsLeft: left } : {} },
      );
    }
    if (user.method === 'none') return { step: 'done', method: 'none', ...(await startSession(data, user)) };
    if (deviceToken) {
      const h = await sha256(deviceToken);
      if (user.trusted.some((d) => d.hash === h && d.expires > now())) {
        return { step: 'done', method: 'trusted', ...(await startSession(data, user)) };
      }
    }
    if (user.method === 'totp') {
      data.pending[user.email] = { kind: 'totp', expires: now() + OTP_TTL_MS, attempts: 0, sentAt: now() };
      saveDb(data);
      return { step: 'code', method: 'totp' };
    }
    sendLoginCode(data, user);
    saveDb(data);
    return { step: 'code', method: 'email', resendCooldownSeconds: RESEND_COOLDOWN_S };
  },

  async resendCode({ email }) {
    await latency();
    const data = await db();
    const user = userFor(data, email);
    const pending = user && data.pending[user.email];
    if (!pending || pending.kind !== 'email') throw new ApiError('Please log in again');
    const wait = Math.ceil((pending.sentAt + RESEND_COOLDOWN_S * 1000 - now()) / 1000);
    if (wait > 0) throw new ApiError(`Please wait ${wait}s before requesting a new code`, { status: 429, data: { retryAfterSeconds: wait } });
    sendLoginCode(data, user);
    saveDb(data);
    return { resendCooldownSeconds: RESEND_COOLDOWN_S };
  },

  async verifyCode({ email, code, trust }) {
    await latency();
    const data = await db();
    const user = userFor(data, email);
    const pending = user && data.pending[user.email];
    if (!pending || pending.expires < now()) throw new ApiError('Invalid or expired code', { status: 200 });
    if (pending.attempts >= MAX_OTP_ATTEMPTS) {
      delete data.pending[user.email];
      saveDb(data);
      throw new ApiError('Too many attempts. Please log in again.', { status: 200 });
    }
    const given = String(code ?? '').trim();
    let ok = false;
    if (pending.kind === 'email') {
      ok = given === pending.code;
    } else if (/^\d{6}$/.test(given.replace(/\s/g, ''))) {
      const step = await verifyTotp(user.totpSecret, given);
      if (step !== null && step > user.lastTotpStep) { user.lastTotpStep = step; ok = true; }
    } else if (normBackup(given).length === 10) {
      const h = await hashBackup(given);
      if (user.backupCodes.includes(h)) { user.backupCodes = user.backupCodes.filter((x) => x !== h); ok = true; }
    }
    if (!ok) {
      pending.attempts += 1;
      logEvent(user, 'code-failed', false);
      const remaining = MAX_OTP_ATTEMPTS - pending.attempts;
      if (remaining <= 0) delete data.pending[user.email];
      saveDb(data);
      throw new ApiError(remaining > 0 ? `Invalid code. ${remaining} attempt(s) left.` : 'Too many attempts. Please log in again.', { status: 200, data: { attemptsLeft: remaining } });
    }
    return startSession(data, user, { trust: trust === true });
  },

  async me() {
    await latency();
    const { data, user } = await authed();
    saveDb(data);
    return publicUser(user);
  },

  async logout() {
    const { data, user } = await authed();
    user.sessions = [];
    saveDb(data);
    return { success: true };
  },

  async security() { await latency(); return securityOf((await authed()).user); },

  async activity() { await latency(); return (await authed()).user.events; },

  async sessions() {
    await latency();
    const { user, session } = await authed();
    return [...user.sessions].reverse().map((s) => ({ ...s, current: s.id === session.id }));
  },

  async revokeSession(id) {
    await latency();
    const { data, user } = await authed();
    if (!user.sessions.some((s) => s.id === id)) throw new ApiError('Session not found', { status: 404 });
    user.sessions = user.sessions.filter((s) => s.id !== id);
    saveDb(data);
    return { success: true };
  },

  async revokeOtherSessions() {
    await latency();
    const { data, user, session } = await authed();
    user.sessions = user.sessions.filter((s) => s.id === session.id);
    saveDb(data);
    return { success: true };
  },

  async revokeTrustedDevices() {
    await latency();
    const { data, user } = await authed();
    user.trusted = [];
    saveDb(data);
    return { success: true };
  },

  async changePassword({ currentPassword, newPassword }) {
    await latency();
    const { data, user, session } = await authed();
    await reauth(user, currentPassword, 'Current password is incorrect');
    checkNewPassword(newPassword);
    if (newPassword === currentPassword) throw new ApiError('New password must be different from the current one');
    user.password = await hashPassword(newPassword);
    user.sessions = user.sessions.filter((s) => s.id === session.id);
    user.trusted = [];
    logEvent(user, 'password-changed', true);
    saveDb(data);
    return { success: true, message: 'Password changed. Other sessions were signed out.' };
  },

  async setMethod({ method, password }) {
    await latency();
    const { data, user } = await authed();
    if (!['email', 'none'].includes(method)) throw new ApiError('Unknown method');
    await reauth(user, password);
    Object.assign(user, { method, totpSecret: null, pendingTotpSecret: null, lastTotpStep: -1, backupCodes: [], trusted: [] });
    logEvent(user, '2fa-changed', true);
    saveDb(data);
    return securityOf(user);
  },

  async totpSetup({ password }) {
    await latency();
    const { data, user } = await authed();
    await reauth(user, password);
    user.pendingTotpSecret = generateSecret();
    saveDb(data);
    return { secret: user.pendingTotpSecret, otpauthUrl: otpauthUrl({ secret: user.pendingTotpSecret, email: user.email }) };
  },

  async totpEnable({ code }) {
    await latency();
    const { data, user } = await authed();
    if (!user.pendingTotpSecret) throw new ApiError('Start the setup first');
    const step = await verifyTotp(user.pendingTotpSecret, code);
    if (step === null) throw new ApiError('That code is not valid. Check the time on your device and try again.');
    const codes = generateBackupCodes();
    Object.assign(user, {
      totpSecret: user.pendingTotpSecret, pendingTotpSecret: null, lastTotpStep: step, method: 'totp',
      backupCodes: await Promise.all(codes.map(hashBackup)), trusted: [],
    });
    logEvent(user, '2fa-changed', true);
    saveDb(data);
    return { backupCodes: codes, security: securityOf(user) };
  },

  async regenerateBackupCodes({ password }) {
    await latency();
    const { data, user } = await authed();
    if (user.method !== 'totp') throw new ApiError('Backup codes need the authenticator app to be enabled');
    await reauth(user, password);
    const codes = generateBackupCodes();
    user.backupCodes = await Promise.all(codes.map(hashBackup));
    saveDb(data);
    return codes;
  },

  async recoverRequest({ email }) {
    await latency();
    const data = await db();
    const user = userFor(data, email);
    const generic = { success: true, message: 'If an account exists for that address, a recovery code has been sent.' };
    if (!user || (user.recovery && now() - user.recovery.sentAt < RESEND_COOLDOWN_S * 1000)) return generic;
    const code = randomCode();
    user.recovery = { hash: await sha256(code), expires: now() + RECOVERY_TTL_MS, attempts: 0, sentAt: now() };
    pushMail({
      to: user.email,
      subject: 'Account recovery code',
      text: 'Use this code to choose a new password. It is valid for 15 minutes. If you did not ask for it, ignore this message.',
      code,
    });
    saveDb(data);
    return generic;
  },

  async recoverReset({ email, code, newPassword }) {
    await latency();
    const data = await db();
    checkNewPassword(newPassword);
    const user = userFor(data, email);
    const invalid = new ApiError('Invalid or expired recovery code');
    const rec = user?.recovery;
    if (!rec || rec.expires < now()) throw invalid;
    if (rec.attempts >= MAX_OTP_ATTEMPTS || rec.hash !== (await sha256(String(code).trim()))) {
      rec.attempts += 1;
      if (rec.attempts >= MAX_OTP_ATTEMPTS) user.recovery = null;
      saveDb(data);
      throw invalid;
    }
    user.password = await hashPassword(newPassword);
    Object.assign(user, { recovery: null, sessions: [], trusted: [], failedLogins: 0, lockUntil: 0 });
    logEvent(user, 'recovery', true);
    saveDb(data);
    return { success: true, message: 'Password updated. You can sign in now.' };
  },
};
