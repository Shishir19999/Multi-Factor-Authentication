// In-browser backend for the Live preview. Same interface and rules as the Express API (realApi.js), built on the same
// shared modules (policy, lockout, rate limits, risk, score, audit, scopes, breach check). Differences, by design:
// PBKDF2 (WebCrypto) instead of bcrypt, localStorage instead of MongoDB, e-mails land in the Preview inbox, the
// session token is an opaque id in localStorage (no cookie/CSRF: there is no network), location is simulated.
import { ApiError } from './errors';
import { getToken } from '../auth/auth';
import { loadDb, saveDb, pushMail } from './previewStore';
import { PREVIEW_ACCOUNTS, PREVIEW_BACKUP_CODE, PREVIEW_PASSWORD, PREVIEW_TOTP_SECRET } from './previewAccounts';
import { currentRequest } from './previewEnv';
import { generateSecret, otpauthUrl, verifyTotp } from '../lib/totp';
import { verifyAssertion, verifyRegistration, PUBKEY_PARAMS } from '../lib/webauthnServer';
import {
  defaultPolicy, normalizePolicy, policyDiff, passwordError, passwordAge, compliance, twoFactorRequired, sessionLifetimeMs,
} from '../shared/policy';
import { registerFailure, registerSuccess, lockStatus, formatDuration } from '../shared/lockout';
import { RATE_LIMITS, hitWindow, windowBlocked } from '../shared/ratelimit';
import { deviceLabel, simulatedGeo, assessLogin } from '../shared/risk';
import { securityScore } from '../shared/score';
import { EVENT_KEYS, eventCategory, eventLabel, eventSeverity, toCsv, AUDIT_COLUMNS } from '../shared/audit';
import { checkPwned } from '../shared/pwned';
import { TOKEN_PREFIX, MAX_TOKENS, ROUTE_SCOPES, validateTokenRequest } from '../shared/scopes';
import { bytesToB64u } from '../shared/b64u';

const FAST = import.meta.env.MODE === 'test';
const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;
const RESEND_COOLDOWN_S = 30;
const RECOVERY_TTL_MS = 15 * 60 * 1000;
const PBKDF2_ITERATIONS = FAST ? 1000 : 100000;
const MAX_AUDIT = 1500;
const MAX_ALERTS = 20;
const DAY = 86400000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const latency = () => (FAST ? Promise.resolve() : sleep(140 + Math.random() * 260));
const now = () => Date.now();
const norm = (e) => String(e || '').trim().toLowerCase();
const isStr = (v) => typeof v === 'string' && v.length > 0;
const E = (message, status = 400, data = {}) => new ApiError(message, { status, data });
const maskEmail = (e = '') => e.replace(/^(.).*?(@.*)$/, (_, a, b) => `${a}***${b}`);

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

// The breach lookup can be replaced in tests.
let breachChecker = (pw) => checkPwned(pw);
export const setBreachChecker = (fn) => { breachChecker = fn; };

// ---- seed data ----
const FAKE_UA = {
  firefoxWin: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
  safariIos: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  chromeMac: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36',
};
const ago = (mins) => now() - mins * 60000;

function blankUser(email, passwordHash, extra = {}) {
  return {
    id: randomHex(12), email, password: passwordHash, role: 'user', twoFactorMethod: 'email', totpSecret: null, pendingTotpSecret: null, lastTotpStep: -1,
    backupCodes: [], passkeys: [], webauthnUserId: bytesToB64u(crypto.getRandomValues(new Uint8Array(32))), trustedDevices: [], sessions: [], apiTokens: [], alerts: [],
    knownDevices: [], knownPlaces: [], lock: registerSuccess(), adminLocked: false, adminLockReason: null, mustChangePassword: false, mustEnrollTwoFactor: false,
    assistRequestedAt: null, assistMessage: null, passwordChangedAt: now(), passwordHistory: [], breachStatus: 'unknown', breachCheckedAt: null, recovery: null,
    recoveryEmail: null, recoveryEmailVerified: false, recoveryEmailPending: null, recoveryEmailHash: null, recoveryEmailExpires: 0, recoveryEmailAttempts: 0,
    lastLoginAt: null, createdAt: now(), ...extra,
  };
}

function audit(data, event, { actor, target, ok = true, meta, at } = {}, reqInfo = currentRequest()) {
  const geo = simulatedGeo(reqInfo.ip);
  data.audit.unshift({
    id: randomHex(6), at: at ?? now(), event, severity: eventSeverity(event), category: eventCategory(event), ok,
    actorId: actor?.id, actorEmail: actor?.email, targetId: target?.id, targetEmail: target?.email,
    ip: reqInfo.ip, userAgent: reqInfo.userAgent, device: deviceLabel(reqInfo.userAgent), geo: geo.label, meta,
  });
  if (data.audit.length > MAX_AUDIT) data.audit.length = MAX_AUDIT;
}

async function seedDb() {
  const hash = await hashPassword(PREVIEW_PASSWORD);
  const data = { users: {}, audit: [], pending: {}, challenges: {}, rate: {}, policy: defaultPolicy() };
  const seedSessions = {
    'member@example.com': [[60 * 3, 30, '198.51.100.24', FAKE_UA.firefoxWin], [60 * 5, 60 * 2, '203.0.113.77', FAKE_UA.safariIos]],
    'alice@example.com': [[60 * 4, 60 * 1, '192.0.2.88', FAKE_UA.chromeMac]],
    'bob@example.com': [[60 * 3, 20, '198.51.100.9', FAKE_UA.firefoxWin]],
    'admin@example.com': [[60 * 2, 15, '203.0.113.12', FAKE_UA.chromeMac]],
  };
  for (const a of PREVIEW_ACCOUNTS) {
    const totp = a.method === 'totp';
    const u = blankUser(a.email, hash, {
      role: a.role, twoFactorMethod: a.method, totpSecret: totp ? PREVIEW_TOTP_SECRET : null,
      backupCodes: totp ? [await hashBackup(PREVIEW_BACKUP_CODE)] : [], createdAt: ago(60 * 24 * 40), passwordChangedAt: ago(60 * 24 * 40),
      breachStatus: a.role === 'admin' || totp ? 'clean' : 'unknown',
    });
    u.sessions = seedSessions[a.email].map(([created, seen, ip, ua]) => ({
      sid: randomHex(16), createdAt: ago(created), lastSeen: ago(seen), ip, userAgent: ua, device: deviceLabel(ua), geo: simulatedGeo(ip).label, via: 'password', stepUpUntil: 0,
    }));
    data.users[a.email] = u;
  }
  // a little history so the activity feed, admin audit log and charts are not empty
  const emails = Object.keys(data.users);
  const sample = [['login', true], ['login', true], ['login', true], ['login-failed', false], ['login', true], ['logout', true], ['login', true]];
  for (let d = 6; d >= 0; d--) {
    sample.slice(0, 3 + ((d * 5) % 5)).forEach(([event, ok], i) => {
      const u = data.users[emails[(d + i) % emails.length]];
      const [, , ip, ua] = seedSessions[u.email][0];
      audit(data, event, { actor: u, target: u, ok, at: ago(d * 60 * 24 + 60 * (2 + i * 3)) }, { ip, userAgent: ua });
    });
  }
  const m = data.users['member@example.com'];
  audit(data, 'password-changed', { actor: m, target: m, at: ago(60 * 24 * 6) }, { ip: '198.51.100.24', userAgent: FAKE_UA.firefoxWin });
  audit(data, 'login-failed', { actor: m, target: m, ok: false, at: ago(60 * 30) }, { ip: '192.0.2.15', userAgent: FAKE_UA.chromeMac });
  data.audit.sort((a, b) => b.at - a.at);
  return data;
}

let seeding = null;
async function db() {
  let data = loadDb();
  if (!data) {
    seeding ??= seedDb().then((fresh) => { saveDb(fresh); return fresh; }).finally(() => { seeding = null; });
    data = await seeding;
  }
  data.policy = normalizePolicy(data.policy || {}).policy;
  return data;
}

// ---- views ----
const facts = (u) => ({
  role: u.role, twoFactorMethod: u.twoFactorMethod, passkeyCount: u.passkeys.length, passwordChangedAt: u.passwordChangedAt,
  mustChangePassword: u.mustChangePassword, mustEnrollTwoFactor: u.mustEnrollTwoFactor,
});
const requirementsOf = (u, policy) => compliance(facts(u), policy);
const publicUser = (u, policy) => ({ id: u.id, email: u.email, role: u.role, twoFactorMethod: u.twoFactorMethod, createdAt: u.createdAt, requirements: requirementsOf(u, policy) });
const unreviewed = (u) => u.alerts.filter((a) => a.status === 'pending');

function securityOf(u, policy) {
  const t = now();
  const trusted = u.trustedDevices.filter((d) => d.expires > t).length;
  const scoreFacts = {
    twoFactorMethod: u.twoFactorMethod, passkeyCount: u.passkeys.length, backupCodesRemaining: u.backupCodes.length, passwordChangedAt: u.passwordChangedAt,
    breachStatus: u.breachStatus, recoveryEmailVerified: u.recoveryEmailVerified, trustedDevices: trusted, sessionCount: u.sessions.length,
    unreviewedAlerts: unreviewed(u).length, riskyTokens: u.apiTokens.filter((x) => !x.expiresAt).length,
  };
  return {
    email: u.email, role: u.role, twoFactorMethod: u.twoFactorMethod, passkeys: u.passkeys.length, backupCodesRemaining: u.backupCodes.length, trustedDevices: trusted,
    createdAt: u.createdAt, passwordChangedAt: u.passwordChangedAt, passwordAge: passwordAge(u.passwordChangedAt, policy, t), breachStatus: u.breachStatus,
    recoveryEmail: u.recoveryEmailVerified ? maskEmail(u.recoveryEmail) : null, sessionCount: u.sessions.length, apiTokens: u.apiTokens.length,
    unreviewedAlerts: scoreFacts.unreviewedAlerts, requirements: requirementsOf(u, policy), score: securityScore(scoreFacts, policy, t),
  };
}

const toActivity = (e) => ({
  id: e.id, at: e.at, event: e.event, label: eventLabel(e.event), ok: e.ok, severity: e.severity, ip: e.ip, userAgent: e.userAgent, device: e.device, geo: e.geo,
  byAdmin: !!e.actorId && e.actorId !== e.targetId,
});
const sessionView = (s, current) => ({ id: s.sid, current: s.sid === current, ip: s.ip, userAgent: s.userAgent, device: s.device, geo: s.geo, name: s.name, via: s.via, createdAt: s.createdAt, lastSeen: s.lastSeen });
const passkeyView = (p) => ({ id: p.credentialId, name: p.name, deviceType: p.deviceType, backedUp: !!p.backedUp, transports: p.transports, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt });
const tokenView = (t) => ({ id: t.id, name: t.name, prefix: t.prefix, scopes: t.scopes, createdAt: t.createdAt, lastUsedAt: t.lastUsedAt, expiresAt: t.expiresAt });
const alertView = (a) => ({ id: a.id, at: a.at, device: a.device, geo: a.geo, ip: a.ip, reasons: a.reasons, level: a.level, status: a.status });
const userStatus = (u) => (u.adminLocked ? 'admin-locked' : u.lock.lockUntil > now() ? 'locked' : 'active');
const adminRow = (u) => ({
  id: u.id, email: u.email, role: u.role, twoFactorMethod: u.twoFactorMethod, passkeys: u.passkeys.length, status: userStatus(u), adminLockReason: u.adminLockReason,
  mustChangePassword: u.mustChangePassword, mustEnrollTwoFactor: u.mustEnrollTwoFactor, assistRequestedAt: u.assistRequestedAt, assistMessage: u.assistMessage,
  lastLoginAt: u.lastLoginAt, createdAt: u.createdAt, sessions: u.sessions.length, breachStatus: u.breachStatus, recoveryEmail: u.recoveryEmailVerified ? maskEmail(u.recoveryEmail) : null,
});

// ---- rate limits (same numbers as the API; sign-in only counts failures here) ----
function rateCheck(data, name, { count = true } = {}) {
  const cfg = RATE_LIMITS[name];
  const retry = (seconds) => E(`${cfg.message} Try again in ${formatDuration(seconds)}.`, 429, { rateLimited: true, retryAfterSeconds: seconds });
  if (count) {
    const r = hitWindow(data.rate, name, cfg);
    saveDb(data);
    if (!r.allowed) throw retry(r.retryAfterSeconds);
  } else {
    const b = windowBlocked(data.rate, name, cfg);
    if (b.blocked) throw retry(b.retryAfterSeconds);
  }
}

// ---- passwords ----
async function vetPassword(data, password, { email, hashes = [] }) {
  const policy = data.policy;
  const err = passwordError(password, policy, { email });
  if (err) throw E(err);
  for (const h of hashes) {
    if (await verifyPassword(password, h)) throw E(`You used this password before. Choose one that is not among your last ${Math.max(1, policy.password.historyCount)} passwords.`);
  }
  if (policy.breachCheck === 'off') return null;
  const result = await breachChecker(password);
  if (result.status === 'pwned' && policy.breachCheck === 'block') throw E(`This password appears in ${result.count.toLocaleString('en-US')} known data breaches. Choose a different one.`);
  return result;
}

async function applyPassword(user, password, policy, breach) {
  const old = user.password;
  user.password = await hashPassword(password);
  if (old && policy.password.historyCount > 0) user.passwordHistory = [old, ...user.passwordHistory].slice(0, policy.password.historyCount);
  user.passwordChangedAt = now();
  user.mustChangePassword = false;
  if (breach && breach.status !== 'unavailable') {
    user.breachStatus = breach.status === 'pwned' ? 'pwned' : 'clean';
    user.breachCheckedAt = now();
  }
}

// ---- sessions ----
async function startSession(data, user, { trust = false, via = 'password' } = {}) {
  const policy = data.policy;
  const req = currentRequest();
  const geo = simulatedGeo(req.ip);
  const device = deviceLabel(req.userAgent);
  const cutoff = now() - sessionLifetimeMs(policy);
  user.sessions = user.sessions.filter((s) => s.createdAt > cutoff);
  const sid = randomHex(24);
  user.sessions.push({ sid, createdAt: now(), lastSeen: now(), ip: req.ip, userAgent: req.userAgent, device, geo: geo.label, via, stepUpUntil: now() + policy.session.stepUpMinutes * 60000 });
  user.sessions = user.sessions.slice(-policy.session.maxSessions);
  let deviceToken;
  if (trust && user.twoFactorMethod !== 'none' && policy.trustedDeviceDays > 0) {
    deviceToken = randomHex(32);
    user.trustedDevices = user.trustedDevices.filter((d) => d.expires > now()).slice(-9);
    user.trustedDevices.push({ hash: await sha256(deviceToken), expires: now() + policy.trustedDeviceDays * DAY, device, createdAt: now() });
  }
  const risk = assessLogin({ family: device, geo }, { devices: user.knownDevices, places: user.knownPlaces });
  let alert;
  if (!risk.firstLogin && risk.level !== 'low' && policy.alerts.newDevice) {
    const id = randomHex(6);
    const secret = randomHex(24);
    user.alerts.push({
      id, at: now(), ip: req.ip, userAgent: req.userAgent, device, geo: geo.label, family: device, placeKey: geo.key, reasons: risk.reasons, level: risk.level,
      status: 'pending', tokenHash: await sha256(secret),
    });
    user.alerts = user.alerts.slice(-MAX_ALERTS);
    alert = { id, level: risk.level, reasons: risk.reasons };
    pushMail({
      kind: 'new-device', to: user.email, subject: 'New sign-in to your account',
      text: `We noticed a sign-in from a device or place we have not seen before.\nDevice: ${device}\nLocation: ${geo.label} (simulated in the Live preview)\nIP address: ${req.ip}\n\nWas this you?`,
      link: `${location.origin}${location.pathname}#/review?t=${user.id}.${id}.${secret}`,
    });
    audit(data, 'new-device-alert', { actor: user, target: user, meta: { reasons: risk.reasons, level: risk.level } });
  }
  if (!user.knownDevices.includes(device)) user.knownDevices = [...user.knownDevices, device].slice(-20);
  if (geo.key !== 'unknown' && !user.knownPlaces.includes(geo.key)) user.knownPlaces = [...user.knownPlaces, geo.key].slice(-20);
  user.lock = registerSuccess();
  user.lastLoginAt = now();
  delete data.pending[user.email];
  audit(data, via === 'passkey' ? 'passkey-login' : 'login', { actor: user, target: user, meta: { via } });
  saveDb(data);
  return { token: sid, user: publicUser(user, policy), ...(deviceToken ? { deviceToken } : {}), ...(alert ? { alert } : {}) };
}

// opts: pending, admin, fresh (same meaning as the API's auth middleware)
async function authed(opts = {}) {
  const data = await db();
  const token = getToken();
  let user;
  let session;
  if (token) {
    for (const u of Object.values(data.users)) {
      const s = u.sessions.find((x) => x.sid === token);
      if (s) { user = u; session = s; break; }
    }
  }
  const policy = data.policy;
  if (!session || now() - session.createdAt > sessionLifetimeMs(policy)) throw E('Session expired. Please sign in again.', 401);
  const idle = policy.session.idleMinutes;
  if (idle > 0 && now() - session.lastSeen > idle * 60000) {
    user.sessions = user.sessions.filter((s) => s !== session);
    saveDb(data);
    throw E('Session expired after a period of inactivity', 401);
  }
  if (user.adminLocked) throw E('This account has been locked by an administrator.', 403, { code: 'ACCOUNT_LOCKED' });
  if (!opts.pending) {
    const requirements = requirementsOf(user, policy);
    if (requirements.length) throw E(requirements[0].message, 403, { code: 'ACTION_REQUIRED', requirements });
  }
  if (opts.admin && user.role !== 'admin') throw E('Administrator access required', 403, { code: 'FORBIDDEN' });
  if (opts.fresh && !(session.stepUpUntil > now())) {
    throw E('Please confirm it is you to continue.', 403, { code: 'STEP_UP_REQUIRED', stepUp: { password: true, totp: user.twoFactorMethod === 'totp', passkey: user.passkeys.length > 0 } });
  }
  if (now() - session.lastSeen > 30000) { session.lastSeen = now(); saveDb(data); }
  return { data, user, session, policy };
}

const markFresh = (session, policy) => { session.stepUpUntil = now() + policy.session.stepUpMinutes * 60000; };
const findUser = (data, email) => data.users[norm(email)] || null;
const findById = (data, id) => Object.values(data.users).find((u) => u.id === id) || null;

function sendLoginCode(data, user) {
  const code = randomCode();
  data.pending[user.email] = { kind: 'email', code, expires: now() + OTP_TTL_MS, attempts: 0, sentAt: now() };
  pushMail({ kind: 'otp', to: user.email, subject: 'Your verification code', text: 'Use this code to finish signing in. It is valid for 5 minutes. If you did not try to sign in, change your password.', code });
}

// "Was this you?" answer: "no" signs everything out and forces a new password.
function resolveAlert(data, user, alert, answer) {
  if (answer === 'yes') {
    alert.status = 'confirmed';
    audit(data, 'alert-confirmed', { actor: user, target: user });
  } else {
    alert.status = 'denied';
    user.sessions = [];
    user.mustChangePassword = true;
    user.trustedDevices = [];
    user.knownDevices = user.knownDevices.filter((d) => d !== alert.family);
    user.knownPlaces = user.knownPlaces.filter((p) => p !== alert.placeKey);
    audit(data, 'alert-denied', { actor: user, target: user, ok: false, meta: { device: alert.device, geo: alert.geo } });
  }
  saveDb(data);
}

// ---- WebAuthn (server side, in the browser) ----
const rpId = () => location.hostname;
const newChallenge = (data, purpose, userId) => {
  const id = randomHex(16);
  const challenge = bytesToB64u(crypto.getRandomValues(new Uint8Array(32)));
  data.challenges[id] = { challenge, purpose, userId, expires: now() + 5 * 60000 };
  for (const [k, c] of Object.entries(data.challenges)) if (c.expires < now()) delete data.challenges[k];
  return { id, challenge };
};
const takeChallenge = (data, id, purpose) => {
  const c = data.challenges[id];
  delete data.challenges[id];
  return c && c.purpose === purpose && c.expires > now() ? c : null;
};
const authOptions = (challenge, passkeys) => ({
  challenge, rpId: rpId(), timeout: 60000, userVerification: 'required',
  allowCredentials: passkeys.map((p) => ({ id: p.credentialId, type: 'public-key', transports: p.transports })),
});

async function checkAssertion(data, challengeRec, response, passkey) {
  try {
    const v = await verifyAssertion({ response, expectedChallenge: challengeRec.challenge, expectedOrigin: location.origin, rpId: rpId(), credential: passkey });
    passkey.counter = v.newCounter;
    passkey.lastUsedAt = now();
    return true;
  } catch {
    return false;
  }
}

// ---- generic mutex: calls run one at a time so overlapping requests never overwrite each other's changes ----
let chain = Promise.resolve();
const serial = (fn) => async (...args) => {
  await latency();
  const run = chain.then(() => fn(...args));
  chain = run.catch(() => {});
  return run;
};

const ACTIONS = ['lock', 'unlock', 'force-reset', 'force-enroll', 'reset-2fa', 'revoke-sessions', 'role', 'issue-recovery', 'clear-assist'];

function auditFilter(q = {}) {
  let events = isStr(q.event) ? q.event.split(',') : null;
  if (isStr(q.category)) {
    const inCat = EVENT_KEYS.filter((k) => eventCategory(k) === q.category);
    events = events ? events.filter((e) => inCat.includes(e)) : inCat;
  }
  const sev = isStr(q.severity) ? q.severity.split(',') : null;
  const text = isStr(q.q) ? q.q.trim().toLowerCase() : '';
  const from = isStr(q.from) ? Date.parse(q.from) : NaN;
  const to = isStr(q.to) ? Date.parse(q.to.length === 10 ? `${q.to}T23:59:59.999Z` : q.to) : NaN;
  return (e) => (!events || events.includes(e.event)) && (!sev || sev.includes(e.severity))
    && (q.ok !== 'true' && q.ok !== 'false' ? true : e.ok === (q.ok === 'true'))
    && (!text || [e.actorEmail, e.targetEmail, e.ip].some((v) => String(v || '').toLowerCase().includes(text)))
    && (Number.isNaN(from) || e.at >= from) && (Number.isNaN(to) || e.at <= to);
}
const auditRow = (e) => ({ id: e.id, at: e.at, event: e.event, label: eventLabel(e.event), severity: e.severity, category: e.category, ok: e.ok, actorEmail: e.actorEmail, targetEmail: e.targetEmail, ip: e.ip, device: e.device, geo: e.geo, meta: e.meta });
const paginate = (rows, q = {}, def = 25) => {
  const limit = Math.min(Math.max(Number(q.limit) || def, 1), 100);
  const page = Math.max(Number(q.page) || 1, 1);
  return { items: rows.slice((page - 1) * limit, page * limit), total: rows.length, page, pages: Math.max(1, Math.ceil(rows.length / limit)) };
};

const handlers = {
  async getPolicy() { return (await db()).policy; },

  async register({ email, password }) {
    const data = await db();
    rateCheck(data, 'public');
    if (!/^\S+@\S+\.\S+$/.test((email || '').trim())) throw E('A valid email is required');
    const key = norm(email);
    const breach = await vetPassword(data, password, { email: key });
    if (data.users[key]) throw E('Email already exists');
    const u = blankUser(key, await hashPassword(password), {
      twoFactorMethod: data.policy.twoFactor.methods.includes('email') ? 'email' : 'none',
      breachStatus: breach?.status === 'pwned' ? 'pwned' : breach?.status === 'safe' ? 'clean' : 'unknown', breachCheckedAt: breach && breach.status !== 'unavailable' ? now() : null,
    });
    data.users[key] = u;
    audit(data, 'register', { actor: u, target: u });
    saveDb(data);
    return { success: true, message: 'User registered successfully', ...(breach?.status === 'pwned' ? { warning: `This password appears in ${breach.count.toLocaleString('en-US')} known data breaches. Consider changing it.` } : {}) };
  },

  async login({ email, password, deviceToken }) {
    const data = await db();
    rateCheck(data, 'login', { count: false });
    const failed = (extra) => { hitWindow(data.rate, 'login', RATE_LIMITS.login); saveDb(data); return extra; };
    const user = findUser(data, email);
    if (!user) {
      await hashPassword(String(password));
      audit(data, 'login-failed', { ok: false, meta: { email: norm(email).slice(0, 120) } });
      failed();
      throw E('Invalid credentials', 200);
    }
    const lock = lockStatus(user.lock);
    if (lock.locked) {
      throw E(`Account temporarily locked after too many failed attempts. Try again in ${Math.ceil(lock.retryAfterSeconds / 60)} minute(s) or reset your password.`, 423, { locked: true, retryAfterSeconds: lock.retryAfterSeconds });
    }
    if (!(await verifyPassword(password || '', user.password))) {
      const r = registerFailure(user.lock, data.policy);
      user.lock = r.state;
      audit(data, 'login-failed', { actor: user, target: user, ok: false });
      if (r.locked) audit(data, 'account-locked', { actor: user, target: user, ok: false, meta: { minutes: Math.round(r.lockMs / 60000) } });
      failed();
      throw E(
        r.locked ? `Too many failed attempts. The account is locked for ${Math.round(r.lockMs / 60000)} minutes.` : 'Invalid credentials', 200,
        { ...(r.locked ? { locked: true, retryAfterSeconds: Math.round(r.lockMs / 1000) } : {}), ...(!r.locked && r.attemptsLeft <= 2 ? { attemptsLeft: r.attemptsLeft } : {}) },
      );
    }
    if (user.adminLocked) {
      audit(data, 'login-failed', { actor: user, target: user, ok: false, meta: { reason: 'admin-locked' } });
      saveDb(data);
      throw E('This account has been locked by an administrator. Use "Ask an administrator for help" on the recovery page.', 423, { locked: true, adminLocked: true });
    }
    user.lock = registerSuccess();
    const policy = data.policy;
    if (policy.breachCheck !== 'off' && (!user.breachCheckedAt || now() - user.breachCheckedAt > DAY)) {
      const r = await breachChecker(password);
      if (r.status !== 'unavailable') {
        user.breachStatus = r.status === 'pwned' ? 'pwned' : 'clean';
        user.breachCheckedAt = now();
        if (r.status === 'pwned' && policy.breachCheck === 'block') user.mustChangePassword = true;
      }
    }
    const method = user.twoFactorMethod;
    if (method === 'none') return { step: 'done', method, ...(await startSession(data, user)) };
    if (deviceToken) {
      const h = await sha256(deviceToken);
      if (user.trustedDevices.some((d) => d.hash === h && d.expires > now())) return { step: 'done', method: 'trusted', ...(await startSession(data, user, { via: 'trusted' })) };
    }
    const passkeys = user.passkeys.length > 0;
    if (method === 'totp') {
      data.pending[user.email] = { kind: 'totp', expires: now() + OTP_TTL_MS, attempts: 0, sentAt: now() };
      saveDb(data);
      return { step: 'code', method: 'totp', passkeys };
    }
    sendLoginCode(data, user);
    saveDb(data);
    return { step: 'code', method: 'email', passkeys, resendCooldownSeconds: RESEND_COOLDOWN_S };
  },

  async resendCode({ email }) {
    const data = await db();
    rateCheck(data, 'resend');
    const user = findUser(data, email);
    const pending = user && data.pending[user.email];
    if (!pending || pending.kind !== 'email') throw E('Please log in again');
    const wait = Math.ceil((pending.sentAt + RESEND_COOLDOWN_S * 1000 - now()) / 1000);
    if (wait > 0) throw E(`Please wait ${wait}s before requesting a new code`, 429, { retryAfterSeconds: wait });
    sendLoginCode(data, user);
    saveDb(data);
    return { resendCooldownSeconds: RESEND_COOLDOWN_S };
  },

  async verifyCode({ email, code, trust }) {
    const data = await db();
    rateCheck(data, 'verify');
    const user = findUser(data, email);
    const pending = user && data.pending[user.email];
    if (!pending || pending.expires < now()) throw E('Invalid or expired code', 200);
    if (user.adminLocked) throw E('This account has been locked by an administrator.', 423, { locked: true, adminLocked: true });
    if (pending.attempts >= MAX_OTP_ATTEMPTS) {
      delete data.pending[user.email];
      saveDb(data);
      throw E('Too many attempts. Please log in again.', 200);
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
      const remaining = MAX_OTP_ATTEMPTS - pending.attempts;
      if (remaining <= 0) delete data.pending[user.email];
      audit(data, 'code-failed', { actor: user, target: user, ok: false });
      saveDb(data);
      throw E(remaining > 0 ? `Invalid code. ${remaining} attempt(s) left.` : 'Too many attempts. Please log in again.', 200, { attemptsLeft: remaining });
    }
    return startSession(data, user, { trust: trust === true });
  },

  // ---- passkey sign-in / second step ----
  async passkeyOptions({ purpose, email }) {
    const data = await db();
    rateCheck(data, 'verify');
    if (!['login', 'mfa'].includes(purpose)) throw E('Unknown purpose');
    const user = isStr(email) ? findUser(data, email) : null;
    if (purpose === 'mfa' && !(user && data.pending[user.email] && data.pending[user.email].expires > now() && user.passkeys.length)) throw E('Please sign in with your password first');
    const { id, challenge } = newChallenge(data, purpose, purpose === 'mfa' ? user.id : undefined);
    saveDb(data);
    return { challengeId: id, options: authOptions(challenge, purpose === 'mfa' || user ? user?.passkeys || [] : []) };
  },

  async passkeyVerify({ purpose, challengeId, response, email, trust }) {
    const data = await db();
    rateCheck(data, 'verify');
    if (!['login', 'mfa'].includes(purpose) || !response?.id) throw E('Invalid request');
    const c = takeChallenge(data, challengeId, purpose);
    if (!c) { saveDb(data); throw E('The passkey request expired. Try again.'); }
    const user = purpose === 'mfa'
      ? Object.values(data.users).find((u) => u.id === c.userId && u.email === norm(email))
      : Object.values(data.users).find((u) => u.passkeys.some((p) => p.credentialId === response.id));
    const pk = user?.passkeys.find((p) => p.credentialId === response.id);
    const fail = (message = 'Passkey sign-in failed') => {
      audit(data, 'passkey-failed', { actor: user, target: user, ok: false });
      saveDb(data);
      return E(message);
    };
    if (!user || !pk) throw fail('That passkey is not registered for this site.');
    if (user.adminLocked) throw E('This account has been locked by an administrator.', 423, { locked: true, adminLocked: true });
    if (!(await checkAssertion(data, c, response, pk))) throw fail();
    if (purpose === 'mfa') delete data.pending[user.email];
    return startSession(data, user, { trust: purpose === 'mfa' && trust === true, via: 'passkey' });
  },

  // ---- recovery ----
  async recoverRequest({ email }) {
    const data = await db();
    rateCheck(data, 'recover');
    const generic = { success: true, message: 'If an account exists for that address, a recovery code has been sent.' };
    const user = findUser(data, email);
    if (!user || (user.recovery && now() - user.recovery.sentAt < RESEND_COOLDOWN_S * 1000)) return generic;
    const code = randomCode();
    user.recovery = { hash: await sha256(code), expires: now() + RECOVERY_TTL_MS, attempts: 0, sentAt: now() };
    const text = 'Use this code to choose a new password. It is valid for 15 minutes. If you did not ask for it, ignore this message.';
    pushMail({ kind: 'recovery', to: user.email, subject: 'Account recovery code', text, code });
    if (user.recoveryEmailVerified && user.recoveryEmail) pushMail({ kind: 'recovery', to: user.recoveryEmail, subject: 'Account recovery code', text, code });
    audit(data, 'recovery-requested', { actor: user, target: user });
    saveDb(data);
    return generic;
  },

  async recoverReset({ email, code, newPassword }) {
    const data = await db();
    rateCheck(data, 'verify');
    const user = findUser(data, email);
    const breach = await vetPassword(data, newPassword, { email: norm(email), hashes: user ? [user.password, ...user.passwordHistory] : [] });
    const invalid = E('Invalid or expired recovery code');
    const rec = user?.recovery;
    if (!rec || rec.expires < now()) throw invalid;
    if (rec.attempts >= MAX_OTP_ATTEMPTS || rec.hash !== (await sha256(String(code).trim()))) {
      rec.attempts += 1;
      if (rec.attempts >= MAX_OTP_ATTEMPTS) user.recovery = null;
      saveDb(data);
      throw invalid;
    }
    await applyPassword(user, newPassword, data.policy, breach);
    Object.assign(user, { recovery: null, sessions: [], trustedDevices: [], lock: registerSuccess(), assistRequestedAt: null });
    audit(data, 'recovery', { actor: user, target: user });
    saveDb(data);
    return { success: true, message: 'Password updated. You can sign in now.' };
  },

  async recoverAssist({ email, message }) {
    const data = await db();
    rateCheck(data, 'public');
    const user = findUser(data, email);
    if (user && !user.assistRequestedAt) {
      user.assistRequestedAt = now();
      user.assistMessage = typeof message === 'string' ? message.trim().slice(0, 300) : null;
      audit(data, 'help-requested', { actor: user, target: user });
      saveDb(data);
    }
    return { success: true, message: 'If an account exists for that address, an administrator has been asked to contact you.' };
  },

  async alertRespondByLink({ t, answer }) {
    const data = await db();
    rateCheck(data, 'public');
    if (!isStr(t) || !['yes', 'no'].includes(answer)) throw E('Invalid request');
    const [userId, alertId, secret] = t.split('.');
    const user = findById(data, userId);
    const alert = user?.alerts.find((a) => a.id === alertId);
    if (!alert || !secret || alert.tokenHash !== (await sha256(secret))) throw E('This link is not valid any more.');
    if (alert.status === 'pending') resolveAlert(data, user, alert, answer);
    return { success: true, status: alert.status };
  },

  // ---- signed in ----
  async me() {
    const { user, policy } = await authed({ pending: true });
    return publicUser(user, policy);
  },

  async logout() {
    const { data, user, session } = await authed({ pending: true });
    user.sessions = user.sessions.filter((s) => s !== session);
    audit(data, 'logout', { actor: user, target: user });
    saveDb(data);
    return { success: true };
  },

  async security() { const { user, policy } = await authed({ pending: true }); return securityOf(user, policy); },

  async activity({ category, event, limit = 100 } = {}) {
    const { data, user } = await authed();
    const f = auditFilter({ category, event });
    return data.audit.filter((e) => e.targetId === user.id && f(e)).slice(0, Math.min(limit, 500)).map(toActivity);
  },

  async exportActivity({ format = 'csv' } = {}) {
    const { data, user } = await authed({ fresh: true });
    const rows = data.audit.filter((e) => e.targetId === user.id).slice(0, 500);
    audit(data, 'activity-exported', { actor: user, target: user });
    saveDb(data);
    if (format === 'json') return { filename: 'account-activity.json', mime: 'application/json', text: JSON.stringify({ exportedAt: new Date().toISOString(), account: user.email, events: rows.map(toActivity) }, null, 2) };
    return { filename: 'account-activity.csv', mime: 'text/csv', text: toCsv(rows.map((r) => ({ ...r, actorEmail: r.actorId && r.actorId !== r.targetId ? 'administrator' : r.actorEmail })), AUDIT_COLUMNS) };
  },

  async sessions() {
    const { data, user, session, policy } = await authed();
    const cutoff = now() - sessionLifetimeMs(policy);
    user.sessions = user.sessions.filter((s) => s.createdAt > cutoff);
    saveDb(data);
    return [...user.sessions].reverse().map((s) => sessionView(s, session.sid));
  },

  async renameSession(id, name) {
    const { data, user } = await authed();
    const s = user.sessions.find((x) => x.sid === id);
    if (!s) throw E('Session not found', 404);
    s.name = String(name || '').trim().slice(0, 40) || undefined;
    saveDb(data);
    return { success: true };
  },

  async revokeSession(id) {
    const { data, user, session } = await authed();
    if (!user.sessions.some((s) => s.sid === id)) throw E('Session not found', 404);
    user.sessions = user.sessions.filter((s) => s.sid !== id);
    audit(data, 'session-revoked', { actor: user, target: user });
    saveDb(data);
    return { success: true, current: id === session.sid };
  },

  async revokeOtherSessions() {
    const { data, user, session } = await authed();
    user.sessions = user.sessions.filter((s) => s.sid === session.sid);
    audit(data, 'sessions-revoked', { actor: user, target: user });
    saveDb(data);
    return { success: true };
  },

  async revokeAllSessions() {
    const { data, user } = await authed();
    user.sessions = [];
    audit(data, 'sessions-revoked', { actor: user, target: user, meta: { all: true } });
    saveDb(data);
    return { success: true };
  },

  async revokeTrustedDevices() {
    const { data, user } = await authed({ fresh: true });
    user.trustedDevices = [];
    audit(data, 'trusted-devices-cleared', { actor: user, target: user });
    saveDb(data);
    return { success: true };
  },

  async stepUp({ password, code }) {
    const { data, user, session, policy } = await authed({ pending: true });
    rateCheck(data, 'sensitive');
    let ok = false;
    if (isStr(password)) {
      ok = await verifyPassword(password, user.password);
    } else if (isStr(code) && user.twoFactorMethod === 'totp') {
      const c = code.trim();
      if (/^\d{6}$/.test(c.replace(/\s/g, ''))) {
        const step = await verifyTotp(user.totpSecret, c);
        if (step !== null && step > user.lastTotpStep) { user.lastTotpStep = step; ok = true; }
      } else if (normBackup(c).length === 10) {
        const h = await hashBackup(c);
        if (user.backupCodes.includes(h)) { user.backupCodes = user.backupCodes.filter((x) => x !== h); ok = true; }
      }
    }
    if (!ok) {
      audit(data, 'step-up-failed', { actor: user, target: user, ok: false });
      saveDb(data);
      throw E(isStr(password) ? 'Password is incorrect' : 'That code is not valid', 403);
    }
    markFresh(session, policy);
    audit(data, 'step-up', { actor: user, target: user });
    saveDb(data);
    return { success: true, validForSeconds: policy.session.stepUpMinutes * 60 };
  },

  async changePassword({ currentPassword, newPassword }) {
    const { data, user, session, policy } = await authed({ pending: true });
    rateCheck(data, 'sensitive');
    if (!(await verifyPassword(currentPassword || '', user.password))) {
      audit(data, 'step-up-failed', { actor: user, target: user, ok: false });
      saveDb(data);
      throw E('Current password is incorrect', 403);
    }
    if (newPassword === currentPassword) throw E('New password must be different from the current one');
    const breach = await vetPassword(data, newPassword, { email: user.email, hashes: user.passwordHistory });
    await applyPassword(user, newPassword, policy, breach);
    user.sessions = user.sessions.filter((s) => s === session);
    user.trustedDevices = [];
    audit(data, 'password-changed', { actor: user, target: user });
    saveDb(data);
    return { success: true, message: 'Password changed. Other sessions were signed out.', ...(breach?.status === 'pwned' ? { warning: `This password appears in ${breach.count.toLocaleString('en-US')} known data breaches. Consider choosing another.` } : {}) };
  },

  async setMethod({ method }) {
    const { data, user, policy } = await authed({ pending: true, fresh: true });
    rateCheck(data, 'sensitive');
    if (!['email', 'none'].includes(method)) throw E('Unknown method');
    if (method === 'email' && !policy.twoFactor.methods.includes('email')) throw E('E-mail codes are not allowed by the security policy');
    if (method === 'none' && (twoFactorRequired(user, policy) || user.mustEnrollTwoFactor) && user.passkeys.length === 0) {
      throw E('Two-step verification is required for your account and cannot be turned off.');
    }
    Object.assign(user, { twoFactorMethod: method, totpSecret: null, pendingTotpSecret: null, lastTotpStep: -1, backupCodes: [], trustedDevices: [] });
    if (method !== 'none') user.mustEnrollTwoFactor = false;
    audit(data, '2fa-changed', { actor: user, target: user, meta: { method } });
    saveDb(data);
    return securityOf(user, policy);
  },

  async totpSetup() {
    const { data, user, policy } = await authed({ pending: true, fresh: true });
    rateCheck(data, 'sensitive');
    if (!policy.twoFactor.methods.includes('totp')) throw E('Authenticator apps are not allowed by the security policy');
    user.pendingTotpSecret = generateSecret();
    saveDb(data);
    return { secret: user.pendingTotpSecret, otpauthUrl: otpauthUrl({ secret: user.pendingTotpSecret, email: user.email }) };
  },

  async totpEnable({ code }) {
    const { data, user, policy } = await authed({ pending: true });
    rateCheck(data, 'sensitive');
    if (!user.pendingTotpSecret) throw E('Start the setup first');
    const step = await verifyTotp(user.pendingTotpSecret, code);
    if (step === null) throw E('That code is not valid. Check the time on your device and try again.');
    const codes = generateBackupCodes();
    Object.assign(user, {
      totpSecret: user.pendingTotpSecret, pendingTotpSecret: null, lastTotpStep: step, twoFactorMethod: 'totp', mustEnrollTwoFactor: false,
      backupCodes: await Promise.all(codes.map(hashBackup)), trustedDevices: [],
    });
    audit(data, '2fa-changed', { actor: user, target: user, meta: { method: 'totp' } });
    saveDb(data);
    return { backupCodes: codes, security: securityOf(user, policy) };
  },

  async regenerateBackupCodes() {
    const { data, user } = await authed({ fresh: true });
    rateCheck(data, 'sensitive');
    if (user.twoFactorMethod !== 'totp') throw E('Backup codes need the authenticator app to be enabled');
    const codes = generateBackupCodes();
    user.backupCodes = await Promise.all(codes.map(hashBackup));
    audit(data, 'backup-codes-regenerated', { actor: user, target: user });
    saveDb(data);
    return codes;
  },

  // ---- passkeys ----
  async passkeys() { const { user } = await authed({ pending: true }); return user.passkeys.map(passkeyView); },

  async passkeyRegisterOptions() {
    const { data, user } = await authed({ pending: true, fresh: true });
    rateCheck(data, 'sensitive');
    if (user.passkeys.length >= 10) throw E('You can register up to 10 passkeys.');
    const { id, challenge } = newChallenge(data, 'register', user.id);
    saveDb(data);
    return {
      challengeId: id,
      options: {
        rp: { id: rpId(), name: 'Multi Factor Authentication' }, user: { id: user.webauthnUserId, name: user.email, displayName: user.email }, challenge,
        pubKeyCredParams: PUBKEY_PARAMS, timeout: 60000, attestation: 'none',
        excludeCredentials: user.passkeys.map((p) => ({ id: p.credentialId, type: 'public-key', transports: p.transports })),
        authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      },
    };
  },

  async passkeyRegisterVerify({ challengeId, response, name }) {
    const { data, user } = await authed({ pending: true });
    rateCheck(data, 'sensitive');
    const c = takeChallenge(data, challengeId, 'register');
    if (!c || c.userId !== user.id || !response) { saveDb(data); throw E('The passkey request expired. Try again.'); }
    let v;
    try {
      v = await verifyRegistration({ response, expectedChallenge: c.challenge, expectedOrigin: location.origin, rpId: rpId() });
    } catch (error) {
      saveDb(data);
      throw E(`That passkey could not be verified (${error.message}).`);
    }
    if (Object.values(data.users).some((u) => u.passkeys.some((p) => p.credentialId === v.credentialId))) { saveDb(data); throw E('That passkey is already registered.'); }
    user.passkeys.push({
      credentialId: v.credentialId, publicKey: v.publicKey, counter: v.counter, transports: v.transports, name: (typeof name === 'string' && name.trim().slice(0, 40)) || `Passkey ${user.passkeys.length + 1}`,
      deviceType: v.deviceType, backedUp: v.backedUp, createdAt: now(), lastUsedAt: null,
    });
    user.mustEnrollTwoFactor = false;
    audit(data, 'passkey-added', { actor: user, target: user });
    saveDb(data);
    return user.passkeys.map(passkeyView);
  },

  async renamePasskey(id, name) {
    const { data, user } = await authed({ pending: true });
    const p = user.passkeys.find((x) => x.credentialId === id);
    if (!p) throw E('Passkey not found', 404);
    if (!isStr(String(name || '').trim())) throw E('Enter a name.');
    p.name = String(name).trim().slice(0, 40);
    saveDb(data);
    return { success: true };
  },

  async removePasskey(id) {
    const { data, user, policy } = await authed({ pending: true, fresh: true });
    rateCheck(data, 'sensitive');
    if (!user.passkeys.some((p) => p.credentialId === id)) throw E('Passkey not found', 404);
    if (compliance({ ...facts(user), passkeyCount: user.passkeys.length - 1 }, policy).some((r) => r.id === 'enroll-2fa')) {
      throw E('This is your last second step and two-step verification is required. Add another method first.');
    }
    user.passkeys = user.passkeys.filter((p) => p.credentialId !== id);
    audit(data, 'passkey-removed', { actor: user, target: user });
    saveDb(data);
    return user.passkeys.map(passkeyView);
  },

  async passkeyStepUpOptions() {
    const { data, user } = await authed({ pending: true });
    rateCheck(data, 'sensitive');
    if (!user.passkeys.length) throw E('No passkey registered');
    const { id, challenge } = newChallenge(data, 'stepup', user.id);
    saveDb(data);
    return { challengeId: id, options: authOptions(challenge, user.passkeys) };
  },

  async passkeyStepUpVerify({ challengeId, response }) {
    const { data, user, session, policy } = await authed({ pending: true });
    rateCheck(data, 'verify');
    const c = takeChallenge(data, challengeId, 'stepup');
    const pk = user.passkeys.find((p) => p.credentialId === response?.id);
    if (!c || c.userId !== user.id || !pk || !(await checkAssertion(data, c, response, pk))) {
      audit(data, 'step-up-failed', { actor: user, target: user, ok: false });
      saveDb(data);
      throw E('Passkey could not be verified', 403);
    }
    markFresh(session, policy);
    audit(data, 'step-up', { actor: user, target: user, meta: { via: 'passkey' } });
    saveDb(data);
    return { success: true, validForSeconds: policy.session.stepUpMinutes * 60 };
  },

  // ---- API tokens ----
  async tokens() { const { user } = await authed(); return user.apiTokens.map(tokenView); },

  async createToken(body) {
    const { data, user } = await authed({ fresh: true });
    rateCheck(data, 'sensitive');
    const parsed = validateTokenRequest(body || {});
    if (parsed.error) throw E(parsed.error);
    if (user.apiTokens.length >= MAX_TOKENS) throw E(`You can have up to ${MAX_TOKENS} tokens. Revoke one first.`);
    const token = `${TOKEN_PREFIX}${bytesToB64u(crypto.getRandomValues(new Uint8Array(24)))}`;
    const { name, scopes, expiresInDays } = parsed.value;
    const rec = { id: randomHex(6), name, prefix: token.slice(0, TOKEN_PREFIX.length + 6), hash: await sha256(token), scopes, createdAt: now(), lastUsedAt: null, expiresAt: expiresInDays ? now() + expiresInDays * DAY : null };
    user.apiTokens.push(rec);
    audit(data, 'api-token-created', { actor: user, target: user, meta: { name, scopes } });
    saveDb(data);
    return { token, tokenInfo: tokenView(rec) };
  },

  async revokeToken(id) {
    const { data, user } = await authed({ fresh: true });
    if (!user.apiTokens.some((t) => t.id === id)) throw E('Token not found', 404);
    user.apiTokens = user.apiTokens.filter((t) => t.id !== id);
    audit(data, 'api-token-revoked', { actor: user, target: user });
    saveDb(data);
    return { success: true };
  },

  // The "try it" box: calls a read-only route the way an external client would, with only the token.
  async callWithToken({ token, route }) {
    const data = await db();
    const h = await sha256(String(token || '').trim());
    const user = Object.values(data.users).find((u) => u.apiTokens.some((t) => t.hash === h));
    const tok = user?.apiTokens.find((t) => t.hash === h);
    if (!tok || (tok.expiresAt && tok.expiresAt < now())) return { status: 401, body: { success: false, message: 'Invalid or expired API token' } };
    const scope = ROUTE_SCOPES[route];
    if (!scope) return { status: 404, body: { success: false, message: 'Not found' } };
    if (!tok.scopes.includes(scope)) return { status: 403, body: { success: false, message: `This token is missing the "${scope}" scope` } };
    if (user.adminLocked) return { status: 403, body: { success: false, message: 'This account has been locked by an administrator.' } };
    tok.lastUsedAt = now();
    saveDb(data);
    const policy = data.policy;
    const bodies = {
      'GET /auth/me': () => ({ success: true, user: publicUser(user, policy) }),
      'GET /auth/security': () => ({ success: true, security: securityOf(user, policy) }),
      'GET /auth/activity': () => ({ success: true, events: data.audit.filter((e) => e.targetId === user.id).slice(0, 20).map(toActivity) }),
      'GET /auth/activity/export': () => ({ exportedAt: new Date().toISOString(), account: user.email, events: data.audit.filter((e) => e.targetId === user.id).slice(0, 20).map(toActivity) }),
      'GET /auth/sessions': () => ({ success: true, sessions: user.sessions.map((s) => sessionView(s, null)) }),
    };
    return { status: 200, body: bodies[route]() };
  },

  // ---- alerts ----
  async alerts() { const { user } = await authed({ pending: true }); return [...user.alerts].reverse().map(alertView); },

  async respondAlert({ id, answer }) {
    const { data, user } = await authed({ pending: true });
    const alert = user.alerts.find((a) => a.id === id);
    if (!alert) throw E('Alert not found', 404);
    if (!['yes', 'no'].includes(answer)) throw E('Answer yes or no');
    if (alert.status === 'pending') resolveAlert(data, user, alert, answer);
    return { success: true, status: alert.status, signedOut: answer === 'no' };
  },

  // ---- recovery e-mail ----
  async setRecoveryEmail({ email }) {
    const { data, user } = await authed({ fresh: true });
    rateCheck(data, 'sensitive');
    if (!/^\S+@\S+\.\S+$/.test((email || '').trim())) throw E('Enter a valid e-mail address.');
    const addr = norm(email);
    if (addr === user.email) throw E('Use an address different from your sign-in e-mail.');
    const code = randomCode();
    Object.assign(user, { recoveryEmailPending: addr, recoveryEmailHash: await sha256(code), recoveryEmailExpires: now() + RECOVERY_TTL_MS, recoveryEmailAttempts: 0 });
    pushMail({ kind: 'verify-recovery-email', to: addr, subject: 'Confirm your recovery e-mail', text: 'Your recovery e-mail confirmation code is below. It is valid for 15 minutes.', code });
    saveDb(data);
    return { success: true, message: `We sent a confirmation code to ${maskEmail(addr)}.` };
  },

  async verifyRecoveryEmail({ code }) {
    const { data, user, policy } = await authed();
    rateCheck(data, 'verify');
    const bad = E('Invalid or expired code');
    if (!user.recoveryEmailPending || !user.recoveryEmailHash || user.recoveryEmailExpires < now()) throw bad;
    if (user.recoveryEmailAttempts >= MAX_OTP_ATTEMPTS || user.recoveryEmailHash !== (await sha256(String(code ?? '').trim()))) {
      user.recoveryEmailAttempts += 1;
      if (user.recoveryEmailAttempts >= MAX_OTP_ATTEMPTS) user.recoveryEmailHash = null;
      saveDb(data);
      throw bad;
    }
    Object.assign(user, { recoveryEmail: user.recoveryEmailPending, recoveryEmailVerified: true, recoveryEmailPending: null, recoveryEmailHash: null, recoveryEmailExpires: 0 });
    audit(data, 'recovery-email-set', { actor: user, target: user });
    saveDb(data);
    return securityOf(user, policy);
  },

  async removeRecoveryEmail() {
    const { data, user, policy } = await authed({ fresh: true });
    Object.assign(user, { recoveryEmail: null, recoveryEmailVerified: false, recoveryEmailPending: null, recoveryEmailHash: null });
    audit(data, 'recovery-email-removed', { actor: user, target: user });
    saveDb(data);
    return securityOf(user, policy);
  },

  // ---- administrator console ----
  async adminStats() {
    const { data } = await authed({ admin: true });
    const users = Object.values(data.users);
    const t = now();
    const recent = data.audit.filter((e) => e.at >= t - DAY);
    const series = Array.from({ length: 7 }, (_, i) => {
      const date = new Date(t - (6 - i) * DAY).toISOString().slice(0, 10);
      const rows = data.audit.filter((e) => new Date(e.at).toISOString().slice(0, 10) === date && ['login', 'passkey-login', 'login-failed', 'code-failed', 'passkey-failed'].includes(e.event));
      return { date, signIns: rows.filter((e) => e.ok).length, failures: rows.filter((e) => !e.ok).length };
    });
    return {
      users: users.length, admins: users.filter((u) => u.role === 'admin').length, adminLocked: users.filter((u) => u.adminLocked).length, locked: users.filter((u) => u.lock.lockUntil > t).length,
      with2fa: users.filter((u) => u.twoFactorMethod !== 'none').length, withPasskeys: users.filter((u) => u.passkeys.length).length, assist: users.filter((u) => u.assistRequestedAt).length,
      events24h: recent.length, failures24h: recent.filter((e) => ['login-failed', 'code-failed', 'passkey-failed'].includes(e.event)).length, alerts24h: recent.filter((e) => e.event === 'new-device-alert').length, series,
    };
  },

  async adminUsers(q = {}) {
    const { data } = await authed({ admin: true });
    let rows = Object.values(data.users);
    if (isStr(q.q)) rows = rows.filter((u) => u.email.includes(q.q.trim().toLowerCase()));
    if (['user', 'admin'].includes(q.role)) rows = rows.filter((u) => u.role === q.role);
    if (['admin-locked', 'locked', 'active'].includes(q.status)) rows = rows.filter((u) => userStatus(u) === q.status);
    if (q.assist === 'true' || q.assist === true) rows = rows.filter((u) => u.assistRequestedAt);
    rows.sort((a, b) => a.email.localeCompare(b.email));
    const p = paginate(rows, q, 20);
    return { users: p.items.map(adminRow), total: p.total, page: p.page, pages: p.pages };
  },

  async adminUser(id) {
    const { data } = await authed({ admin: true });
    const u = findById(data, id);
    if (!u) throw E('User not found', 404);
    return { user: adminRow(u), events: data.audit.filter((e) => e.targetId === u.id).slice(0, 15).map((e) => ({ ...toActivity(e) })) };
  },

  async adminAction(id, action, body = {}) {
    const { data, user: me } = await authed({ admin: true, fresh: true });
    rateCheck(data, 'sensitive');
    if (!ACTIONS.includes(action)) throw E('Unknown action', 404);
    const user = findById(data, id);
    if (!user) throw E('User not found', 404);
    const self = user.id === me.id;
    const revoke = () => { user.sessions = []; };
    let event;
    let meta;
    if (action === 'lock') {
      if (self) throw E('You cannot lock your own account.');
      Object.assign(user, { adminLocked: true, adminLockReason: isStr(body.reason) ? body.reason.trim().slice(0, 200) : null });
      revoke(); event = 'admin-lock'; meta = { reason: user.adminLockReason };
    } else if (action === 'unlock') {
      Object.assign(user, { adminLocked: false, adminLockReason: null, lock: registerSuccess() }); event = 'admin-unlock';
    } else if (action === 'force-reset') {
      user.mustChangePassword = true; revoke(); event = 'admin-force-reset';
    } else if (action === 'force-enroll') {
      user.mustEnrollTwoFactor = true; event = 'admin-force-enroll';
    } else if (action === 'reset-2fa') {
      Object.assign(user, { twoFactorMethod: 'email', totpSecret: null, pendingTotpSecret: null, lastTotpStep: -1, backupCodes: [], passkeys: [], trustedDevices: [] }); revoke(); event = 'admin-reset-2fa';
    } else if (action === 'revoke-sessions') {
      revoke(); event = 'admin-revoke-sessions';
    } else if (action === 'role') {
      if (!['user', 'admin'].includes(body.role)) throw E('Role must be user or admin');
      if (self) throw E('You cannot change your own role.');
      if (user.role === 'admin' && body.role === 'user' && Object.values(data.users).filter((u) => u.role === 'admin').length <= 1) throw E('There must be at least one administrator.');
      user.role = body.role; event = 'admin-role-change'; meta = { role: body.role };
    } else if (action === 'issue-recovery') {
      const code = randomCode();
      user.recovery = { hash: await sha256(code), expires: now() + RECOVERY_TTL_MS, attempts: 0, sentAt: now() };
      Object.assign(user, { assistRequestedAt: null, assistMessage: null });
      pushMail({ kind: 'recovery', to: user.email, subject: 'Account recovery code', text: 'An administrator issued this recovery code at your request. It is valid for 15 minutes.', code });
      event = 'admin-recovery-issued';
    } else {
      Object.assign(user, { assistRequestedAt: null, assistMessage: null }); event = 'admin-recovery-issued'; meta = { cleared: true };
    }
    audit(data, event, { actor: me, target: user, meta });
    saveDb(data);
    return adminRow(user);
  },

  async adminAudit(q = {}) {
    const { data } = await authed({ admin: true });
    const p = paginate(data.audit.filter(auditFilter(q)), q, 25);
    return { events: p.items.map(auditRow), total: p.total, page: p.page, pages: p.pages };
  },

  async adminAuditExport(q = {}) {
    const { data, user } = await authed({ admin: true, fresh: true });
    const rows = data.audit.filter(auditFilter(q)).slice(0, 5000);
    audit(data, 'admin-audit-exported', { actor: user, meta: { rows: rows.length } });
    saveDb(data);
    return { filename: 'audit-log.csv', mime: 'text/csv', text: toCsv(rows, AUDIT_COLUMNS) };
  },

  async adminGetPolicy() { const { data } = await authed({ admin: true }); return data.policy; },

  async adminSetPolicy(input) {
    const { data, user } = await authed({ admin: true, fresh: true });
    rateCheck(data, 'sensitive');
    const { policy, errors } = normalizePolicy(input, data.policy);
    if (errors.length) throw E(errors[0].message, 400, { errors });
    const changed = policyDiff(data.policy, policy);
    data.policy = policy;
    audit(data, 'policy-updated', { actor: user, meta: { changed } });
    saveDb(data);
    return { policy, changed };
  },

  async adminTestMail() {
    const { data, user } = await authed({ admin: true, fresh: true });
    rateCheck(data, 'sensitive');
    const to = 'ops@example.org';
    pushMail({ kind: 'admin-test', to, subject: 'Security mail test', text: `This is a test message from the account security service, sent at ${new Date().toUTCString()}. In a real deployment it goes to ADMIN_NOTIFY_EMAIL.` });
    audit(data, 'admin-test-mail', { actor: user });
    saveDb(data);
    return { message: `Test e-mail sent to ${maskEmail(to)} (in the Preview inbox).` };
  },
};

export const previewApi = Object.fromEntries(Object.entries(handlers).map(([name, fn]) => [name, serial(fn)]));
