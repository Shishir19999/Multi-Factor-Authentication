// Shared server plumbing: policy store, audit log, sessions + cookies + CSRF, auth middleware, rate limiters, mail.
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import User from '../models/User.js';
import { AuditEvent, Setting } from '../models/Other.js';
import { defaultPolicy, normalizePolicy, compliance, sessionLifetimeMs, passwordAge, passwordError } from '../shared/policy.js';
import { RATE_LIMITS } from '../shared/ratelimit.js';
import { formatDuration } from '../shared/lockout.js';
import { deviceLabel, geoFromHeaders, assessLogin } from '../shared/risk.js';
import { eventCategory, eventSeverity } from '../shared/audit.js';
import { securityScore } from '../shared/score.js';
import { TOKEN_PREFIX, ROUTE_SCOPES } from '../shared/scopes.js';
import { checkPwned } from '../shared/pwned.js';
import { webauthnConfig } from './webauthn.js';

export const COOKIE_NAME = 'mfa_session';
export const OTP_TTL_MS = 5 * 60 * 1000;
export const MAX_OTP_ATTEMPTS = 5;
export const RESEND_COOLDOWN_MS = 30 * 1000;
export const RECOVERY_TTL_MS = 15 * 60 * 1000;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const MAX_ALERTS = 20;

export const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');
export const isStr = (v) => typeof v === 'string' && v.length > 0;
export const normEmail = (e) => e.trim().toLowerCase();
export const maskEmail = (e = '') => e.replace(/^(.).*?(@.*)$/, (_, a, b) => `${a}***${b}`);

function readCookie(req, name) {
  const h = req.headers.cookie;
  if (!h) return null;
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return null; }
    }
  }
  return null;
}

// CORS_ORIGIN: comma-separated allowed browser origins. Unset = localhost / 127.0.0.1 on any port (development).
export function originAllowed(origin, env = process.env) {
  const list = (env.CORS_ORIGIN || '').split(',').map((o) => o.trim()).filter(Boolean);
  if (list.length) return list.includes(origin);
  return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
}

export function corsOptions(env = process.env) {
  return { origin: (origin, cb) => cb(null, !origin || originAllowed(origin, env)), credentials: true };
}

export function createContext({ mail, limits = {}, env = process.env, webauthn = {}, breach, jwtSecret = () => process.env.JWT_SECRET } = {}) {
  // ---- policy (stored in MongoDB, cached briefly) ----
  let policyCache = null;
  let policyAt = 0;
  async function getPolicy() {
    if (policyCache && Date.now() - policyAt < 3000) return policyCache;
    const row = await Setting.findOne({ key: 'policy' }).lean();
    policyCache = normalizePolicy(row?.value || {}).policy;
    policyAt = Date.now();
    return policyCache;
  }
  async function savePolicy(policy) {
    await Setting.updateOne({ key: 'policy' }, { $set: { value: policy, updatedAt: new Date() } }, { upsert: true });
    policyCache = policy;
    policyAt = Date.now();
  }

  const wa = webauthnConfig(env, webauthn);
  const appUrl = () => (env.APP_URL || env.CORS_ORIGIN?.split(',')[0] || 'http://localhost:5173').replace(/\/+$/, '');

  // ---- mail ----
  async function sendMail(kind, data) {
    try {
      await mail(kind, data);
      return true;
    } catch (error) {
      console.error(`Error sending ${kind} mail:`, error.message);
      return false;
    }
  }

  // ---- request info + audit ----
  const deviceInfo = (req) => {
    const ua = String(req.headers['user-agent'] || '').slice(0, 200);
    const geo = geoFromHeaders(req.ip, req.headers);
    return { ip: req.ip, userAgent: ua, device: deviceLabel(ua), geo };
  };

  async function audit(req, event, { actor, target, ok = true, meta } = {}) {
    try {
      const info = req ? deviceInfo(req) : {};
      await AuditEvent.create({
        event, severity: eventSeverity(event), category: eventCategory(event), ok,
        actorId: actor ? String(actor._id) : undefined, actorEmail: actor?.email,
        targetId: target ? String(target._id) : undefined, targetEmail: target?.email,
        ip: info.ip, userAgent: info.userAgent, device: info.device, geo: info.geo?.label, meta,
      });
    } catch (error) {
      console.error('Audit log write failed:', error.message);
    }
  }

  // ---- password helpers ----
  async function breachLookup(password) {
    if (breach) return breach(password);
    return checkPwned(password, { padding: true, timeoutMs: 3000 });
  }

  // Validates a new password against policy, history and (optionally) the breach list.
  // Returns { error } or { breach } where breach is { status, count? } or null.
  async function vetPassword(password, { email, hashes = [] }, policy) {
    const err = passwordError(password, policy, { email });
    if (err) return { error: err };
    for (const h of hashes) {
      if (await bcrypt.compare(password, h)) {
        return { error: `You used this password before. Choose one that is not among your last ${Math.max(1, policy.password.historyCount)} passwords.` };
      }
    }
    if (policy.breachCheck === 'off') return { breach: null };
    const result = await breachLookup(password);
    if (result.status === 'pwned' && policy.breachCheck === 'block') {
      return { error: `This password appears in ${result.count.toLocaleString('en-US')} known data breaches. Choose a different one.` };
    }
    return { breach: result };
  }

  async function applyPassword(user, newPassword, policy, breachResult) {
    const old = user.password;
    user.password = await bcrypt.hash(newPassword, 10);
    if (old && policy.password.historyCount > 0) user.passwordHistory = [old, ...user.passwordHistory].slice(0, policy.password.historyCount);
    user.passwordChangedAt = new Date();
    user.mustChangePassword = false;
    if (breachResult) {
      user.breachStatus = breachResult.status === 'pwned' ? 'pwned' : breachResult.status === 'safe' ? 'clean' : user.breachStatus;
      if (breachResult.status !== 'unavailable') user.breachCheckedAt = new Date();
    }
  }

  // ---- views of a user ----
  const facts = (u) => ({
    role: u.role, twoFactorMethod: u.twoFactorMethod || 'email', passkeyCount: u.passkeys.length,
    passwordChangedAt: u.passwordChangedAt, mustChangePassword: u.mustChangePassword, mustEnrollTwoFactor: u.mustEnrollTwoFactor,
  });
  const requirementsOf = (u, policy) => compliance(facts(u), policy);
  const publicUser = (u, policy) => ({
    id: u._id, email: u.email, role: u.role || 'user', twoFactorMethod: u.twoFactorMethod || 'email', createdAt: u.createdAt,
    requirements: requirementsOf(u, policy),
  });
  const unreviewed = (u) => u.alerts.filter((a) => a.status === 'pending');

  function securityOf(u, policy) {
    const now = Date.now();
    const trusted = u.trustedDevices.filter((d) => d.expires > now).length;
    const age = passwordAge(u.passwordChangedAt, policy, now);
    const scoreFacts = {
      twoFactorMethod: u.twoFactorMethod || 'email', passkeyCount: u.passkeys.length, backupCodesRemaining: u.backupCodes.length,
      passwordChangedAt: u.passwordChangedAt, breachStatus: u.breachStatus || 'unknown', recoveryEmailVerified: !!u.recoveryEmailVerified,
      trustedDevices: trusted, sessionCount: u.sessions.length, unreviewedAlerts: unreviewed(u).length,
      riskyTokens: u.apiTokens.filter((t) => !t.expiresAt).length,
    };
    return {
      email: u.email, role: u.role || 'user', twoFactorMethod: u.twoFactorMethod || 'email', passkeys: u.passkeys.length,
      backupCodesRemaining: u.backupCodes.length, trustedDevices: trusted, createdAt: u.createdAt,
      passwordChangedAt: u.passwordChangedAt, passwordAge: age, breachStatus: scoreFacts.breachStatus,
      recoveryEmail: u.recoveryEmailVerified ? maskEmail(u.recoveryEmail) : null,
      sessionCount: u.sessions.length, apiTokens: u.apiTokens.length, unreviewedAlerts: scoreFacts.unreviewedAlerts,
      requirements: requirementsOf(u, policy), score: securityScore(scoreFacts, policy, now),
    };
  }

  // ---- sessions, cookies, CSRF ----
  const csrfFor = (sid) => crypto.createHmac('sha256', jwtSecret()).update(`csrf:${sid}`).digest('hex');
  const sameToken = (a, b) => {
    const x = Buffer.from(String(a)); const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  };
  const cookieOptions = (policy) => ({
    httpOnly: true,
    sameSite: (env.COOKIE_SAMESITE || 'lax').toLowerCase(),
    secure: env.COOKIE_SECURE ? env.COOKIE_SECURE === 'true' : env.NODE_ENV === 'production',
    path: '/',
    maxAge: sessionLifetimeMs(policy),
  });
  const clearSessionCookie = (res) => res.clearCookie(COOKIE_NAME, { ...cookieOptions(defaultPolicy()), maxAge: undefined });

  function pruneSessions(user, policy) {
    const cutoff = Date.now() - sessionLifetimeMs(policy);
    user.sessions = user.sessions.filter((x) => x.createdAt && x.createdAt.getTime() > cutoff);
  }

  // Creates a session after every required factor passed. Returns the JSON payload for the client.
  async function finishLogin(req, res, user, { trust = false, method = 'email', via = 'password' } = {}) {
    const policy = await getPolicy();
    const info = deviceInfo(req);
    const now = Date.now();
    pruneSessions(user, policy);
    const sid = crypto.randomUUID();
    user.sessions.push({
      sid, createdAt: new Date(), lastSeen: new Date(), ip: info.ip, userAgent: info.userAgent, device: info.device, geo: info.geo.label, via,
      stepUpUntil: new Date(now + policy.session.stepUpMinutes * 60000),
    });
    if (user.sessions.length > policy.session.maxSessions) user.sessions = user.sessions.slice(-policy.session.maxSessions);

    let deviceToken;
    if (trust && method !== 'none' && policy.trustedDeviceDays > 0) {
      deviceToken = crypto.randomBytes(32).toString('hex');
      user.trustedDevices = user.trustedDevices.filter((d) => d.expires > now).slice(-9);
      user.trustedDevices.push({
        hash: sha(deviceToken), expires: new Date(now + policy.trustedDeviceDays * 86400000), userAgent: info.userAgent, device: info.device, createdAt: new Date(),
      });
    }

    // new-device / new-location detection
    const risk = assessLogin({ family: info.device, geo: info.geo }, { devices: user.knownDevices, places: user.knownPlaces });
    let alertInfo;
    if (!risk.firstLogin && risk.level !== 'low' && policy.alerts.newDevice) {
      const alertId = crypto.randomBytes(6).toString('hex');
      const secret = crypto.randomBytes(24).toString('hex');
      user.alerts.push({
        id: alertId, at: new Date(), ip: info.ip, userAgent: info.userAgent, device: info.device, geo: info.geo.label, family: info.device,
        placeKey: info.geo.key, reasons: risk.reasons, level: risk.level, status: 'pending', tokenHash: sha(secret),
      });
      if (user.alerts.length > MAX_ALERTS) user.alerts = user.alerts.slice(-MAX_ALERTS);
      alertInfo = { id: alertId, level: risk.level, reasons: risk.reasons };
      const link = `${appUrl()}/review?t=${user._id}.${alertId}.${secret}`;
      sendMail('new-device', { to: user.email, device: info.device, geo: info.geo.label, ip: info.ip, time: new Date().toUTCString(), link, reasons: risk.reasons });
      await audit(req, 'new-device-alert', { actor: user, target: user, meta: { reasons: risk.reasons, level: risk.level } });
    }
    if (!user.knownDevices.includes(info.device)) user.knownDevices = [...user.knownDevices, info.device].slice(-20);
    if (info.geo.key !== 'unknown' && !user.knownPlaces.includes(info.geo.key)) user.knownPlaces = [...user.knownPlaces, info.geo.key].slice(-20);

    user.failedLogins = 0;
    user.lockCount = 0;
    user.lockUntil = undefined;
    user.lastLoginAt = new Date();
    await user.save();
    await audit(req, via === 'passkey' ? 'passkey-login' : 'login', { actor: user, target: user, meta: { via } });

    const token = jwt.sign({ sub: String(user._id), tv: user.tokenVersion ?? 0, sid }, jwtSecret(), { expiresIn: Math.floor(sessionLifetimeMs(policy) / 1000) });
    res.cookie(COOKIE_NAME, token, cookieOptions(policy));
    const bearer = String(req.headers['x-auth-transport'] || '').toLowerCase() === 'bearer';
    return {
      success: true, user: publicUser(user, policy), csrfToken: csrfFor(sid), ...(bearer ? { token } : {}),
      ...(deviceToken ? { deviceToken } : {}), ...(alertInfo ? { alert: alertInfo } : {}),
    };
  }

  // ---- auth middleware ----
  // opts: pending (allow accounts that still have to change password / enrol 2FA), scope (accept a personal API
  // token with this scope), admin, fresh (true | 'session': require recent step-up; 'session' lets API tokens through).
  const deny = (res, status, message, extra = {}) => res.status(status).json({ success: false, message, ...extra });

  function auth(opts = {}) {
    return async (req, res, next) => {
      try {
        const policy = await getPolicy();
        req.policy = policy;
        const header = req.headers.authorization || '';
        const bearer = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
        let user;

        if (bearer?.startsWith(TOKEN_PREFIX)) {
          const h = sha(bearer);
          user = await User.findOne({ 'apiTokens.hash': h });
          const tok = user?.apiTokens.find((t) => t.hash === h);
          if (!tok || (tok.expiresAt && tok.expiresAt.getTime() < Date.now())) return deny(res, 401, 'Invalid or expired API token');
          if (!opts.scope) return deny(res, 403, 'API tokens cannot be used for this endpoint');
          if (!tok.scopes.includes(opts.scope)) return deny(res, 403, `This token is missing the "${opts.scope}" scope`);
          if (opts.fresh === true || opts.admin) return deny(res, 403, 'API tokens cannot be used for this endpoint');
          await User.updateOne({ _id: user._id, 'apiTokens.id': tok.id }, { $set: { 'apiTokens.$.lastUsedAt': new Date() } });
          req.auth = { pat: true, tokenId: tok.id, sid: null };
        } else {
          const cookieToken = bearer ? null : readCookie(req, COOKIE_NAME);
          const token = bearer || cookieToken;
          if (!token) return deny(res, 401, 'Missing token');
          let payload;
          try {
            payload = jwt.verify(token, jwtSecret());
          } catch {
            return deny(res, 401, 'Invalid or expired token');
          }
          user = await User.findById(payload.sub);
          if (!user) return deny(res, 401, 'User not found');
          if ((payload.tv ?? 0) !== (user.tokenVersion ?? 0)) return deny(res, 401, 'Token has been revoked');
          const sess = payload.sid ? user.sessions.find((x) => x.sid === payload.sid) : null;
          if (!sess) return deny(res, 401, 'Session has been revoked');
          const idle = policy.session.idleMinutes;
          if (idle > 0 && sess.lastSeen && Date.now() - sess.lastSeen.getTime() > idle * 60000) {
            await User.updateOne({ _id: user._id }, { $pull: { sessions: { sid: sess.sid } } });
            return deny(res, 401, 'Session expired after a period of inactivity');
          }
          if (cookieToken && !SAFE_METHODS.has(req.method)) {
            const origin = req.headers.origin;
            if (origin && !originAllowed(origin, env)) return deny(res, 403, 'Origin not allowed', { code: 'CSRF' });
            if (!sameToken(req.headers['x-csrf-token'] || '', csrfFor(sess.sid))) return deny(res, 403, 'Missing or invalid CSRF token', { code: 'CSRF' });
          }
          if (!sess.lastSeen || Date.now() - sess.lastSeen.getTime() > 30 * 1000) {
            await User.updateOne({ _id: user._id, 'sessions.sid': sess.sid }, { $set: { 'sessions.$.lastSeen': new Date() } });
          }
          req.auth = { pat: false, sid: sess.sid, session: sess, cookie: !!cookieToken };
          req.csrfToken = csrfFor(sess.sid);
        }

        if (user.adminLocked) return deny(res, 403, 'This account has been locked by an administrator.', { code: 'ACCOUNT_LOCKED' });
        req.user = user;
        if (!opts.pending) {
          const requirements = requirementsOf(user, policy);
          if (requirements.length) return deny(res, 403, requirements[0].message, { code: 'ACTION_REQUIRED', requirements });
        }
        if (opts.admin && user.role !== 'admin') return deny(res, 403, 'Administrator access required', { code: 'FORBIDDEN' });

        const needFresh = opts.fresh === true || (opts.fresh === 'session' && !req.auth.pat);
        if (needFresh && !(req.auth.session?.stepUpUntil && req.auth.session.stepUpUntil.getTime() > Date.now())) {
          // Backwards compatible: a request that carries the current password re-confirms identity inline.
          if (isStr(req.body?.password)) {
            if (!(await bcrypt.compare(req.body.password, user.password))) {
              await audit(req, 'step-up-failed', { actor: user, target: user, ok: false });
              return deny(res, 403, 'Password is incorrect');
            }
            await markFresh(user, req.auth.sid, policy);
          } else {
            return deny(res, 403, 'Please confirm it is you to continue.', {
              code: 'STEP_UP_REQUIRED', stepUp: { password: true, totp: user.twoFactorMethod === 'totp', passkey: user.passkeys.length > 0 },
            });
          }
        }
        return next();
      } catch (error) {
        console.error('Error in auth middleware:', error.message);
        return deny(res, 500, 'Internal Server Error');
      }
    };
  }

  async function markFresh(user, sid, policy) {
    const until = new Date(Date.now() + policy.session.stepUpMinutes * 60000);
    await User.updateOne({ _id: user._id, 'sessions.sid': sid }, { $set: { 'sessions.$.stepUpUntil': until } });
    const s = user.sessions.find((x) => x.sid === sid);
    if (s) s.stepUpUntil = until;
  }

  // "Was this you?" answer. Denying signs everything out and forces a new password.
  async function resolveAlert(req, user, alert, answer) {
    if (answer === 'yes') {
      alert.status = 'confirmed';
      await user.save();
      await audit(req, 'alert-confirmed', { actor: user, target: user });
      return;
    }
    alert.status = 'denied';
    user.sessions = [];
    user.tokenVersion = (user.tokenVersion ?? 0) + 1;
    user.mustChangePassword = true;
    user.trustedDevices = [];
    user.knownDevices = user.knownDevices.filter((d) => d !== alert.family);
    user.knownPlaces = user.knownPlaces.filter((p) => p !== alert.placeKey);
    await user.save();
    await audit(req, 'alert-denied', { actor: user, target: user, ok: false, meta: { device: alert.device, geo: alert.geo } });
  }

  // ---- rate limiting with visible countdowns ----
  const limiter = (name) => {
    const cfg = RATE_LIMITS[name];
    return rateLimit({
      windowMs: cfg.windowMs,
      limit: limits[name] ?? cfg.limit,
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        const retryAfterSeconds = Math.max(1, Math.ceil((req.rateLimit.resetTime.getTime() - Date.now()) / 1000));
        res.set('Retry-After', String(retryAfterSeconds));
        res.status(429).json({ success: false, rateLimited: true, retryAfterSeconds, message: `${cfg.message} Try again in ${formatDuration(retryAfterSeconds)}.` });
      },
    });
  };

  const wrap = (fn) => async (req, res) => {
    try {
      await fn(req, res);
    } catch (error) {
      console.error('Error in', req.method, req.path, error.message);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
  };

  return {
    env, getPolicy, savePolicy, wa, appUrl, sendMail, deviceInfo, audit, vetPassword, applyPassword, facts, requirementsOf, publicUser,
    securityOf, unreviewed, resolveAlert, csrfFor, cookieOptions, clearSessionCookie, finishLogin, markFresh, auth, limiter, wrap, pruneSessions, breachLookup,
    ROUTE_SCOPES,
  };
}
