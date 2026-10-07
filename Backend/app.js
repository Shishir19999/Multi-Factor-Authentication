import express from 'express';
import cors from 'cors';
import randomize from 'randomatic';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import User from './models/User.js';
import crypto from 'node:crypto';
import { sendOtpEmail as defaultSendOtpEmail, sendRecoveryEmail as defaultSendRecoveryEmail } from './mailer.js';
import { generateSecret, otpauthUrl, verifyTotp } from './totp.js';
import { generateBackupCodes, hashBackupCode, consumeBackupCode } from './backupCodes.js';
import { validatePassword } from './password.js';

export const OTP_TTL_MS = 5 * 60 * 1000; // OTP valid for 5 minutes
export const MAX_OTP_ATTEMPTS = 5;
export const RESEND_COOLDOWN_MS = 30 * 1000;
export const MAX_LOGIN_FAILURES = 5;
export const LOCKOUT_MS = 15 * 60 * 1000;
export const RECOVERY_TTL_MS = 15 * 60 * 1000;
export const TRUSTED_DEVICE_MS = 30 * 24 * 60 * 60 * 1000;
const JWT_EXPIRES_IN = '1h';
const SESSION_TTL_MS = 60 * 60 * 1000;
const MAX_SESSIONS = 10;
const MAX_LOG = 50;
const jwtSecret = () => process.env.JWT_SECRET;

// CORS_ORIGIN: comma-separated allowed origins (e.g. http://localhost:5173,http://192.168.1.20:5173); unset = any origin.
export function corsOptions() {
  const list = (process.env.CORS_ORIGIN || '').split(',').map((o) => o.trim()).filter(Boolean);
  return list.length ? { origin: list } : {};
}

const limiterOptions = (windowMs, limit, message) => ({
  windowMs,
  limit,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ success: false, message }),
});

const isStr = (v) => typeof v === 'string' && v.length > 0;
const normEmail = (e) => e.trim().toLowerCase();

// createApp({ sendOtpEmail, limits }) - sendOtpEmail(email, otp) can be replaced by a stub in tests.
export function createApp({ sendOtpEmail = defaultSendOtpEmail, sendRecoveryEmail = defaultSendRecoveryEmail, limits = {} } = {}) {
  const app = express();
  const loginLimiter = rateLimit(limiterOptions(15 * 60 * 1000, limits.login ?? 10, 'Too many login attempts. Try again later.'));
  const verifyLimiter = rateLimit(limiterOptions(15 * 60 * 1000, limits.verify ?? 20, 'Too many verification attempts. Try again later.'));
  const resendLimiter = rateLimit(limiterOptions(15 * 60 * 1000, limits.resend ?? 10, 'Too many resend requests. Try again later.'));

  const sensitiveLimiter = rateLimit(limiterOptions(15 * 60 * 1000, limits.sensitive ?? 30, 'Too many attempts. Try again later.'));
  const recoverLimiter = rateLimit(limiterOptions(15 * 60 * 1000, limits.recover ?? 10, 'Too many recovery requests. Try again later.'));

  app.use(express.json());
  // Express 5 leaves req.body undefined when no body is sent; keep the Express 4 behavior (empty object).
  app.use((req, res, next) => { if (req.body === undefined) req.body = {}; next(); });
  app.use(cors(corsOptions()));

  function clearOtp(user) {
    user.otpHash = undefined;
    user.otpExpires = undefined;
    user.otpAttempts = 0;
  }

  // Issue a fresh OTP for the user, store only its hash, and email it
  async function issueOtp(user) {
    const otp = randomize('0', 6);
    user.otpHash = await bcrypt.hash(otp, 8);
    user.otpExpires = new Date(Date.now() + OTP_TTL_MS);
    user.otpAttempts = 0;
    user.otpSentAt = new Date();
    await user.save();
    try {
      await sendOtpEmail(user.email, otp);
    } catch (mailError) {
      console.error('Error sending email:', mailError.message);
      clearOtp(user);
      user.otpSentAt = undefined;
      await user.save();
      return false;
    }
    return true;
  }

  const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');
  const deviceInfo = (req) => ({ ip: req.ip, userAgent: String(req.headers['user-agent'] || '').slice(0, 200) });
  const publicUser = (u) => ({ id: u._id, email: u.email, twoFactorMethod: u.twoFactorMethod || 'email', createdAt: u.createdAt });

  function logEvent(user, req, event, ok) {
    user.signIns.push({ at: new Date(), event, ok, ...deviceInfo(req) });
    if (user.signIns.length > MAX_LOG) user.signIns = user.signIns.slice(-MAX_LOG);
  }

  function pruneSessions(user) {
    const cutoff = Date.now() - SESSION_TTL_MS;
    user.sessions = user.sessions.filter((x) => x.createdAt && x.createdAt.getTime() > cutoff);
  }

  // Creates a session + JWT after the user passed every required factor.
  async function finishLogin(user, req, { trust = false, method = 'email' } = {}) {
    pruneSessions(user);
    const sid = crypto.randomUUID();
    user.sessions.push({ sid, createdAt: new Date(), lastSeen: new Date(), ...deviceInfo(req) });
    if (user.sessions.length > MAX_SESSIONS) user.sessions = user.sessions.slice(-MAX_SESSIONS);
    let deviceToken;
    if (trust && method !== 'none') {
      deviceToken = crypto.randomBytes(32).toString('hex');
      user.trustedDevices = user.trustedDevices.filter((d) => d.expires > new Date()).slice(-9);
      user.trustedDevices.push({ hash: sha(deviceToken), expires: new Date(Date.now() + TRUSTED_DEVICE_MS), userAgent: deviceInfo(req).userAgent });
    }
    logEvent(user, req, 'login', true);
    user.failedLogins = 0;
    user.lockUntil = undefined;
    await user.save();
    const token = jwt.sign(
      { sub: String(user._id), email: user.email, tv: user.tokenVersion ?? 0, sid },
      jwtSecret(),
      { expiresIn: JWT_EXPIRES_IN },
    );
    return { success: true, token, user: publicUser(user), ...(deviceToken ? { deviceToken } : {}) };
  }

  // Auth middleware: requires "Authorization: Bearer <jwt>" that matches the user's tokenVersion and a live session
  async function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, message: 'Missing token' });
    let payload;
    try {
      payload = jwt.verify(token, jwtSecret());
    } catch {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
    try {
      const user = await User.findById(payload.sub);
      if (!user) return res.status(401).json({ success: false, message: 'User not found' });
      if ((payload.tv ?? 0) !== (user.tokenVersion ?? 0)) {
        return res.status(401).json({ success: false, message: 'Token has been revoked' });
      }
      if (payload.sid) {
        const sess = user.sessions.find((x) => x.sid === payload.sid);
        if (!sess) return res.status(401).json({ success: false, message: 'Session has been revoked' });
        if (!sess.lastSeen || Date.now() - sess.lastSeen.getTime() > 60 * 1000) {
          await User.updateOne({ _id: user._id, 'sessions.sid': payload.sid }, { $set: { 'sessions.$.lastSeen': new Date() } });
        }
      }
      req.auth = payload;
      req.user = user;
      return next();
    } catch (error) {
      console.error('Error in auth middleware:', error.message);
      return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
  }

  // Re-authentication for sensitive actions: the body must carry the current password.
  async function reauth(req, res) {
    const { password } = req.body || {};
    if (!isStr(password) || !(await bcrypt.compare(password, req.user.password))) {
      res.status(403).json({ success: false, message: 'Password is incorrect' });
      return false;
    }
    return true;
  }

  // Registration endpoint
  app.post('/auth/register', async (req, res) => {
    const { email: rawEmail, password } = req.body || {};

    try {
      if (typeof rawEmail !== 'string' || !/^\S+@\S+\.\S+$/.test(rawEmail.trim())) {
        return res.status(400).json({ success: false, message: 'A valid email is required' });
      }
      const pwError = validatePassword(password);
      if (pwError) return res.status(400).json({ success: false, message: pwError });
      const email = normEmail(rawEmail);
      if (await User.findOne({ email })) {
        return res.status(400).json({ success: false, message: 'Email already exists' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      await new User({ email, password: hashedPassword }).save();
      return res.json({ success: true, message: 'User registered successfully', redirectTo: '/login' });
    } catch (error) {
      console.error('Error during registration:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred during registration' });
    }
  });

  // Login endpoint (step 1: password; then a second factor unless disabled or the device is trusted)
  app.post('/auth/login', loginLimiter, async (req, res) => {
    const { email, password, deviceToken } = req.body || {};

    try {
      if (!isStr(email) || !isStr(password)) {
        return res.status(400).json({ success: false, message: 'Email and password are required' });
      }
      const user = await User.findOne({ email: normEmail(email) });
      if (!user) return res.json({ success: false, message: 'Invalid credentials' });

      if (user.lockUntil && user.lockUntil.getTime() > Date.now()) {
        const retryAfterSeconds = Math.ceil((user.lockUntil.getTime() - Date.now()) / 1000);
        res.set('Retry-After', String(retryAfterSeconds));
        return res.status(423).json({
          success: false,
          locked: true,
          retryAfterSeconds,
          message: `Account temporarily locked after too many failed attempts. Try again in ${Math.ceil(retryAfterSeconds / 60)} minute(s) or reset your password.`,
        });
      }

      if (!(await bcrypt.compare(password, user.password))) {
        user.failedLogins = (user.failedLogins || 0) + 1;
        logEvent(user, req, 'login-failed', false);
        const left = MAX_LOGIN_FAILURES - user.failedLogins;
        if (left <= 0) {
          user.lockUntil = new Date(Date.now() + LOCKOUT_MS);
          user.failedLogins = 0;
        }
        await user.save();
        return res.json({
          success: false,
          message: left > 0 ? 'Invalid credentials' : 'Too many failed attempts. The account is locked for 15 minutes.',
          ...(left > 0 && left <= 2 ? { attemptsLeft: left } : {}),
        });
      }

      const method = user.twoFactorMethod || 'email';
      if (method === 'none') {
        return res.json({ ...(await finishLogin(user, req, { method })), method });
      }
      if (isStr(deviceToken)) {
        const h = sha(deviceToken);
        if (user.trustedDevices.some((d) => d.hash === h && d.expires > new Date())) {
          return res.json({ ...(await finishLogin(user, req, { method })), method: 'trusted' });
        }
      }

      if (method === 'totp') {
        clearOtp(user);
        user.otpExpires = new Date(Date.now() + OTP_TTL_MS);
        user.otpSentAt = new Date();
        await user.save();
        return res.json({ success: true, method: 'totp' });
      }

      if (!(await issueOtp(user))) {
        return res.status(500).json({ success: false, message: 'Could not send the OTP email. Please try again later.' });
      }

      return res.json({ success: true, method: 'email', resendCooldownSeconds: RESEND_COOLDOWN_MS / 1000 });
    } catch (error) {
      console.error('Error during login:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred during login' });
    }
  });

  // Resend OTP (only after a successful password login created a pending OTP)
  app.post('/auth/resend-otp', resendLimiter, async (req, res) => {
    const { email } = req.body || {};

    try {
      if (!isStr(email)) {
        return res.status(400).json({ success: false, message: 'Email is required' });
      }
      const user = await User.findOne({ email: normEmail(email) });
      if (!user || !user.otpSentAt || !user.otpHash) {
        return res.status(400).json({ success: false, message: 'Please log in again' });
      }

      const waitMs = user.otpSentAt.getTime() + RESEND_COOLDOWN_MS - Date.now();
      if (waitMs > 0) {
        const retryAfterSeconds = Math.ceil(waitMs / 1000);
        res.set('Retry-After', String(retryAfterSeconds));
        return res.status(429).json({
          success: false,
          message: `Please wait ${retryAfterSeconds}s before requesting a new code`,
          retryAfterSeconds,
        });
      }

      if (!(await issueOtp(user))) {
        return res.status(500).json({ success: false, message: 'Could not send the OTP email. Please try again later.' });
      }
      return res.json({ success: true, resendCooldownSeconds: RESEND_COOLDOWN_MS / 1000 });
    } catch (error) {
      console.error('Error during OTP resend:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred while resending the OTP' });
    }
  });

  // Second-factor verification (step 2): e-mailed OTP, authenticator code or a backup code
  app.post('/auth/verify-otp', verifyLimiter, async (req, res) => {
    const { email, otp, trust } = req.body || {};

    try {
      if (!isStr(email) || !(isStr(otp) || typeof otp === 'number')) {
        return res.status(400).json({ success: false, message: 'Email and OTP are required' });
      }

      const user = await User.findOne({ email: normEmail(email) });
      const method = user?.twoFactorMethod || 'email';
      const pending = user && user.otpExpires && user.otpExpires.getTime() >= Date.now() && (method === 'totp' || user.otpHash);

      if (!pending) {
        return res.json({ success: false, message: 'Invalid or expired OTP' });
      }

      if (user.otpAttempts >= MAX_OTP_ATTEMPTS) {
        clearOtp(user);
        await user.save();
        return res.json({ success: false, message: 'Too many attempts. Please log in again.' });
      }

      const code = String(otp).trim();
      let ok = false;
      if (method === 'totp') {
        if (/^\d{6}$/.test(code.replace(/\s/g, ''))) {
          const step = verifyTotp(user.totpSecret, code);
          if (step !== null && step > (user.lastTotpStep ?? -1)) { user.lastTotpStep = step; ok = true; }
        } else {
          const rest = consumeBackupCode(user.backupCodes, code);
          if (rest) { user.backupCodes = rest; ok = true; }
        }
      } else {
        ok = await bcrypt.compare(code, user.otpHash);
      }

      if (!ok) {
        user.otpAttempts += 1;
        logEvent(user, req, 'code-failed', false);
        const remaining = MAX_OTP_ATTEMPTS - user.otpAttempts;
        if (remaining <= 0) clearOtp(user);
        await user.save();
        return res.json({
          success: false,
          message: remaining > 0 ? `Invalid OTP. ${remaining} attempt(s) left.` : 'Too many attempts. Please log in again.',
        });
      }

      clearOtp(user);
      user.otpSentAt = undefined;
      return res.json(await finishLogin(user, req, { trust: trust === true, method }));
    } catch (error) {
      console.error('Error during OTP verification:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred during OTP verification' });
    }
  });

  // Current user (protected)
  app.get('/auth/me', requireAuth, (req, res) => {
    res.json({ success: true, user: publicUser(req.user) });
  });

  // Logout: bumps tokenVersion so every JWT issued so far for this user stops working.
  app.post('/auth/logout', requireAuth, async (req, res) => {
    try {
      await User.updateOne({ _id: req.user._id }, { $inc: { tokenVersion: 1 }, $set: { sessions: [] } });
      return res.json({ success: true, message: 'Logged out' });
    } catch (error) {
      console.error('Error during logout:', error.message);
      return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
  });

  // ---- Security dashboard ----

  const wrap = (fn) => async (req, res) => {
    try {
      await fn(req, res);
    } catch (error) {
      console.error('Error in', req.path, error.message);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
  };

  const securityOf = (u) => ({
    email: u.email,
    twoFactorMethod: u.twoFactorMethod || 'email',
    backupCodesRemaining: u.backupCodes.length,
    trustedDevices: u.trustedDevices.filter((d) => d.expires > new Date()).length,
    createdAt: u.createdAt,
  });

  app.get('/auth/security', requireAuth, (req, res) => res.json({ success: true, security: securityOf(req.user) }));

  app.get('/auth/activity', requireAuth, (req, res) => {
    const events = [...req.user.signIns].reverse().map((e, i) => ({
      id: `${e.at.getTime()}-${i}`, at: e.at, event: e.event, ok: e.ok, ip: e.ip, userAgent: e.userAgent,
    }));
    res.json({ success: true, events });
  });

  app.get('/auth/sessions', requireAuth, wrap(async (req, res) => {
    const before = req.user.sessions.length;
    pruneSessions(req.user);
    if (req.user.sessions.length !== before) await req.user.save();
    const sessions = [...req.user.sessions].reverse().map((x) => ({
      id: x.sid, current: x.sid === req.auth.sid, ip: x.ip, userAgent: x.userAgent, createdAt: x.createdAt, lastSeen: x.lastSeen,
    }));
    res.json({ success: true, sessions });
  }));

  app.delete('/auth/sessions/:sid', requireAuth, wrap(async (req, res) => {
    if (!req.user.sessions.some((x) => x.sid === req.params.sid)) {
      return res.status(404).json({ success: false, message: 'Session not found' });
    }
    await User.updateOne({ _id: req.user._id }, { $pull: { sessions: { sid: req.params.sid } } });
    return res.json({ success: true, current: req.params.sid === req.auth.sid });
  }));

  app.post('/auth/sessions/revoke-others', requireAuth, wrap(async (req, res) => {
    await User.updateOne({ _id: req.user._id }, { $pull: { sessions: { sid: { $ne: req.auth.sid } } } });
    res.json({ success: true });
  }));

  app.post('/auth/change-password', requireAuth, sensitiveLimiter, wrap(async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    const user = req.user;
    if (!isStr(currentPassword) || !(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(403).json({ success: false, message: 'Current password is incorrect' });
    }
    const pwError = validatePassword(newPassword);
    if (pwError) return res.status(400).json({ success: false, message: pwError });
    if (newPassword === currentPassword) {
      return res.status(400).json({ success: false, message: 'New password must be different from the current one' });
    }
    user.password = await bcrypt.hash(newPassword, 10);
    user.sessions = user.sessions.filter((x) => x.sid === req.auth.sid);
    user.trustedDevices = [];
    logEvent(user, req, 'password-changed', true);
    await user.save();
    res.json({ success: true, message: 'Password changed. Other sessions were signed out.' });
  }));

  // Switch to e-mail OTP or turn the second factor off (re-authenticates with the password).
  app.post('/auth/2fa/method', requireAuth, sensitiveLimiter, wrap(async (req, res) => {
    const { method } = req.body || {};
    if (!['email', 'none'].includes(method)) return res.status(400).json({ success: false, message: 'Unknown method' });
    if (!(await reauth(req, res))) return;
    const user = req.user;
    user.twoFactorMethod = method;
    user.totpSecret = undefined;
    user.pendingTotpSecret = undefined;
    user.lastTotpStep = undefined;
    user.backupCodes = [];
    user.trustedDevices = [];
    logEvent(user, req, '2fa-changed', true);
    await user.save();
    res.json({ success: true, security: securityOf(user) });
  }));

  app.post('/auth/2fa/totp/setup', requireAuth, sensitiveLimiter, wrap(async (req, res) => {
    if (!(await reauth(req, res))) return;
    const secret = generateSecret();
    req.user.pendingTotpSecret = secret;
    await req.user.save();
    res.json({ success: true, secret, otpauthUrl: otpauthUrl({ secret, email: req.user.email }) });
  }));

  app.post('/auth/2fa/totp/enable', requireAuth, sensitiveLimiter, wrap(async (req, res) => {
    const user = req.user;
    if (!user.pendingTotpSecret) return res.status(400).json({ success: false, message: 'Start the setup first' });
    const step = verifyTotp(user.pendingTotpSecret, req.body?.code);
    if (step === null) return res.status(400).json({ success: false, message: 'That code is not valid. Check the time on your device and try again.' });
    const codes = generateBackupCodes();
    user.totpSecret = user.pendingTotpSecret;
    user.pendingTotpSecret = undefined;
    user.lastTotpStep = step;
    user.twoFactorMethod = 'totp';
    user.backupCodes = codes.map(hashBackupCode);
    user.trustedDevices = [];
    logEvent(user, req, '2fa-changed', true);
    await user.save();
    res.json({ success: true, backupCodes: codes, security: securityOf(user) });
  }));

  app.post('/auth/backup-codes/regenerate', requireAuth, sensitiveLimiter, wrap(async (req, res) => {
    if (req.user.twoFactorMethod !== 'totp') {
      return res.status(400).json({ success: false, message: 'Backup codes need the authenticator app to be enabled' });
    }
    if (!(await reauth(req, res))) return;
    const codes = generateBackupCodes();
    req.user.backupCodes = codes.map(hashBackupCode);
    await req.user.save();
    res.json({ success: true, backupCodes: codes });
  }));

  app.delete('/auth/trusted-devices', requireAuth, wrap(async (req, res) => {
    await User.updateOne({ _id: req.user._id }, { $set: { trustedDevices: [] } });
    res.json({ success: true });
  }));

  // ---- Account recovery (e-mailed code, then a new password) ----

  app.post('/auth/recover/request', recoverLimiter, async (req, res) => {
    const { email } = req.body || {};
    if (!isStr(email)) return res.status(400).json({ success: false, message: 'Email is required' });
    const generic = { success: true, message: 'If an account exists for that address, a recovery code has been sent.' };
    try {
      const user = await User.findOne({ email: normEmail(email) });
      if (!user) return res.json(generic);
      if (user.recoverySentAt && Date.now() - user.recoverySentAt.getTime() < RESEND_COOLDOWN_MS) return res.json(generic);
      const code = randomize('0', 6);
      user.recoveryHash = await bcrypt.hash(code, 8);
      user.recoveryExpires = new Date(Date.now() + RECOVERY_TTL_MS);
      user.recoveryAttempts = 0;
      user.recoverySentAt = new Date();
      await user.save();
      try {
        await sendRecoveryEmail(user.email, code);
      } catch (mailError) {
        console.error('Error sending recovery email:', mailError.message);
        user.recoveryHash = undefined;
        user.recoverySentAt = undefined;
        await user.save();
      }
      return res.json(generic);
    } catch (error) {
      console.error('Error during recovery request:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred. Please try again later.' });
    }
  });

  app.post('/auth/recover/reset', verifyLimiter, async (req, res) => {
    const { email, code, newPassword } = req.body || {};
    try {
      if (!isStr(email) || !(isStr(code) || typeof code === 'number')) {
        return res.status(400).json({ success: false, message: 'Email and code are required' });
      }
      const pwError = validatePassword(newPassword);
      if (pwError) return res.status(400).json({ success: false, message: pwError });
      const user = await User.findOne({ email: normEmail(email) });
      const invalid = { success: false, message: 'Invalid or expired recovery code' };
      if (!user || !user.recoveryHash || !user.recoveryExpires || user.recoveryExpires.getTime() < Date.now()) {
        return res.status(400).json(invalid);
      }
      if (user.recoveryAttempts >= MAX_OTP_ATTEMPTS || !(await bcrypt.compare(String(code).trim(), user.recoveryHash))) {
        user.recoveryAttempts += 1;
        if (user.recoveryAttempts >= MAX_OTP_ATTEMPTS) user.recoveryHash = undefined;
        await user.save();
        return res.status(400).json(invalid);
      }
      user.password = await bcrypt.hash(newPassword, 10);
      user.recoveryHash = undefined;
      user.recoveryExpires = undefined;
      user.recoverySentAt = undefined;
      user.sessions = [];
      user.tokenVersion = (user.tokenVersion ?? 0) + 1;
      user.trustedDevices = [];
      user.failedLogins = 0;
      user.lockUntil = undefined;
      logEvent(user, req, 'recovery', true);
      await user.save();
      return res.json({ success: true, message: 'Password updated. You can sign in now.' });
    } catch (error) {
      console.error('Error during recovery reset:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred. Please try again later.' });
    }
  });

  return app;
}
