// Public sign-in side of the API: register, login (password, e-mail/TOTP code, passkeys), recovery, alert replies.
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import randomize from 'randomatic';
import User from '../models/User.js';
import { Challenge } from '../models/Other.js';
import { lockStatus, registerFailure, registerSuccess } from '../shared/lockout.js';
import { verifyTotp } from '../totp.js';
import { consumeBackupCode } from '../backupCodes.js';
import { authenticationOptions, verifyAuthentication } from './../lib/webauthn.js';
import {
  isStr, normEmail, sha, OTP_TTL_MS, MAX_OTP_ATTEMPTS, RESEND_COOLDOWN_MS, RECOVERY_TTL_MS, COOKIE_NAME,
} from '../lib/context.js';

const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 8);
const lockState = (u) => ({
  failedLogins: u.failedLogins || 0, lockCount: u.lockCount || 0, lockUntil: u.lockUntil?.getTime() || 0, lastFailureAt: u.lastFailureAt?.getTime() || 0,
});
const applyLock = (u, s) => {
  u.failedLogins = s.failedLogins;
  u.lockCount = s.lockCount;
  u.lockUntil = s.lockUntil ? new Date(s.lockUntil) : undefined;
  u.lastFailureAt = s.lastFailureAt ? new Date(s.lastFailureAt) : undefined;
};

export async function newChallenge(options, purpose, userId) {
  const id = crypto.randomBytes(16).toString('hex');
  await Challenge.create({ id, challenge: options.challenge, purpose, userId: userId ? String(userId) : undefined, expires: new Date(Date.now() + 5 * 60000) });
  return id;
}

export async function takeChallenge(id, purpose) {
  if (!isStr(id)) return null;
  const c = await Challenge.findOneAndDelete({ id, purpose });
  return c && c.expires > new Date() ? c : null;
}

export default function authRoutes(app, ctx) {
  const { auth, limiter, wrap, getPolicy, audit, finishLogin, sendMail, vetPassword, applyPassword, publicUser } = ctx;
  const L = { login: limiter('login'), verify: limiter('verify'), resend: limiter('resend'), recover: limiter('recover'), pub: limiter('public') };

  function clearOtp(user) {
    user.otpHash = undefined;
    user.otpExpires = undefined;
    user.otpAttempts = 0;
  }

  async function issueOtp(user) {
    const otp = randomize('0', 6);
    user.otpHash = await bcrypt.hash(otp, 8);
    user.otpExpires = new Date(Date.now() + OTP_TTL_MS);
    user.otpAttempts = 0;
    user.otpSentAt = new Date();
    await user.save();
    if (!(await sendMail('otp', { to: user.email, code: otp }))) {
      clearOtp(user);
      user.otpSentAt = undefined;
      await user.save();
      return false;
    }
    return true;
  }

  // Public policy (nothing secret): lets the forms show the real password rules.
  app.get('/auth/policy', wrap(async (req, res) => res.json({ success: true, policy: await getPolicy() })));

  app.post('/auth/register', L.pub, wrap(async (req, res) => {
    const { email: rawEmail, password } = req.body || {};
    if (typeof rawEmail !== 'string' || !/^\S+@\S+\.\S+$/.test(rawEmail.trim())) {
      return res.status(400).json({ success: false, message: 'A valid email is required' });
    }
    const email = normEmail(rawEmail);
    const policy = await getPolicy();
    const vet = await vetPassword(password, { email }, policy);
    if (vet.error) return res.status(400).json({ success: false, message: vet.error });
    if (await User.findOne({ email })) return res.status(400).json({ success: false, message: 'Email already exists' });
    const user = await new User({
      email, password: await bcrypt.hash(password, 10), passwordChangedAt: new Date(),
      breachStatus: vet.breach?.status === 'pwned' ? 'pwned' : vet.breach?.status === 'safe' ? 'clean' : 'unknown',
      breachCheckedAt: vet.breach && vet.breach.status !== 'unavailable' ? new Date() : undefined,
      twoFactorMethod: policy.twoFactor.methods.includes('email') ? 'email' : 'none',
    }).save();
    await audit(req, 'register', { actor: user, target: user });
    return res.json({
      success: true, message: 'User registered successfully', redirectTo: '/login',
      ...(vet.breach?.status === 'pwned' ? { warning: `This password appears in ${vet.breach.count.toLocaleString('en-US')} known data breaches. Consider changing it.` } : {}),
    });
  }));

  // Step 1: password. Then a second factor unless disabled or the device is trusted.
  app.post('/auth/login', L.login, wrap(async (req, res) => {
    const { email, password, deviceToken } = req.body || {};
    if (!isStr(email) || !isStr(password)) return res.status(400).json({ success: false, message: 'Email and password are required' });
    const policy = await getPolicy();
    const user = await User.findOne({ email: normEmail(email) });
    if (!user) {
      await bcrypt.compare(password, DUMMY_HASH); // keep timing similar
      await audit(req, 'login-failed', { ok: false, meta: { email: normEmail(email).slice(0, 120) } });
      return res.json({ success: false, message: 'Invalid credentials' });
    }

    const lock = lockStatus(lockState(user));
    if (lock.locked) {
      res.set('Retry-After', String(lock.retryAfterSeconds));
      return res.status(423).json({
        success: false, locked: true, retryAfterSeconds: lock.retryAfterSeconds,
        message: `Account temporarily locked after too many failed attempts. Try again in ${Math.ceil(lock.retryAfterSeconds / 60)} minute(s) or reset your password.`,
      });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      const r = registerFailure(lockState(user), policy);
      applyLock(user, r.state);
      await user.save();
      await audit(req, 'login-failed', { actor: user, target: user, ok: false });
      if (r.locked) await audit(req, 'account-locked', { actor: user, target: user, ok: false, meta: { minutes: Math.round(r.lockMs / 60000) } });
      return res.json({
        success: false,
        message: r.locked ? `Too many failed attempts. The account is locked for ${Math.round(r.lockMs / 60000)} minutes.` : 'Invalid credentials',
        ...(r.locked ? { locked: true, retryAfterSeconds: Math.round(r.lockMs / 1000) } : {}),
        ...(!r.locked && r.attemptsLeft <= 2 ? { attemptsLeft: r.attemptsLeft } : {}),
      });
    }

    if (user.adminLocked) {
      await audit(req, 'login-failed', { actor: user, target: user, ok: false, meta: { reason: 'admin-locked' } });
      return res.status(423).json({
        success: false, locked: true, adminLocked: true,
        message: 'This account has been locked by an administrator. Use "Ask an administrator for help" on the recovery page.',
      });
    }
    applyLock(user, registerSuccess());

    // Password hygiene at the only moment we hold the plaintext: breach lookup (cached for a day).
    if (policy.breachCheck !== 'off' && (!user.breachCheckedAt || Date.now() - user.breachCheckedAt.getTime() > 86400000)) {
      const r = await ctx.breachLookup(password);
      if (r.status !== 'unavailable') {
        user.breachStatus = r.status === 'pwned' ? 'pwned' : 'clean';
        user.breachCheckedAt = new Date();
        if (r.status === 'pwned' && policy.breachCheck === 'block') user.mustChangePassword = true;
      }
    }

    const method = user.twoFactorMethod || 'email';
    if (method === 'none') return res.json({ ...(await finishLogin(req, res, user, { method })), method });
    if (isStr(deviceToken)) {
      const h = sha(deviceToken);
      if (user.trustedDevices.some((d) => d.hash === h && d.expires > new Date())) {
        return res.json({ ...(await finishLogin(req, res, user, { method, via: 'trusted' })), method: 'trusted' });
      }
    }
    const passkeys = user.passkeys.length > 0;
    if (method === 'totp') {
      clearOtp(user);
      user.otpExpires = new Date(Date.now() + OTP_TTL_MS);
      user.otpSentAt = new Date();
      await user.save();
      return res.json({ success: true, method: 'totp', passkeys });
    }
    if (!(await issueOtp(user))) return res.status(500).json({ success: false, message: 'Could not send the OTP email. Please try again later.' });
    return res.json({ success: true, method: 'email', passkeys, resendCooldownSeconds: RESEND_COOLDOWN_MS / 1000 });
  }));

  app.post('/auth/resend-otp', L.resend, wrap(async (req, res) => {
    const { email } = req.body || {};
    if (!isStr(email)) return res.status(400).json({ success: false, message: 'Email is required' });
    const user = await User.findOne({ email: normEmail(email) });
    if (!user || !user.otpSentAt || !user.otpHash) return res.status(400).json({ success: false, message: 'Please log in again' });
    const waitMs = user.otpSentAt.getTime() + RESEND_COOLDOWN_MS - Date.now();
    if (waitMs > 0) {
      const retryAfterSeconds = Math.ceil(waitMs / 1000);
      res.set('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({ success: false, message: `Please wait ${retryAfterSeconds}s before requesting a new code`, retryAfterSeconds });
    }
    if (!(await issueOtp(user))) return res.status(500).json({ success: false, message: 'Could not send the OTP email. Please try again later.' });
    return res.json({ success: true, resendCooldownSeconds: RESEND_COOLDOWN_MS / 1000 });
  }));

  // Step 2: e-mailed OTP, authenticator code or a backup code.
  app.post('/auth/verify-otp', L.verify, wrap(async (req, res) => {
    const { email, otp, trust } = req.body || {};
    if (!isStr(email) || !(isStr(otp) || typeof otp === 'number')) return res.status(400).json({ success: false, message: 'Email and OTP are required' });
    const user = await User.findOne({ email: normEmail(email) });
    const method = user?.twoFactorMethod || 'email';
    const pending = user && user.otpExpires && user.otpExpires.getTime() >= Date.now() && (method === 'totp' || user.otpHash);
    if (!pending) return res.json({ success: false, message: 'Invalid or expired OTP' });
    if (user.adminLocked) return res.status(423).json({ success: false, locked: true, adminLocked: true, message: 'This account has been locked by an administrator.' });
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
      const remaining = MAX_OTP_ATTEMPTS - user.otpAttempts;
      if (remaining <= 0) clearOtp(user);
      await user.save();
      await audit(req, 'code-failed', { actor: user, target: user, ok: false });
      return res.json({ success: false, message: remaining > 0 ? `Invalid OTP. ${remaining} attempt(s) left.` : 'Too many attempts. Please log in again.' });
    }
    clearOtp(user);
    user.otpSentAt = undefined;
    return res.json(await finishLogin(req, res, user, { trust: trust === true, method }));
  }));

  // ---- Passkeys: sign in, or use as the second step after the password ----
  app.post('/auth/passkeys/options', L.verify, wrap(async (req, res) => {
    const { purpose, email } = req.body || {};
    if (!['login', 'mfa'].includes(purpose)) return res.status(400).json({ success: false, message: 'Unknown purpose' });
    let user = null;
    if (isStr(email)) user = await User.findOne({ email: normEmail(email) });
    if (purpose === 'mfa' && !(user && user.otpExpires && user.otpExpires.getTime() >= Date.now() && user.passkeys.length)) {
      return res.status(400).json({ success: false, message: 'Please sign in with your password first' });
    }
    // Without an e-mail the browser offers any discoverable passkey for this site (usernameless sign-in).
    const options = await authenticationOptions(ctx.wa, purpose === 'mfa' || (user && isStr(email)) ? user?.passkeys || [] : []);
    const challengeId = await newChallenge(options, purpose, purpose === 'mfa' ? user._id : undefined);
    return res.json({ success: true, challengeId, options });
  }));

  app.post('/auth/passkeys/verify', L.verify, wrap(async (req, res) => {
    const { purpose, challengeId, response, email, trust } = req.body || {};
    if (!['login', 'mfa'].includes(purpose) || !response?.id) return res.status(400).json({ success: false, message: 'Invalid request' });
    const c = await takeChallenge(challengeId, purpose);
    if (!c) return res.status(400).json({ success: false, message: 'The passkey request expired. Try again.' });
    const fail = async (user, message = 'Passkey sign-in failed') => {
      await audit(req, 'passkey-failed', { actor: user || undefined, target: user || undefined, ok: false });
      return res.status(400).json({ success: false, message });
    };
    const user = purpose === 'mfa'
      ? await User.findOne({ _id: c.userId, email: isStr(email) ? normEmail(email) : '' })
      : await User.findOne({ 'passkeys.credentialId': response.id });
    const pk = user?.passkeys.find((p) => p.credentialId === response.id);
    if (!user || !pk) return fail(null, 'That passkey is not registered for this site.');
    if (user.adminLocked) return res.status(423).json({ success: false, locked: true, adminLocked: true, message: 'This account has been locked by an administrator.' });
    let verified;
    try {
      verified = await verifyAuthentication(ctx.wa, response, c.challenge, pk);
    } catch (error) {
      console.error('Passkey verification error:', error.message);
      return fail(user);
    }
    if (!verified.verified) return fail(user);
    pk.counter = verified.authenticationInfo.newCounter;
    pk.lastUsedAt = new Date();
    pk.backedUp = verified.authenticationInfo.credentialBackedUp;
    if (purpose === 'mfa') { clearOtp(user); user.otpSentAt = undefined; }
    const out = await finishLogin(req, res, user, { trust: purpose === 'mfa' && trust === true, method: user.twoFactorMethod || 'email', via: 'passkey' });
    return res.json(out);
  }));

  // ---- Account recovery (e-mailed code, then a new password) ----
  app.post('/auth/recover/request', L.recover, wrap(async (req, res) => {
    const { email } = req.body || {};
    if (!isStr(email)) return res.status(400).json({ success: false, message: 'Email is required' });
    const generic = { success: true, message: 'If an account exists for that address, a recovery code has been sent.' };
    const user = await User.findOne({ email: normEmail(email) });
    if (!user) return res.json(generic);
    if (user.recoverySentAt && Date.now() - user.recoverySentAt.getTime() < RESEND_COOLDOWN_MS) return res.json(generic);
    const code = randomize('0', 6);
    user.recoveryHash = await bcrypt.hash(code, 8);
    user.recoveryExpires = new Date(Date.now() + RECOVERY_TTL_MS);
    user.recoveryAttempts = 0;
    user.recoverySentAt = new Date();
    await user.save();
    await audit(req, 'recovery-requested', { actor: user, target: user });
    const sent = await sendMail('recovery', { to: user.email, code });
    if (user.recoveryEmailVerified && user.recoveryEmail) await sendMail('recovery', { to: user.recoveryEmail, code });
    if (!sent) {
      user.recoveryHash = undefined;
      user.recoverySentAt = undefined;
      await user.save();
    }
    return res.json(generic);
  }));

  app.post('/auth/recover/reset', L.verify, wrap(async (req, res) => {
    const { email, code, newPassword } = req.body || {};
    if (!isStr(email) || !(isStr(code) || typeof code === 'number')) return res.status(400).json({ success: false, message: 'Email and code are required' });
    const policy = await getPolicy();
    const user = await User.findOne({ email: normEmail(email) });
    const pwCheck = await vetPassword(newPassword, { email: normEmail(email), hashes: user ? [user.password, ...user.passwordHistory] : [] }, policy);
    if (pwCheck.error) return res.status(400).json({ success: false, message: pwCheck.error });
    const invalid = { success: false, message: 'Invalid or expired recovery code' };
    if (!user || !user.recoveryHash || !user.recoveryExpires || user.recoveryExpires.getTime() < Date.now()) return res.status(400).json(invalid);
    if (user.recoveryAttempts >= MAX_OTP_ATTEMPTS || !(await bcrypt.compare(String(code).trim(), user.recoveryHash))) {
      user.recoveryAttempts += 1;
      if (user.recoveryAttempts >= MAX_OTP_ATTEMPTS) user.recoveryHash = undefined;
      await user.save();
      return res.status(400).json(invalid);
    }
    await applyPassword(user, newPassword, policy, pwCheck.breach);
    user.recoveryHash = undefined;
    user.recoveryExpires = undefined;
    user.recoverySentAt = undefined;
    user.assistRequestedAt = undefined;
    user.sessions = [];
    user.tokenVersion = (user.tokenVersion ?? 0) + 1;
    user.trustedDevices = [];
    applyLock(user, registerSuccess());
    await user.save();
    await audit(req, 'recovery', { actor: user, target: user });
    return res.json({ success: true, message: 'Password updated. You can sign in now.' });
  }));

  // Admin-assisted recovery: leaves a help request for administrators (generic answer, no account enumeration).
  app.post('/auth/recover/assist', L.pub, wrap(async (req, res) => {
    const { email, message } = req.body || {};
    if (!isStr(email)) return res.status(400).json({ success: false, message: 'Email is required' });
    const user = await User.findOne({ email: normEmail(email) });
    if (user && !user.assistRequestedAt) {
      user.assistRequestedAt = new Date();
      user.assistMessage = typeof message === 'string' ? message.trim().slice(0, 300) : undefined;
      await user.save();
      await audit(req, 'help-requested', { actor: user, target: user });
    }
    return res.json({ success: true, message: 'If an account exists for that address, an administrator has been asked to contact you.' });
  }));

  // ---- Answer a "was this you?" alert from the e-mail link (no sign-in needed) ----
  app.post('/auth/alerts/respond', L.pub, wrap(async (req, res) => {
    const { t, answer } = req.body || {};
    if (!isStr(t) || !['yes', 'no'].includes(answer)) return res.status(400).json({ success: false, message: 'Invalid request' });
    const [userId, alertId, secret] = t.split('.');
    let user = null;
    try { user = await User.findById(userId); } catch { /* malformed id */ }
    const alert = user?.alerts.find((a) => a.id === alertId);
    if (!alert || !secret || alert.tokenHash !== sha(secret)) return res.status(400).json({ success: false, message: 'This link is not valid any more.' });
    if (alert.status !== 'pending') return res.json({ success: true, status: alert.status, message: 'You already answered this alert.' });
    await ctx.resolveAlert(req, user, alert, answer);
    return res.json({ success: true, status: alert.status });
  }));

  // ---- Session basics ----
  app.get('/auth/me', auth({ pending: true, scope: 'profile:read' }), wrap(async (req, res) => {
    res.json({ success: true, user: publicUser(req.user, req.policy), ...(req.csrfToken ? { csrfToken: req.csrfToken } : {}) });
  }));

  app.post('/auth/logout', auth({ pending: true }), wrap(async (req, res) => {
    await User.updateOne({ _id: req.user._id }, { $pull: { sessions: { sid: req.auth.sid } } });
    await audit(req, 'logout', { actor: req.user, target: req.user });
    res.clearCookie(COOKIE_NAME, { ...ctx.cookieOptions(req.policy), maxAge: undefined });
    return res.json({ success: true, message: 'Logged out' });
  }));
}
