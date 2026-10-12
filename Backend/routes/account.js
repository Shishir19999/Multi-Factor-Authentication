// Signed-in account routes: security overview, activity, sessions, password, factors, passkeys, API tokens, alerts.
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import randomize from 'randomatic';
import User from '../models/User.js';
import { AuditEvent } from '../models/Other.js';
import { generateSecret, otpauthUrl, verifyTotp } from '../totp.js';
import { generateBackupCodes, hashBackupCode, consumeBackupCode } from '../backupCodes.js';
import { compliance, twoFactorRequired } from '../shared/policy.js';
import { EVENT_KEYS, eventCategory, eventLabel, toCsv, AUDIT_COLUMNS } from '../shared/audit.js';
import { TOKEN_PREFIX, MAX_TOKENS, validateTokenRequest } from '../shared/scopes.js';
import { bytesToB64u } from '../shared/b64u.js';
import { registrationOptions, verifyRegistration, authenticationOptions, verifyAuthentication } from '../lib/webauthn.js';
import { newChallenge, takeChallenge } from './auth.js';
import { isStr, sha, MAX_OTP_ATTEMPTS, RECOVERY_TTL_MS, maskEmail } from '../lib/context.js';

export const toActivity = (e) => ({
  id: String(e._id), at: e.at, event: e.event, label: eventLabel(e.event), ok: e.ok, severity: e.severity, ip: e.ip, userAgent: e.userAgent,
  device: e.device, geo: e.geo, byAdmin: !!e.actorId && e.actorId !== e.targetId,
});

export default function accountRoutes(app, ctx) {
  const { auth, limiter, wrap, audit, securityOf, vetPassword, applyPassword, markFresh, sendMail } = ctx;
  const sensitive = limiter('sensitive');
  const verifyLimit = limiter('verify');

  app.get('/auth/security', auth({ pending: true, scope: 'security:read' }), (req, res) => res.json({ success: true, security: securityOf(req.user, req.policy) }));

  // ---- Activity ----
  async function activityRows(user, { category, event, limit = 100 }) {
    const filter = { targetId: String(user._id) };
    if (event) filter.event = String(event);
    else if (category) filter.event = { $in: EVENT_KEYS.filter((k) => eventCategory(k) === category) };
    return AuditEvent.find(filter).sort({ at: -1 }).limit(Math.min(Number(limit) || 100, 500)).lean();
  }

  app.get('/auth/activity', auth({ scope: 'activity:read' }), wrap(async (req, res) => {
    const rows = await activityRows(req.user, req.query);
    res.json({ success: true, events: rows.map(toActivity) });
  }));

  app.get('/auth/activity/export', auth({ scope: 'activity:read', fresh: 'session' }), wrap(async (req, res) => {
    const rows = await activityRows(req.user, { limit: 500 });
    await audit(req, 'activity-exported', { actor: req.user, target: req.user });
    if (req.query.format === 'json') {
      res.set('Content-Disposition', 'attachment; filename="account-activity.json"');
      return res.json({ exportedAt: new Date().toISOString(), account: req.user.email, events: rows.map(toActivity) });
    }
    res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="account-activity.csv"' });
    return res.send(toCsv(rows.map((r) => ({ ...r, actorEmail: r.actorId && r.actorId !== r.targetId ? 'administrator' : r.actorEmail })), AUDIT_COLUMNS));
  }));

  // ---- Sessions ----
  app.get('/auth/sessions', auth({ scope: 'sessions:read' }), wrap(async (req, res) => {
    const before = req.user.sessions.length;
    ctx.pruneSessions(req.user, req.policy);
    if (req.user.sessions.length !== before) await req.user.save();
    const sessions = [...req.user.sessions].reverse().map((x) => ({
      id: x.sid, current: x.sid === req.auth.sid, ip: x.ip, userAgent: x.userAgent, device: x.device, geo: x.geo, name: x.name, via: x.via,
      createdAt: x.createdAt, lastSeen: x.lastSeen,
    }));
    res.json({ success: true, sessions });
  }));

  app.patch('/auth/sessions/:sid', auth(), wrap(async (req, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 40) : '';
    const r = await User.updateOne({ _id: req.user._id, 'sessions.sid': req.params.sid }, { $set: { 'sessions.$.name': name || undefined } });
    if (!r.matchedCount) return res.status(404).json({ success: false, message: 'Session not found' });
    return res.json({ success: true });
  }));

  app.delete('/auth/sessions/:sid', auth(), wrap(async (req, res) => {
    if (!req.user.sessions.some((x) => x.sid === req.params.sid)) return res.status(404).json({ success: false, message: 'Session not found' });
    await User.updateOne({ _id: req.user._id }, { $pull: { sessions: { sid: req.params.sid } } });
    await audit(req, 'session-revoked', { actor: req.user, target: req.user });
    return res.json({ success: true, current: req.params.sid === req.auth.sid });
  }));

  app.post('/auth/sessions/revoke-others', auth(), wrap(async (req, res) => {
    await User.updateOne({ _id: req.user._id }, { $pull: { sessions: { sid: { $ne: req.auth.sid } } } });
    await audit(req, 'sessions-revoked', { actor: req.user, target: req.user });
    res.json({ success: true });
  }));

  // "Sign out everywhere": also invalidates this device.
  app.post('/auth/sessions/revoke-all', auth(), wrap(async (req, res) => {
    await User.updateOne({ _id: req.user._id }, { $inc: { tokenVersion: 1 }, $set: { sessions: [] } });
    await audit(req, 'sessions-revoked', { actor: req.user, target: req.user, meta: { all: true } });
    ctx.clearSessionCookie(res);
    res.json({ success: true });
  }));

  // ---- Step-up re-authentication ----
  app.post('/auth/stepup', auth({ pending: true }), sensitive, wrap(async (req, res) => {
    const { password, code } = req.body || {};
    const user = req.user;
    let ok = false;
    if (isStr(password)) {
      ok = await bcrypt.compare(password, user.password);
    } else if (isStr(code) && user.twoFactorMethod === 'totp') {
      const c = code.trim();
      if (/^\d{6}$/.test(c.replace(/\s/g, ''))) {
        const step = verifyTotp(user.totpSecret, c);
        if (step !== null && step > (user.lastTotpStep ?? -1)) { user.lastTotpStep = step; ok = true; }
      } else {
        const rest = consumeBackupCode(user.backupCodes, c);
        if (rest) { user.backupCodes = rest; ok = true; }
      }
      if (ok) await user.save();
    }
    if (!ok) {
      await audit(req, 'step-up-failed', { actor: user, target: user, ok: false });
      return res.status(403).json({ success: false, message: isStr(password) ? 'Password is incorrect' : 'That code is not valid' });
    }
    await markFresh(user, req.auth.sid, req.policy);
    await audit(req, 'step-up', { actor: user, target: user });
    return res.json({ success: true, validForSeconds: req.policy.session.stepUpMinutes * 60 });
  }));

  // ---- Password ----
  app.post('/auth/change-password', auth({ pending: true }), sensitive, wrap(async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    const user = req.user;
    if (!isStr(currentPassword) || !(await bcrypt.compare(currentPassword, user.password))) {
      await audit(req, 'step-up-failed', { actor: user, target: user, ok: false });
      return res.status(403).json({ success: false, message: 'Current password is incorrect' });
    }
    if (newPassword === currentPassword) return res.status(400).json({ success: false, message: 'New password must be different from the current one' });
    const vet = await vetPassword(newPassword, { email: user.email, hashes: user.passwordHistory }, req.policy);
    if (vet.error) return res.status(400).json({ success: false, message: vet.error });
    await applyPassword(user, newPassword, req.policy, vet.breach);
    user.sessions = user.sessions.filter((x) => x.sid === req.auth.sid);
    user.trustedDevices = [];
    await user.save();
    await audit(req, 'password-changed', { actor: user, target: user });
    res.json({
      success: true, message: 'Password changed. Other sessions were signed out.',
      ...(vet.breach?.status === 'pwned' ? { warning: `This password appears in ${vet.breach.count.toLocaleString('en-US')} known data breaches. Consider choosing another.` } : {}),
    });
  }));

  // ---- Code factors ----
  // Switch to e-mail codes or turn the code factor off.
  app.post('/auth/2fa/method', auth({ pending: true, fresh: true }), sensitive, wrap(async (req, res) => {
    const { method } = req.body || {};
    const user = req.user;
    if (!['email', 'none'].includes(method)) return res.status(400).json({ success: false, message: 'Unknown method' });
    if (method === 'email' && !req.policy.twoFactor.methods.includes('email')) return res.status(400).json({ success: false, message: 'E-mail codes are not allowed by the security policy' });
    if (method === 'none' && (twoFactorRequired(user, req.policy) || user.mustEnrollTwoFactor) && user.passkeys.length === 0) {
      return res.status(400).json({ success: false, message: 'Two-step verification is required for your account and cannot be turned off.' });
    }
    user.twoFactorMethod = method;
    user.totpSecret = undefined;
    user.pendingTotpSecret = undefined;
    user.lastTotpStep = undefined;
    user.backupCodes = [];
    user.trustedDevices = [];
    if (method !== 'none') user.mustEnrollTwoFactor = false;
    await user.save();
    await audit(req, '2fa-changed', { actor: user, target: user, meta: { method } });
    res.json({ success: true, security: securityOf(user, req.policy) });
  }));

  app.post('/auth/2fa/totp/setup', auth({ pending: true, fresh: true }), sensitive, wrap(async (req, res) => {
    if (!req.policy.twoFactor.methods.includes('totp')) return res.status(400).json({ success: false, message: 'Authenticator apps are not allowed by the security policy' });
    const secret = generateSecret();
    req.user.pendingTotpSecret = secret;
    await req.user.save();
    res.json({ success: true, secret, otpauthUrl: otpauthUrl({ secret, email: req.user.email }) });
  }));

  app.post('/auth/2fa/totp/enable', auth({ pending: true }), sensitive, wrap(async (req, res) => {
    const user = req.user;
    if (!user.pendingTotpSecret) return res.status(400).json({ success: false, message: 'Start the setup first' });
    const step = verifyTotp(user.pendingTotpSecret, req.body?.code);
    if (step === null) return res.status(400).json({ success: false, message: 'That code is not valid. Check the time on your device and try again.' });
    const codes = generateBackupCodes();
    user.totpSecret = user.pendingTotpSecret;
    user.pendingTotpSecret = undefined;
    user.lastTotpStep = step;
    user.twoFactorMethod = 'totp';
    user.mustEnrollTwoFactor = false;
    user.backupCodes = codes.map(hashBackupCode);
    user.trustedDevices = [];
    await user.save();
    await audit(req, '2fa-changed', { actor: user, target: user, meta: { method: 'totp' } });
    res.json({ success: true, backupCodes: codes, security: securityOf(user, req.policy) });
  }));

  app.post('/auth/backup-codes/regenerate', auth({ fresh: true }), sensitive, wrap(async (req, res) => {
    if (req.user.twoFactorMethod !== 'totp') return res.status(400).json({ success: false, message: 'Backup codes need the authenticator app to be enabled' });
    const codes = generateBackupCodes();
    req.user.backupCodes = codes.map(hashBackupCode);
    await req.user.save();
    await audit(req, 'backup-codes-regenerated', { actor: req.user, target: req.user });
    res.json({ success: true, backupCodes: codes });
  }));

  app.delete('/auth/trusted-devices', auth({ fresh: true }), wrap(async (req, res) => {
    await User.updateOne({ _id: req.user._id }, { $set: { trustedDevices: [] } });
    await audit(req, 'trusted-devices-cleared', { actor: req.user, target: req.user });
    res.json({ success: true });
  }));

  // ---- Passkeys ----
  const passkeyView = (p) => ({
    id: p.credentialId, name: p.name, deviceType: p.deviceType, backedUp: !!p.backedUp, transports: p.transports, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt,
  });

  app.get('/auth/passkeys', auth({ pending: true }), (req, res) => res.json({ success: true, passkeys: req.user.passkeys.map(passkeyView) }));

  app.post('/auth/passkeys/register/options', auth({ pending: true, fresh: true }), sensitive, wrap(async (req, res) => {
    const user = req.user;
    if (user.passkeys.length >= 10) return res.status(400).json({ success: false, message: 'You can register up to 10 passkeys.' });
    if (!user.webauthnUserId) {
      user.webauthnUserId = bytesToB64u(crypto.randomBytes(32));
      await user.save();
    }
    const options = await registrationOptions(ctx.wa, user);
    const challengeId = await newChallenge(options, 'register', user._id);
    res.json({ success: true, challengeId, options });
  }));

  app.post('/auth/passkeys/register/verify', auth({ pending: true }), sensitive, wrap(async (req, res) => {
    const { challengeId, response, name } = req.body || {};
    const user = req.user;
    const c = await takeChallenge(challengeId, 'register');
    if (!c || c.userId !== String(user._id) || !response) return res.status(400).json({ success: false, message: 'The passkey request expired. Try again.' });
    let v;
    try {
      v = await verifyRegistration(ctx.wa, response, c.challenge);
    } catch (error) {
      console.error('Passkey registration error:', error.message);
      return res.status(400).json({ success: false, message: 'That passkey could not be verified.' });
    }
    if (!v.verified) return res.status(400).json({ success: false, message: 'That passkey could not be verified.' });
    const cred = v.registrationInfo.credential;
    if (user.passkeys.some((p) => p.credentialId === cred.id) || await User.exists({ 'passkeys.credentialId': cred.id })) {
      return res.status(400).json({ success: false, message: 'That passkey is already registered.' });
    }
    user.passkeys.push({
      credentialId: cred.id, publicKey: bytesToB64u(cred.publicKey), counter: cred.counter, transports: cred.transports || response.response?.transports || [],
      name: (typeof name === 'string' && name.trim().slice(0, 40)) || `Passkey ${user.passkeys.length + 1}`,
      deviceType: v.registrationInfo.credentialDeviceType, backedUp: v.registrationInfo.credentialBackedUp, createdAt: new Date(),
    });
    user.mustEnrollTwoFactor = false;
    await user.save();
    await audit(req, 'passkey-added', { actor: user, target: user });
    res.json({ success: true, passkeys: user.passkeys.map(passkeyView) });
  }));

  app.patch('/auth/passkeys/:id', auth({ pending: true }), wrap(async (req, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 40) : '';
    if (!name) return res.status(400).json({ success: false, message: 'Enter a name.' });
    const r = await User.updateOne({ _id: req.user._id, 'passkeys.credentialId': req.params.id }, { $set: { 'passkeys.$.name': name } });
    if (!r.matchedCount) return res.status(404).json({ success: false, message: 'Passkey not found' });
    res.json({ success: true });
  }));

  app.delete('/auth/passkeys/:id', auth({ pending: true, fresh: true }), sensitive, wrap(async (req, res) => {
    const user = req.user;
    if (!user.passkeys.some((p) => p.credentialId === req.params.id)) return res.status(404).json({ success: false, message: 'Passkey not found' });
    const after = compliance({ ...ctx.facts(user), passkeyCount: user.passkeys.length - 1 }, req.policy);
    if (after.some((r) => r.id === 'enroll-2fa')) {
      return res.status(400).json({ success: false, message: 'This is your last second step and two-step verification is required. Add another method first.' });
    }
    user.passkeys = user.passkeys.filter((p) => p.credentialId !== req.params.id);
    await user.save();
    await audit(req, 'passkey-removed', { actor: user, target: user });
    res.json({ success: true, passkeys: user.passkeys.map(passkeyView) });
  }));

  // Step-up with a passkey
  app.post('/auth/passkeys/stepup/options', auth({ pending: true }), sensitive, wrap(async (req, res) => {
    if (!req.user.passkeys.length) return res.status(400).json({ success: false, message: 'No passkey registered' });
    const options = await authenticationOptions(ctx.wa, req.user.passkeys);
    res.json({ success: true, challengeId: await newChallenge(options, 'stepup', req.user._id), options });
  }));

  app.post('/auth/passkeys/stepup/verify', auth({ pending: true }), verifyLimit, wrap(async (req, res) => {
    const { challengeId, response } = req.body || {};
    const user = req.user;
    const c = await takeChallenge(challengeId, 'stepup');
    const pk = user.passkeys.find((p) => p.credentialId === response?.id);
    const fail = async () => {
      await audit(req, 'step-up-failed', { actor: user, target: user, ok: false });
      return res.status(403).json({ success: false, message: 'Passkey could not be verified' });
    };
    if (!c || c.userId !== String(user._id) || !pk) return fail();
    try {
      const v = await verifyAuthentication(ctx.wa, response, c.challenge, pk);
      if (!v.verified) return fail();
      await User.updateOne({ _id: user._id, 'passkeys.credentialId': pk.credentialId }, { $set: { 'passkeys.$.counter': v.authenticationInfo.newCounter, 'passkeys.$.lastUsedAt': new Date() } });
    } catch {
      return fail();
    }
    await markFresh(user, req.auth.sid, req.policy);
    await audit(req, 'step-up', { actor: user, target: user, meta: { via: 'passkey' } });
    return res.json({ success: true, validForSeconds: req.policy.session.stepUpMinutes * 60 });
  }));

  // ---- Personal API tokens (hashed at rest, scoped, revocable) ----
  const tokenView = (t) => ({ id: t.id, name: t.name, prefix: t.prefix, scopes: t.scopes, createdAt: t.createdAt, lastUsedAt: t.lastUsedAt, expiresAt: t.expiresAt });

  app.get('/auth/tokens', auth(), (req, res) => res.json({ success: true, tokens: req.user.apiTokens.map(tokenView) }));

  app.post('/auth/tokens', auth({ fresh: true }), sensitive, wrap(async (req, res) => {
    const parsed = validateTokenRequest(req.body || {});
    if (parsed.error) return res.status(400).json({ success: false, message: parsed.error });
    if (req.user.apiTokens.length >= MAX_TOKENS) return res.status(400).json({ success: false, message: `You can have up to ${MAX_TOKENS} tokens. Revoke one first.` });
    const token = `${TOKEN_PREFIX}${crypto.randomBytes(24).toString('base64url')}`;
    const { name, scopes, expiresInDays } = parsed.value;
    const record = {
      id: crypto.randomBytes(6).toString('hex'), name, prefix: token.slice(0, TOKEN_PREFIX.length + 6), hash: sha(token), scopes,
      createdAt: new Date(), expiresAt: expiresInDays ? new Date(Date.now() + expiresInDays * 86400000) : undefined,
    };
    req.user.apiTokens.push(record);
    await req.user.save();
    await audit(req, 'api-token-created', { actor: req.user, target: req.user, meta: { name, scopes } });
    res.json({ success: true, token, tokenInfo: tokenView(record) });
  }));

  app.delete('/auth/tokens/:id', auth({ fresh: true }), wrap(async (req, res) => {
    if (!req.user.apiTokens.some((t) => t.id === req.params.id)) return res.status(404).json({ success: false, message: 'Token not found' });
    await User.updateOne({ _id: req.user._id }, { $pull: { apiTokens: { id: req.params.id } } });
    await audit(req, 'api-token-revoked', { actor: req.user, target: req.user });
    res.json({ success: true });
  }));

  // ---- "Was this you?" alerts ----
  const alertView = (a) => ({ id: a.id, at: a.at, device: a.device, geo: a.geo, ip: a.ip, reasons: a.reasons, level: a.level, status: a.status });
  app.get('/auth/alerts', auth({ pending: true }), (req, res) => res.json({ success: true, alerts: [...req.user.alerts].reverse().map(alertView) }));

  app.post('/auth/alerts/:id/respond', auth({ pending: true }), wrap(async (req, res) => {
    const alert = req.user.alerts.find((a) => a.id === req.params.id);
    if (!alert) return res.status(404).json({ success: false, message: 'Alert not found' });
    if (!['yes', 'no'].includes(req.body?.answer)) return res.status(400).json({ success: false, message: 'Answer yes or no' });
    if (alert.status !== 'pending') return res.json({ success: true, status: alert.status });
    await ctx.resolveAlert(req, req.user, alert, req.body.answer);
    if (req.body.answer === 'no') ctx.clearSessionCookie(res);
    res.json({ success: true, status: alert.status, signedOut: req.body.answer === 'no' });
  }));

  // ---- Recovery e-mail ----
  app.post('/auth/recovery-email', auth({ fresh: true }), sensitive, wrap(async (req, res) => {
    const raw = req.body?.email;
    if (typeof raw !== 'string' || !/^\S+@\S+\.\S+$/.test(raw.trim())) return res.status(400).json({ success: false, message: 'Enter a valid e-mail address.' });
    const email = raw.trim().toLowerCase();
    if (email === req.user.email) return res.status(400).json({ success: false, message: 'Use an address different from your sign-in e-mail.' });
    const code = randomize('0', 6);
    req.user.recoveryEmailPending = email;
    req.user.recoveryEmailHash = await bcrypt.hash(code, 8);
    req.user.recoveryEmailExpires = new Date(Date.now() + RECOVERY_TTL_MS);
    req.user.recoveryEmailAttempts = 0;
    await req.user.save();
    if (!(await sendMail('verify-recovery-email', { to: email, code }))) return res.status(500).json({ success: false, message: 'Could not send the confirmation e-mail.' });
    res.json({ success: true, message: `We sent a confirmation code to ${maskEmail(email)}.` });
  }));

  app.post('/auth/recovery-email/verify', auth(), verifyLimit, wrap(async (req, res) => {
    const u = req.user;
    const code = String(req.body?.code ?? '').trim();
    if (!u.recoveryEmailPending || !u.recoveryEmailHash || !u.recoveryEmailExpires || u.recoveryEmailExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'Invalid or expired code' });
    }
    if (u.recoveryEmailAttempts >= MAX_OTP_ATTEMPTS || !(await bcrypt.compare(code, u.recoveryEmailHash))) {
      u.recoveryEmailAttempts += 1;
      if (u.recoveryEmailAttempts >= MAX_OTP_ATTEMPTS) u.recoveryEmailHash = undefined;
      await u.save();
      return res.status(400).json({ success: false, message: 'Invalid or expired code' });
    }
    u.recoveryEmail = u.recoveryEmailPending;
    u.recoveryEmailVerified = true;
    u.recoveryEmailPending = undefined;
    u.recoveryEmailHash = undefined;
    u.recoveryEmailExpires = undefined;
    await u.save();
    await audit(req, 'recovery-email-set', { actor: u, target: u });
    res.json({ success: true, security: securityOf(u, req.policy) });
  }));

  app.delete('/auth/recovery-email', auth({ fresh: true }), wrap(async (req, res) => {
    const u = req.user;
    u.recoveryEmail = undefined; u.recoveryEmailVerified = false; u.recoveryEmailPending = undefined; u.recoveryEmailHash = undefined;
    await u.save();
    await audit(req, 'recovery-email-removed', { actor: u, target: u });
    res.json({ success: true, security: securityOf(u, req.policy) });
  }));
}
