// Administrator console API: stats, users, per-user actions, audit log (+CSV), security policy, test mail.
import randomize from 'randomatic';
import bcrypt from 'bcrypt';
import User from '../models/User.js';
import { AuditEvent } from '../models/Other.js';
import { normalizePolicy, policyDiff } from '../shared/policy.js';
import { toCsv, AUDIT_COLUMNS, EVENT_KEYS, eventCategory, eventLabel } from '../shared/audit.js';
import { isStr, maskEmail, RECOVERY_TTL_MS } from '../lib/context.js';

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const ACTIONS = ['lock', 'unlock', 'force-reset', 'force-enroll', 'reset-2fa', 'revoke-sessions', 'role', 'issue-recovery', 'clear-assist'];

export default function adminRoutes(app, ctx) {
  const { auth, limiter, wrap, audit, getPolicy, savePolicy, sendMail, env } = ctx;
  const sensitive = limiter('sensitive');
  const read = auth({ admin: true });
  const write = auth({ admin: true, fresh: true });

  const status = (u) => (u.adminLocked ? 'admin-locked' : u.lockUntil && u.lockUntil.getTime() > Date.now() ? 'locked' : 'active');
  const row = (u) => ({
    id: String(u._id), email: u.email, role: u.role || 'user', twoFactorMethod: u.twoFactorMethod || 'email', passkeys: (u.passkeys || []).length,
    status: status(u), adminLockReason: u.adminLockReason, mustChangePassword: !!u.mustChangePassword, mustEnrollTwoFactor: !!u.mustEnrollTwoFactor,
    assistRequestedAt: u.assistRequestedAt, assistMessage: u.assistMessage, lastLoginAt: u.lastLoginAt, createdAt: u.createdAt,
    sessions: (u.sessions || []).length, breachStatus: u.breachStatus || 'unknown', recoveryEmail: u.recoveryEmailVerified ? maskEmail(u.recoveryEmail) : null,
  });
  const LIST_FIELDS = 'email role twoFactorMethod passkeys adminLocked adminLockReason lockUntil mustChangePassword mustEnrollTwoFactor assistRequestedAt assistMessage lastLoginAt createdAt sessions breachStatus recoveryEmail recoveryEmailVerified';

  app.get('/admin/stats', read, wrap(async (req, res) => {
    const now = new Date();
    const day = new Date(now.getTime() - 86400000);
    const week = new Date(now.getTime() - 7 * 86400000);
    const [users, admins, adminLocked, locked, with2fa, withPasskeys, assist, events24h, failures24h, alerts24h, daily] = await Promise.all([
      User.countDocuments(), User.countDocuments({ role: 'admin' }), User.countDocuments({ adminLocked: true }), User.countDocuments({ lockUntil: { $gt: now } }),
      User.countDocuments({ twoFactorMethod: { $in: ['email', 'totp'] } }), User.countDocuments({ 'passkeys.0': { $exists: true } }),
      User.countDocuments({ assistRequestedAt: { $exists: true, $ne: null } }),
      AuditEvent.countDocuments({ at: { $gte: day } }),
      AuditEvent.countDocuments({ at: { $gte: day }, event: { $in: ['login-failed', 'code-failed', 'passkey-failed'] } }),
      AuditEvent.countDocuments({ at: { $gte: day }, event: 'new-device-alert' }),
      AuditEvent.aggregate([
        { $match: { at: { $gte: week }, event: { $in: ['login', 'passkey-login', 'login-failed', 'code-failed', 'passkey-failed'] } } },
        { $group: { _id: { d: { $dateToString: { format: '%Y-%m-%d', date: '$at' } }, ok: '$ok' }, n: { $sum: 1 } } },
      ]),
    ]);
    const byDay = {};
    for (const r of daily) {
      byDay[r._id.d] ??= { date: r._id.d, signIns: 0, failures: 0 };
      byDay[r._id.d][r._id.ok ? 'signIns' : 'failures'] += r.n;
    }
    const series = Array.from({ length: 7 }, (_, i) => {
      const d = new Date(now.getTime() - (6 - i) * 86400000).toISOString().slice(0, 10);
      return byDay[d] || { date: d, signIns: 0, failures: 0 };
    });
    res.json({ success: true, stats: { users, admins, adminLocked, locked, with2fa, withPasskeys, assist, events24h, failures24h, alerts24h, series } });
  }));

  app.get('/admin/users', read, wrap(async (req, res) => {
    const { q, role, status: st, assist } = req.query;
    const f = {};
    if (isStr(q)) f.email = { $regex: escapeRe(q.trim()), $options: 'i' };
    if (['user', 'admin'].includes(role)) f.role = role;
    if (st === 'admin-locked') f.adminLocked = true;
    else if (st === 'locked') f.lockUntil = { $gt: new Date() };
    else if (st === 'active') { f.adminLocked = { $ne: true }; f.$or = [{ lockUntil: null }, { lockUntil: { $lte: new Date() } }]; }
    if (assist === 'true') f.assistRequestedAt = { $exists: true, $ne: null };
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    const page = Math.max(Number(req.query.page) || 1, 1);
    const [total, rows] = await Promise.all([
      User.countDocuments(f),
      User.find(f).select(LIST_FIELDS).sort({ email: 1 }).skip((page - 1) * limit).limit(limit).lean(),
    ]);
    res.json({ success: true, users: rows.map(row), total, page, pages: Math.max(1, Math.ceil(total / limit)) });
  }));

  app.get('/admin/users/:id', read, wrap(async (req, res) => {
    let u = null;
    try { u = await User.findById(req.params.id).select(LIST_FIELDS).lean(); } catch { /* malformed id */ }
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });
    const events = await AuditEvent.find({ targetId: String(u._id) }).sort({ at: -1 }).limit(15).lean();
    res.json({
      success: true, user: row(u),
      events: events.map((e) => ({ id: String(e._id), at: e.at, event: e.event, label: eventLabel(e.event), ok: e.ok, severity: e.severity, ip: e.ip, device: e.device, geo: e.geo, byAdmin: !!e.actorId && e.actorId !== e.targetId })),
    });
  }));

  app.post('/admin/users/:id/:action', write, sensitive, wrap(async (req, res) => {
    const { action } = req.params;
    if (!ACTIONS.includes(action)) return res.status(404).json({ success: false, message: 'Unknown action' });
    let user = null;
    try { user = await User.findById(req.params.id); } catch { /* malformed id */ }
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const me = req.user;
    const self = String(user._id) === String(me._id);
    const revoke = () => { user.sessions = []; user.tokenVersion = (user.tokenVersion ?? 0) + 1; };
    let event;
    let meta;

    if (action === 'lock') {
      if (self) return res.status(400).json({ success: false, message: 'You cannot lock your own account.' });
      user.adminLocked = true;
      user.adminLockReason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 200) : undefined;
      revoke();
      event = 'admin-lock'; meta = { reason: user.adminLockReason };
    } else if (action === 'unlock') {
      user.adminLocked = false; user.adminLockReason = undefined; user.lockUntil = undefined; user.failedLogins = 0; user.lockCount = 0;
      event = 'admin-unlock';
    } else if (action === 'force-reset') {
      user.mustChangePassword = true; revoke();
      event = 'admin-force-reset';
    } else if (action === 'force-enroll') {
      user.mustEnrollTwoFactor = true;
      event = 'admin-force-enroll';
    } else if (action === 'reset-2fa') {
      Object.assign(user, { twoFactorMethod: 'email', totpSecret: undefined, pendingTotpSecret: undefined, lastTotpStep: undefined, backupCodes: [], passkeys: [], trustedDevices: [] });
      revoke();
      event = 'admin-reset-2fa';
    } else if (action === 'revoke-sessions') {
      revoke();
      event = 'admin-revoke-sessions';
    } else if (action === 'role') {
      const role = req.body?.role;
      if (!['user', 'admin'].includes(role)) return res.status(400).json({ success: false, message: 'Role must be user or admin' });
      if (self) return res.status(400).json({ success: false, message: 'You cannot change your own role.' });
      if (user.role === 'admin' && role === 'user' && (await User.countDocuments({ role: 'admin' })) <= 1) {
        return res.status(400).json({ success: false, message: 'There must be at least one administrator.' });
      }
      user.role = role;
      event = 'admin-role-change'; meta = { role };
    } else if (action === 'issue-recovery') {
      const code = randomize('0', 6);
      user.recoveryHash = await bcrypt.hash(code, 8);
      user.recoveryExpires = new Date(Date.now() + RECOVERY_TTL_MS);
      user.recoveryAttempts = 0;
      user.recoverySentAt = new Date();
      user.assistRequestedAt = undefined;
      user.assistMessage = undefined;
      if (!(await sendMail('recovery', { to: user.email, code, byAdmin: true }))) {
        return res.status(500).json({ success: false, message: 'The recovery e-mail could not be sent. Check the SMTP settings.' });
      }
      event = 'admin-recovery-issued';
    } else {
      user.assistRequestedAt = undefined; user.assistMessage = undefined;
      event = 'admin-recovery-issued'; meta = { cleared: true };
    }
    await user.save();
    await audit(req, event, { actor: me, target: user, meta });
    res.json({ success: true, user: row(user) });
  }));

  // ---- Audit log ----
  function auditFilter(q) {
    const f = {};
    let events = null;
    if (isStr(q.event)) events = q.event.split(',');
    if (isStr(q.category)) {
      const inCat = EVENT_KEYS.filter((k) => eventCategory(k) === q.category);
      events = events ? events.filter((e) => inCat.includes(e)) : inCat;
    }
    if (events) f.event = { $in: events };
    if (isStr(q.severity)) f.severity = { $in: q.severity.split(',') };
    if (q.ok === 'true' || q.ok === 'false') f.ok = q.ok === 'true';
    if (isStr(q.q)) {
      const re = { $regex: escapeRe(q.q.trim()), $options: 'i' };
      f.$or = [{ actorEmail: re }, { targetEmail: re }, { ip: re }];
    }
    const from = isStr(q.from) ? new Date(q.from) : null;
    let to = isStr(q.to) ? new Date(q.to.length === 10 ? `${q.to}T23:59:59.999Z` : q.to) : null;
    if (from && !Number.isNaN(from.getTime())) f.at = { ...f.at, $gte: from };
    if (to && !Number.isNaN(to.getTime())) f.at = { ...f.at, $lte: to };
    return f;
  }
  const auditRow = (e) => ({
    id: String(e._id), at: e.at, event: e.event, label: eventLabel(e.event), severity: e.severity, category: e.category, ok: e.ok,
    actorEmail: e.actorEmail, targetEmail: e.targetEmail, ip: e.ip, device: e.device, geo: e.geo, meta: e.meta,
  });

  app.get('/admin/audit', read, wrap(async (req, res) => {
    const f = auditFilter(req.query);
    const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);
    const page = Math.max(Number(req.query.page) || 1, 1);
    const [total, rows] = await Promise.all([AuditEvent.countDocuments(f), AuditEvent.find(f).sort({ at: -1 }).skip((page - 1) * limit).limit(limit).lean()]);
    res.json({ success: true, events: rows.map(auditRow), total, page, pages: Math.max(1, Math.ceil(total / limit)) });
  }));

  app.get('/admin/audit/export', write, wrap(async (req, res) => {
    const rows = await AuditEvent.find(auditFilter(req.query)).sort({ at: -1 }).limit(5000).lean();
    await audit(req, 'admin-audit-exported', { actor: req.user, meta: { rows: rows.length } });
    res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="audit-log.csv"' });
    res.send(toCsv(rows, AUDIT_COLUMNS));
  }));

  // ---- Policy ----
  app.get('/admin/policy', read, wrap(async (req, res) => res.json({ success: true, policy: await getPolicy() })));

  app.put('/admin/policy', write, sensitive, wrap(async (req, res) => {
    const current = await getPolicy();
    const { policy, errors } = normalizePolicy(req.body, current);
    if (errors.length) return res.status(400).json({ success: false, message: errors[0].message, errors });
    const changed = policyDiff(current, policy);
    await savePolicy(policy);
    await audit(req, 'policy-updated', { actor: req.user, meta: { changed } });
    res.json({ success: true, policy, changed });
  }));

  // ---- Test mail: the recipient comes from the environment, never from the request ----
  app.post('/admin/test-mail', write, sensitive, wrap(async (req, res) => {
    const to = (env.ADMIN_NOTIFY_EMAIL || '').trim();
    if (!to) return res.status(400).json({ success: false, message: 'ADMIN_NOTIFY_EMAIL is not set on the server.' });
    const ok = await sendMail('admin-test', { to, time: new Date().toUTCString() });
    await audit(req, 'admin-test-mail', { actor: req.user, ok });
    if (!ok) return res.status(502).json({ success: false, message: 'The test e-mail could not be sent. Check the SMTP settings.' });
    res.json({ success: true, message: `Test e-mail sent to ${maskEmail(to)}.` });
  }));
}
