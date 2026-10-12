// API tests for cookie sessions + CSRF, roles and the admin console, policy, step-up, passkeys, API tokens,
// sign-in alerts, password history / breach / expiry, recovery options and exports.
// Throwaway database (mfa_feat_test_<pid>), capture mailer, software passkey authenticator; the DB is dropped afterwards.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

process.env.JWT_SECRET = 'test-secret';
const BASE = process.env.TEST_MONGO_URI || 'mongodb://127.0.0.1:27017';

const { default: mongoose } = await import('mongoose');
const { createApp } = await import('../app.js');
const { default: User } = await import('../models/User.js');
const { AuditEvent } = await import('../models/Other.js');
const { request, cookieAgent, captureMail, SoftAuthenticator } = await import('./helpers.js');
const { base32Decode, totp } = await import('../totp.js');
const { bootstrapAdmin } = await import('../lib/bootstrap.js');

const mail = captureMail();
let breachResult = { status: 'safe' };
const app = createApp({
  mail,
  breach: async () => breachResult,
  limits: { login: 1000, verify: 1000, resend: 1000, sensitive: 1000, recover: 1000, public: 1000 },
  env: { ...process.env, ADMIN_NOTIFY_EMAIL: 'ops@example.org' },
});

const PW = 'secret12';
const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
const FIREFOX = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0';
const auth = (t) => ({ Authorization: `Bearer ${t}` });
const stale = (email) => User.updateOne({ email }, { $set: { 'sessions.$[].stepUpUntil': new Date(0) } });

before(async () => {
  await mongoose.connect(`${BASE}/mfa_feat_test_${process.pid}`);
  await mongoose.connection.dropDatabase();
  await User.syncIndexes();
});
after(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.disconnect();
});
beforeEach(() => { mail.clear(); breachResult = { status: 'safe' }; });

async function signUp(email, role = 'user') {
  const r = await request(app).post('/auth/register').send({ email, password: PW });
  assert.equal(r.body.success, true, r.body.message);
  if (role !== 'user') await User.updateOne({ email }, { role });
}
async function signIn(email, ua = CHROME, password = PW) {
  const l = await request(app).post('/auth/login').set('User-Agent', ua).send({ email, password });
  if (l.body.token) return l.body;
  assert.equal(l.body.success, true, l.body.message);
  const v = await request(app).post('/auth/verify-otp').set('User-Agent', ua).send({ email, otp: mail.last('otp').code });
  assert.equal(v.body.success, true, v.body.message);
  return v.body;
}
async function setupUser(email, role = 'user') {
  await signUp(email, role);
  const s = await signIn(email);
  return { token: s.token, email };
}

test('browser sessions use an HttpOnly cookie plus a CSRF token; the token is not exposed to scripts', async () => {
  await signUp('cookie@example.com');
  const agent = cookieAgent(app);
  await agent.post('/auth/login').send({ email: 'cookie@example.com', password: PW });
  const v = await agent.post('/auth/verify-otp').send({ email: 'cookie@example.com', otp: mail.last('otp').code });
  assert.equal(v.body.success, true);
  assert.equal(v.body.token, undefined, 'no bearer token in the body for browsers');
  assert.ok(v.body.csrfToken);
  const setCookie = v.headers['set-cookie'].join(';');
  assert.match(setCookie, /mfa_session=/);
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Lax/i);

  const me = await agent.get('/auth/me');
  assert.equal(me.body.user.email, 'cookie@example.com');
  assert.equal(me.body.csrfToken, v.body.csrfToken);
  const noCsrf = await agent.post('/auth/sessions/revoke-others').send({});
  assert.equal(noCsrf.status, 403);
  assert.equal(noCsrf.body.code, 'CSRF');
  assert.equal((await agent.post('/auth/sessions/revoke-others').set('X-CSRF-Token', 'wrong').send({})).status, 403);
  assert.equal((await agent.post('/auth/sessions/revoke-others').set('Origin', 'https://evil.example').set('X-CSRF-Token', v.body.csrfToken).send({})).status, 403);
  assert.equal((await agent.post('/auth/sessions/revoke-others').set('Origin', 'http://localhost:5173').set('X-CSRF-Token', v.body.csrfToken).send({})).status, 200);
  const out = await agent.post('/auth/logout').set('X-CSRF-Token', v.body.csrfToken).send({});
  assert.equal(out.status, 200);
  assert.equal((await agent.get('/auth/me')).status, 401);
});

test('admin console: roles, user list, lock/unlock, force reset, force enrol, revoke, role guards', async () => {
  const admin = await setupUser('boss@example.com', 'admin');
  const user = await setupUser('worker@example.com');
  const row = await User.findOne({ email: 'worker@example.com' });
  const id = String(row._id);

  assert.equal((await request(app).get('/admin/users').set(auth(user.token))).status, 403, 'plain users are refused');
  assert.equal((await request(app).get('/admin/users')).status, 401);
  const list = await request(app).get('/admin/users?q=worker').set(auth(admin.token));
  assert.equal(list.body.total, 1);
  assert.equal(list.body.users[0].email, 'worker@example.com');
  assert.equal(list.body.users[0].password, undefined, 'no secrets in the list');
  const stats = await request(app).get('/admin/stats').set(auth(admin.token));
  assert.ok(stats.body.stats.users >= 2);
  assert.equal(stats.body.stats.series.length, 7);

  // lock: existing session dies, sign-in is refused with an explanation, unlock restores it
  const lock = await request(app).post(`/admin/users/${id}/lock`).set(auth(admin.token)).send({ reason: 'investigation' });
  assert.equal(lock.body.user.status, 'admin-locked');
  assert.equal((await request(app).get('/auth/me').set(auth(user.token))).status, 401);
  const refused = await request(app).post('/auth/login').send({ email: 'worker@example.com', password: PW });
  assert.equal(refused.status, 423);
  assert.equal(refused.body.adminLocked, true);
  assert.equal((await request(app).post(`/admin/users/${id}/unlock`).set(auth(admin.token)).send({})).body.user.status, 'active');
  const back = await signIn('worker@example.com');
  assert.ok(back.token);

  // force password reset: sign-in works but everything except the password change is blocked
  await request(app).post(`/admin/users/${id}/force-reset`).set(auth(admin.token)).send({});
  const forced = await signIn('worker@example.com');
  assert.deepEqual(forced.user.requirements.map((r) => r.id), ['change-password']);
  const blocked = await request(app).get('/auth/sessions').set(auth(forced.token));
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.code, 'ACTION_REQUIRED');
  assert.equal((await request(app).get('/auth/security').set(auth(forced.token))).status, 200, 'the security summary stays readable');
  const changed = await request(app).post('/auth/change-password').set(auth(forced.token)).send({ currentPassword: PW, newPassword: 'fresh-pass9' });
  assert.equal(changed.body.success, true);
  assert.equal((await request(app).get('/auth/sessions').set(auth(forced.token))).status, 200);

  // force 2FA enrolment: only matters when the account has no second step
  await request(app).post('/auth/2fa/method').set(auth(forced.token)).send({ method: 'none', password: 'fresh-pass9' });
  await request(app).post(`/admin/users/${id}/force-enroll`).set(auth(admin.token)).send({});
  const need = await request(app).get('/auth/security').set(auth(forced.token));
  assert.deepEqual(need.body.security.requirements.map((r) => r.id), ['enroll-2fa']);
  assert.equal((await request(app).post('/auth/2fa/method').set(auth(forced.token)).send({ method: 'none' })).status, 400, 'cannot opt out again');
  assert.equal((await request(app).post('/auth/2fa/method').set(auth(forced.token)).send({ method: 'email' })).status, 200);
  assert.equal((await request(app).get('/auth/sessions').set(auth(forced.token))).status, 200);

  // revoke sessions + reset 2FA
  await request(app).post(`/admin/users/${id}/revoke-sessions`).set(auth(admin.token)).send({});
  assert.equal((await request(app).get('/auth/me').set(auth(forced.token))).status, 401);
  assert.equal((await request(app).post(`/admin/users/${id}/reset-2fa`).set(auth(admin.token)).send({})).body.user.twoFactorMethod, 'email');

  // guards
  const adminId = String((await User.findOne({ email: 'boss@example.com' }))._id);
  assert.equal((await request(app).post(`/admin/users/${adminId}/lock`).set(auth(admin.token)).send({})).status, 400, 'cannot lock yourself');
  assert.equal((await request(app).post(`/admin/users/${adminId}/role`).set(auth(admin.token)).send({ role: 'user' })).status, 400, 'cannot demote yourself');
  assert.equal((await request(app).post(`/admin/users/${id}/role`).set(auth(admin.token)).send({ role: 'owner' })).status, 400);
  assert.equal((await request(app).post(`/admin/users/${id}/role`).set(auth(admin.token)).send({ role: 'admin' })).body.user.role, 'admin');
  assert.equal((await request(app).post(`/admin/users/${id}/nope`).set(auth(admin.token)).send({})).status, 404);
  assert.equal((await request(app).post('/admin/users/not-an-id/lock').set(auth(admin.token)).send({})).status, 404);
  // admin actions need a fresh step-up
  await stale('boss@example.com');
  const need2 = await request(app).post(`/admin/users/${id}/unlock`).set(auth(admin.token)).send({});
  assert.equal(need2.body.code, 'STEP_UP_REQUIRED');
});

test('audit log: filters, pagination, CSV export with spreadsheet-formula protection', async () => {
  const admin = await setupUser('auditor@example.com', 'admin');
  await request(app).post('/auth/login').send({ email: '=cmd@example.com', password: 'x' });
  await request(app).post('/auth/login').send({ email: 'auditor@example.com', password: 'wrong-pass1' });
  const all = await request(app).get('/admin/audit?limit=5&page=1').set(auth(admin.token));
  assert.ok(all.body.total >= 3);
  assert.equal(all.body.events.length, 5);
  const failed = await request(app).get('/admin/audit?ok=false&event=login-failed&q=auditor').set(auth(admin.token));
  assert.ok(failed.body.total >= 1);
  assert.ok(failed.body.events.every((e) => e.event === 'login-failed' && !e.ok));
  const cat = await request(app).get('/admin/audit?category=signin&severity=warn').set(auth(admin.token));
  assert.ok(cat.body.events.every((e) => e.category === 'signin' && e.severity === 'warn'));
  const none = await request(app).get('/admin/audit?from=2999-01-01').set(auth(admin.token));
  assert.equal(none.body.total, 0);

  const csv = await request(app).get('/admin/audit/export?event=login-failed').set(auth(admin.token));
  assert.equal(csv.status, 200);
  assert.match(csv.headers['content-type'], /text\/csv/);
  assert.match(csv.text.split('\r\n')[0], /^Time \(UTC\),Event,Description,Severity,Result/);
  assert.ok(csv.text.includes('login-failed'));
  assert.ok(!/^=/m.test(csv.text), 'no cell starts with a formula character');
  await AuditEvent.create({ event: 'login-failed', ok: false, actorEmail: '=HYPERLINK("http://x")', at: new Date() });
  const csv2 = await request(app).get('/admin/audit/export?event=login-failed').set(auth(admin.token));
  assert.match(csv2.text, /'=HYPERLINK/);
  assert.equal((await request(app).get('/admin/audit/export').set(auth((await setupUser('plain1@example.com')).token))).status, 403);
});

test('security policy: validated, applied to registration and recorded in the audit log; test mail goes to the env address', async () => {
  const admin = await setupUser('policy@example.com', 'admin');
  const bad = await request(app).put('/admin/policy').set(auth(admin.token)).send({ password: { minLength: 3 }, lockout: { threshold: 'many' } });
  assert.equal(bad.status, 400);
  assert.ok(bad.body.errors.length >= 2);
  const ok = await request(app).put('/admin/policy').set(auth(admin.token)).send({ password: { minLength: 12, requireSymbol: true, historyCount: 2 }, trustedDeviceDays: 0 });
  assert.equal(ok.body.success, true);
  assert.deepEqual(ok.body.changed.sort(), ['password.historyCount', 'password.minLength', 'password.requireSymbol', 'trustedDeviceDays']);
  const pub = await request(app).get('/auth/policy');
  assert.equal(pub.body.policy.password.minLength, 12);
  const weak = await request(app).post('/auth/register').send({ email: 'p1@example.com', password: 'secret12' });
  assert.equal(weak.status, 400);
  assert.match(weak.body.message, /at least 12/);
  const strong = await request(app).post('/auth/register').send({ email: 'p1@example.com', password: 'correct-horse-9!' });
  assert.equal(strong.body.success, true);
  assert.ok((await AuditEvent.findOne({ event: 'policy-updated' })).meta.changed.includes('password.minLength'));

  // trusted devices switched off by policy
  await request(app).post('/auth/login').send({ email: 'p1@example.com', password: 'correct-horse-9!' });
  const v = await request(app).post('/auth/verify-otp').send({ email: 'p1@example.com', otp: mail.last('otp').code, trust: true });
  assert.equal(v.body.deviceToken, undefined);

  const sent = await request(app).post('/admin/test-mail').set(auth(admin.token)).send({ to: 'attacker@example.com' });
  assert.equal(sent.body.success, true);
  assert.equal(mail.last('admin-test').to, 'ops@example.org', 'recipient comes from the environment, not the request');
  assert.equal((await request(app).put('/admin/policy').set(auth(admin.token)).send({ password: { minLength: 8, requireSymbol: false, historyCount: 3 }, trustedDeviceDays: 30 })).body.success, true);
});

test('policy can require two-step verification for everyone or only admins', async () => {
  const admin = await setupUser('req-admin@example.com', 'admin');
  const user = await setupUser('req-user@example.com');
  await request(app).post('/auth/2fa/method').set(auth(user.token)).send({ method: 'none' });
  await request(app).post('/auth/2fa/method').set(auth(admin.token)).send({ method: 'none' });
  await request(app).put('/admin/policy').set(auth(admin.token)).send({ twoFactor: { required: 'admins' } });
  assert.deepEqual((await request(app).get('/auth/security').set(auth(admin.token))).body.security.requirements.map((r) => r.id), ['enroll-2fa']);
  assert.equal((await request(app).get('/admin/stats').set(auth(admin.token))).body.code, 'ACTION_REQUIRED', 'the admin must enrol first');
  assert.deepEqual((await request(app).get('/auth/security').set(auth(user.token))).body.security.requirements, []);
  // the admin enrols an authenticator app and is compliant again
  const setup = await request(app).post('/auth/2fa/totp/setup').set(auth(admin.token)).send({});
  await request(app).post('/auth/2fa/totp/enable').set(auth(admin.token)).send({ code: totp(base32Decode(setup.body.secret)) });
  assert.equal((await request(app).get('/admin/stats').set(auth(admin.token))).status, 200);
  await request(app).put('/admin/policy').set(auth(admin.token)).send({ twoFactor: { required: 'everyone', methods: ['totp'] } });
  assert.equal((await request(app).get('/auth/sessions').set(auth(user.token))).body.code, 'ACTION_REQUIRED');
  assert.equal((await request(app).post('/auth/2fa/method').set(auth(user.token)).send({ method: 'email' })).status, 400, 'e-mail codes are no longer allowed');
  await request(app).put('/admin/policy').set(auth(admin.token)).send({ twoFactor: { required: 'none', methods: ['email', 'totp'] } });
  assert.deepEqual((await request(app).get('/auth/security').set(auth(user.token))).body.security.requirements, []);
});

test('step-up: sensitive actions need a recent confirmation (password or authenticator code)', async () => {
  const { token, email } = await setupUser('stepup@example.com');
  await stale(email);
  const r1 = await request(app).post('/auth/tokens').set(auth(token)).send({ name: 'ci', scopes: ['profile:read'], expiresInDays: 30 });
  assert.equal(r1.status, 403);
  assert.equal(r1.body.code, 'STEP_UP_REQUIRED');
  assert.equal(r1.body.stepUp.password, true);
  assert.equal((await request(app).post('/auth/stepup').set(auth(token)).send({ password: 'nope-nope1' })).status, 403);
  assert.equal((await request(app).post('/auth/stepup').set(auth(token)).send({ password: PW })).body.success, true);
  assert.equal((await request(app).post('/auth/tokens').set(auth(token)).send({ name: 'ci', scopes: ['profile:read'], expiresInDays: 30 })).body.success, true);
  assert.ok(await AuditEvent.findOne({ event: 'step-up-failed' }));

  // authenticator code as the step-up proof
  const setup = await request(app).post('/auth/2fa/totp/setup').set(auth(token)).send({});
  const secret = base32Decode(setup.body.secret);
  await request(app).post('/auth/2fa/totp/enable').set(auth(token)).send({ code: totp(secret) });
  await stale(email);
  assert.equal((await request(app).post('/auth/stepup').set(auth(token)).send({ code: '000000' })).status, 403);
  const next = totp(secret, Date.now() + 30000);
  assert.equal((await request(app).post('/auth/stepup').set(auth(token)).send({ code: next })).body.success, true);
  assert.equal((await request(app).post('/auth/stepup').set(auth(token)).send({ code: next })).status, 403, 'a code cannot be replayed');
});

test('passkeys: register, sign in without a password, use as second step and for step-up, replay and origin checks', async () => {
  const { token, email } = await setupUser('passkey@example.com');
  const key = new SoftAuthenticator();
  const opts = await request(app).post('/auth/passkeys/register/options').set(auth(token)).send({});
  assert.equal(opts.body.options.authenticatorSelection.userVerification, 'required');
  assert.equal(opts.body.options.rp.id, 'localhost');
  const wrongOrigin = await request(app).post('/auth/passkeys/register/verify').set(auth(token)).send({ challengeId: opts.body.challengeId, response: key.create(opts.body.options, { origin: 'https://evil.example' }), name: 'x' });
  assert.equal(wrongOrigin.status, 400);
  const opts2 = await request(app).post('/auth/passkeys/register/options').set(auth(token)).send({});
  const reg = await request(app).post('/auth/passkeys/register/verify').set(auth(token)).send({ challengeId: opts2.body.challengeId, response: key.create(opts2.body.options), name: 'Laptop' });
  assert.equal(reg.body.success, true, reg.body.message);
  assert.equal(reg.body.passkeys[0].name, 'Laptop');
  assert.equal((await request(app).get('/auth/security').set(auth(token))).body.security.passkeys, 1);
  const again = await request(app).post('/auth/passkeys/register/options').set(auth(token)).send({});
  assert.equal(again.body.options.excludeCredentials.length, 1, 'already registered keys are excluded');
  const dupe = await request(app).post('/auth/passkeys/register/verify').set(auth(token)).send({ challengeId: again.body.challengeId, response: key.create(again.body.options), name: 'again' });
  assert.equal(dupe.status, 400);

  // passwordless sign-in (discoverable credential, no e-mail typed)
  const lo = await request(app).post('/auth/passkeys/options').send({ purpose: 'login' });
  assert.deepEqual(lo.body.options.allowCredentials ?? [], []);
  const assertion = key.get(lo.body.options);
  const login = await request(app).post('/auth/passkeys/verify').send({ purpose: 'login', challengeId: lo.body.challengeId, response: assertion });
  assert.equal(login.body.success, true, login.body.message);
  assert.ok(login.body.token);
  assert.equal(login.body.user.email, email);
  const replay = await request(app).post('/auth/passkeys/verify').send({ purpose: 'login', challengeId: lo.body.challengeId, response: assertion });
  assert.equal(replay.status, 400, 'challenge is single use');
  const lo2 = await request(app).post('/auth/passkeys/options').send({ purpose: 'login' });
  const badOrigin = await request(app).post('/auth/passkeys/verify').send({ purpose: 'login', challengeId: lo2.body.challengeId, response: key.get(lo2.body.options, { origin: 'https://evil.example' }) });
  assert.equal(badOrigin.status, 400);
  const stored = (await User.findOne({ email })).passkeys[0];
  assert.ok(stored.counter >= 1 && stored.lastUsedAt);
  const noUv = await request(app).post('/auth/passkeys/options').send({ purpose: 'login' });
  assert.equal((await request(app).post('/auth/passkeys/verify').send({ purpose: 'login', challengeId: noUv.body.challengeId, response: key.get(noUv.body.options, { uv: false }) })).status, 400, 'user verification is required');
  assert.ok(await AuditEvent.findOne({ event: 'passkey-failed' }));

  // second step after the password
  await request(app).post('/auth/login').send({ email, password: PW });
  const mo = await request(app).post('/auth/passkeys/options').send({ purpose: 'mfa', email });
  assert.equal(mo.body.options.allowCredentials.length, 1);
  const mfa = await request(app).post('/auth/passkeys/verify').send({ purpose: 'mfa', email, challengeId: mo.body.challengeId, response: key.get(mo.body.options) });
  assert.ok(mfa.body.token);
  assert.equal((await request(app).post('/auth/passkeys/options').send({ purpose: 'mfa', email: 'nobody@example.com' })).status, 400);

  // step-up with the passkey, then removal
  await stale(email);
  assert.equal((await request(app).delete(`/auth/passkeys/${key.id}`).set(auth(mfa.body.token))).body.code, 'STEP_UP_REQUIRED');
  const so = await request(app).post('/auth/passkeys/stepup/options').set(auth(mfa.body.token)).send({});
  const su = await request(app).post('/auth/passkeys/stepup/verify').set(auth(mfa.body.token)).send({ challengeId: so.body.challengeId, response: key.get(so.body.options) });
  assert.equal(su.body.success, true, su.body.message);
  assert.equal((await request(app).patch(`/auth/passkeys/${key.id}`).set(auth(mfa.body.token)).send({ name: 'Work laptop' })).body.success, true);
  const del = await request(app).delete(`/auth/passkeys/${key.id}`).set(auth(mfa.body.token));
  assert.equal(del.body.passkeys.length, 0);
  assert.equal((await request(app).post('/auth/passkeys/options').send({ purpose: 'login' }).then((r) => request(app).post('/auth/passkeys/verify').send({ purpose: 'login', challengeId: r.body.challengeId, response: key.get(r.body.options) }))).status, 400, 'removed passkey no longer signs in');
});

test('personal API tokens: scoped, hashed at rest, read-only, revocable and expiring', async () => {
  const { token, email } = await setupUser('tokens@example.com');
  assert.equal((await request(app).post('/auth/tokens').set(auth(token)).send({ name: 'x', scopes: ['profile:read'] })).status, 400, 'name too short');
  assert.equal((await request(app).post('/auth/tokens').set(auth(token)).send({ name: 'bad', scopes: ['admin:all'] })).status, 400);
  const made = await request(app).post('/auth/tokens').set(auth(token)).send({ name: 'reporting', scopes: ['profile:read', 'activity:read'], expiresInDays: 7 });
  const pat = made.body.token;
  assert.match(pat, /^mfa_pat_/);
  const stored = (await User.findOne({ email })).apiTokens[0];
  assert.notEqual(stored.hash, pat);
  assert.ok(!JSON.stringify(stored).includes(pat), 'plaintext never stored');
  const list = await request(app).get('/auth/tokens').set(auth(token));
  assert.equal(list.body.tokens.length, 1);
  assert.equal(list.body.tokens[0].hash, undefined);

  assert.equal((await request(app).get('/auth/me').set(auth(pat))).body.user.email, email);
  assert.equal((await request(app).get('/auth/activity').set(auth(pat))).status, 200);
  assert.equal((await request(app).get('/auth/activity/export?format=json').set(auth(pat))).status, 200);
  const noScope = await request(app).get('/auth/sessions').set(auth(pat));
  assert.equal(noScope.status, 403);
  assert.match(noScope.body.message, /sessions:read/);
  assert.equal((await request(app).post('/auth/sessions/revoke-others').set(auth(pat))).status, 403, 'tokens are read-only');
  assert.equal((await request(app).post('/admin/stats').set(auth(pat))).status, 404);
  assert.equal((await request(app).get('/auth/me').set(auth('mfa_pat_bogus'))).status, 401);
  assert.ok((await User.findOne({ email })).apiTokens[0].lastUsedAt);

  await User.updateOne({ email }, { $set: { 'apiTokens.0.expiresAt': new Date(Date.now() - 1000) } });
  assert.equal((await request(app).get('/auth/me').set(auth(pat))).status, 401, 'expired');
  assert.equal((await request(app).delete(`/auth/tokens/${stored.id}`).set(auth(token))).body.success, true);
  assert.equal((await request(app).delete(`/auth/tokens/${stored.id}`).set(auth(token))).status, 404);
});

test('new device alert: e-mail with a review link, answered by link or in the app', async () => {
  const email = 'alerts@example.com';
  await signUp(email);
  await signIn(email, CHROME);
  assert.equal(mail.last('new-device'), undefined, 'first sign-in is not an alert');
  const second = await signIn(email, FIREFOX);
  const note = mail.last('new-device');
  assert.ok(note, 'new device mailed');
  assert.match(note.device, /Firefox on macOS/);
  assert.match(note.link, /\/review\?t=/);
  assert.equal(second.alert.level, 'medium');
  assert.equal(second.user.requirements.length, 0, 'an alert does not block sign-in');
  const same = await signIn(email, FIREFOX);
  assert.equal(same.alert, undefined, 'known device from now on');

  const list = await request(app).get('/auth/alerts').set(auth(second.token));
  assert.equal(list.body.alerts.length, 1);
  assert.equal(list.body.alerts[0].status, 'pending');
  assert.equal((await request(app).get('/auth/security').set(auth(second.token))).body.security.unreviewedAlerts, 1);

  const t = new URL(note.link).searchParams.get('t');
  assert.equal((await request(app).post('/auth/alerts/respond').send({ t: `${t}x`, answer: 'yes' })).status, 400);
  const yes = await request(app).post('/auth/alerts/respond').send({ t, answer: 'yes' });
  assert.equal(yes.body.status, 'confirmed');
  assert.equal((await request(app).get('/auth/me').set(auth(second.token))).status, 200, 'confirming keeps sessions');

  await signIn(email, 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36');
  const t2 = new URL(mail.last('new-device').link).searchParams.get('t');
  const live = await signIn(email, 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36');
  const no = await request(app).post('/auth/alerts/respond').send({ t: t2, answer: 'no' });
  assert.equal(no.body.status, 'denied');
  assert.equal((await request(app).get('/auth/me').set(auth(live.token))).status, 401, 'everything signed out');
  const after = await signIn(email, CHROME);
  assert.deepEqual(after.user.requirements.map((r) => r.id), ['change-password'], 'a new password is required');
  assert.ok(await AuditEvent.findOne({ event: 'alert-denied' }));
});

test('password history, breach check (warn / block) and expiry', async () => {
  const email = 'hist@example.com';
  await signUp(email);
  const { token } = await signIn(email);
  const change = (a, b) => request(app).post('/auth/change-password').set(auth(token)).send({ currentPassword: a, newPassword: b });
  assert.equal((await change(PW, 'second-pass2')).body.success, true);
  const reuse = await change('second-pass2', PW);
  assert.equal(reuse.status, 400);
  assert.match(reuse.body.message, /used this password before/);
  assert.equal((await change('second-pass2', 'third-pass3')).body.success, true);

  breachResult = { status: 'pwned', count: 4242 };
  const warn = await change('third-pass3', 'fourth-pass4');
  assert.equal(warn.body.success, true);
  assert.match(warn.body.warning, /4,242/);
  assert.equal((await User.findOne({ email })).breachStatus, 'pwned');
  assert.ok((await request(app).get('/auth/security').set(auth(token))).body.security.score.recommendations.some((r) => r.id === 'breach'));
  const admin = await setupUser('breach-admin@example.com', 'admin');
  await request(app).put('/admin/policy').set(auth(admin.token)).send({ breachCheck: 'block' });
  const blocked = await change('fourth-pass4', 'fifth-pass5');
  assert.equal(blocked.status, 400);
  assert.match(blocked.body.message, /known data breaches/);
  assert.equal((await request(app).post('/auth/register').send({ email: 'newbie@example.com', password: PW })).status, 400);
  breachResult = { status: 'unavailable', reason: 'network' };
  assert.equal((await change('fourth-pass4', 'fifth-pass5')).body.success, true, 'fails open when the service is unreachable');
  await request(app).put('/admin/policy').set(auth(admin.token)).send({ breachCheck: 'warn' });

  // expiry
  await request(app).put('/admin/policy').set(auth(admin.token)).send({ password: { maxAgeDays: 90 } });
  await User.updateOne({ email }, { passwordChangedAt: new Date(Date.now() - 100 * 86400000) });
  const sec = await request(app).get('/auth/security').set(auth(token));
  assert.equal(sec.body.security.passwordAge.expired, true);
  assert.deepEqual(sec.body.security.requirements.map((r) => r.id), ['change-password']);
  await request(app).put('/admin/policy').set(auth(admin.token)).send({ password: { maxAgeDays: 0 } });
});

test('recovery options: verified recovery e-mail also receives the code; help requests reach admins who can issue a code', async () => {
  const { token, email } = await setupUser('rec@example.com');
  const admin = await setupUser('rec-admin@example.com', 'admin');
  assert.equal((await request(app).post('/auth/recovery-email').set(auth(token)).send({ email })).status, 400);
  assert.equal((await request(app).post('/auth/recovery-email').set(auth(token)).send({ email: 'backup@example.org' })).body.success, true);
  const code = mail.last('verify-recovery-email').code;
  assert.equal((await request(app).post('/auth/recovery-email/verify').set(auth(token)).send({ code: code === '000000' ? '111111' : '000000' })).status, 400);
  const verified = await request(app).post('/auth/recovery-email/verify').set(auth(token)).send({ code });
  assert.equal(verified.body.security.recoveryEmail, 'b***@example.org');
  mail.clear();
  await request(app).post('/auth/recover/request').send({ email });
  assert.deepEqual(mail.box.filter((m) => m.kind === 'recovery').map((m) => m.to).sort(), ['backup@example.org', email].sort());
  await request(app).delete('/auth/recovery-email').set(auth(token));
  assert.equal((await User.findOne({ email })).recoveryEmailVerified, false);

  // admin-assisted
  const ghost = await request(app).post('/auth/recover/assist').send({ email: 'ghost@example.com', message: 'hi' });
  const real = await request(app).post('/auth/recover/assist').send({ email, message: 'I lost my phone' });
  assert.equal(ghost.body.message, real.body.message, 'no account enumeration');
  const help = await request(app).get('/admin/users?assist=true').set(auth(admin.token));
  assert.equal(help.body.total, 1);
  assert.equal(help.body.users[0].assistMessage, 'I lost my phone');
  const id = help.body.users[0].id;
  mail.clear();
  const issued = await request(app).post(`/admin/users/${id}/issue-recovery`).set(auth(admin.token)).send({});
  assert.equal(issued.body.success, true);
  const m = mail.last('recovery');
  assert.equal(m.byAdmin, true);
  assert.equal((await request(app).get('/admin/users?assist=true').set(auth(admin.token))).body.total, 0);
  assert.equal((await request(app).post('/auth/recover/reset').send({ email, code: m.code, newPassword: 'brand-new-pw7' })).body.success, true);
});

test('activity export (CSV / JSON) needs step-up for sessions; idle sessions expire; bootstrap admin from the environment', async () => {
  const { token, email } = await setupUser('export@example.com');
  const csv = await request(app).get('/auth/activity/export').set(auth(token));
  assert.equal(csv.status, 200);
  assert.match(csv.text, /Signed in/);
  assert.equal((await request(app).get('/auth/activity/export?format=json').set(auth(token))).body.account, email);
  await stale(email);
  assert.equal((await request(app).get('/auth/activity/export').set(auth(token))).body.code, 'STEP_UP_REQUIRED');
  assert.equal((await request(app).get('/auth/activity?category=security').set(auth(token))).status, 200, 'viewing needs no step-up');

  const admin = await setupUser('idle-admin@example.com', 'admin');
  await request(app).put('/admin/policy').set(auth(admin.token)).send({ session: { idleMinutes: 5 } });
  await new Promise((r) => setTimeout(r, 3100));
  await User.updateOne({ email }, { $set: { 'sessions.$[].lastSeen': new Date(Date.now() - 10 * 60000) } });
  const idle = await request(app).get('/auth/me').set(auth(token));
  assert.equal(idle.status, 401);
  assert.match(idle.body.message, /inactivity/);
  await request(app).put('/admin/policy').set(auth(admin.token)).send({ session: { idleMinutes: 0 } });

  const quiet = { log() {}, warn() {} };
  assert.equal(await bootstrapAdmin({}, quiet), null);
  const promoted = await bootstrapAdmin({ ADMIN_EMAIL: 'Export@Example.com' }, quiet);
  assert.equal(promoted.role, 'admin');
  assert.equal(await bootstrapAdmin({ ADMIN_EMAIL: 'fresh-admin@example.com' }, quiet), null, 'no password, no account');
  assert.equal(await bootstrapAdmin({ ADMIN_EMAIL: 'fresh-admin@example.com', ADMIN_PASSWORD: 'x' }, quiet), null, 'weak password refused');
  assert.equal((await bootstrapAdmin({ ADMIN_EMAIL: 'fresh-admin@example.com', ADMIN_PASSWORD: 'Sup3r-secret-pw' }, quiet)).role, 'admin');
});
