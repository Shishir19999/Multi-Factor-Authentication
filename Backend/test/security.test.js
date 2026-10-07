// API tests for TOTP, backup codes, sessions, sign-in log, change password, trusted devices, lockout and recovery.
// Throwaway database (mfa_sec_test_<pid>), stub mailers; the DB is dropped afterwards. No real mail is sent.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

process.env.JWT_SECRET = 'test-secret';
const BASE = process.env.TEST_MONGO_URI || 'mongodb://127.0.0.1:27017';

const { default: mongoose } = await import('mongoose');
const { default: request } = await import('supertest');
const { createApp, MAX_LOGIN_FAILURES } = await import('../app.js');
const { default: User } = await import('../models/User.js');
const { base32Decode, totp } = await import('../totp.js');

const otps = [];
const recoveries = [];
const app = createApp({
  sendOtpEmail: async (email, otp) => { otps.push({ email, otp }); },
  sendRecoveryEmail: async (email, code) => { recoveries.push({ email, code }); },
  limits: { login: 1000, verify: 1000, resend: 1000, sensitive: 1000, recover: 1000 },
});

before(async () => {
  await mongoose.connect(`${BASE}/mfa_sec_test_${process.pid}`);
  await mongoose.connection.dropDatabase();
  await User.syncIndexes();
});
after(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.disconnect();
});

const PW = 'secret12';
const auth = (t) => ({ Authorization: `Bearer ${t}` });
async function signUp(email) {
  await request(app).post('/auth/register').send({ email, password: PW });
}
async function emailLogin(email) {
  await request(app).post('/auth/login').send({ email, password: PW });
  const v = await request(app).post('/auth/verify-otp').send({ email, otp: otps.at(-1).otp });
  return v.body;
}

test('password policy is enforced on register', async () => {
  const r = await request(app).post('/auth/register').send({ email: 'weak@example.com', password: 'abcdefgh' });
  assert.equal(r.status, 400);
  assert.match(r.body.message, /letter and one number/);
});

test('enrol TOTP: needs password, wrong code rejected, backup codes returned once; login then needs a TOTP code', async () => {
  const email = 'totp@example.com';
  await signUp(email);
  const s1 = await emailLogin(email);
  const t = s1.token;
  assert.equal((await request(app).post('/auth/2fa/totp/setup').set(auth(t)).send({ password: 'wrong-pass1' })).status, 403);
  const setup = await request(app).post('/auth/2fa/totp/setup').set(auth(t)).send({ password: PW });
  assert.match(setup.body.otpauthUrl, /^otpauth:\/\/totp\//);
  assert.equal((await request(app).post('/auth/2fa/totp/enable').set(auth(t)).send({ code: '000000' })).status, 400);
  const enable = await request(app).post('/auth/2fa/totp/enable').set(auth(t)).send({ code: totp(base32Decode(setup.body.secret)) });
  assert.equal(enable.body.success, true);
  assert.equal(enable.body.backupCodes.length, 10);
  const stored = await User.findOne({ email });
  assert.ok(!stored.backupCodes.includes(enable.body.backupCodes[0]), 'backup codes stored hashed');

  otps.length = 0;
  const login = await request(app).post('/auth/login').send({ email, password: PW });
  assert.equal(login.body.method, 'totp');
  assert.equal(otps.length, 0, 'no e-mail for authenticator users');
  const secret = base32Decode(setup.body.secret);
  const wrong = await request(app).post('/auth/verify-otp').send({ email, otp: '000000' });
  assert.equal(wrong.body.success, false);
  // the code used at enrolment cannot be replayed
  const replay = await request(app).post('/auth/verify-otp').send({ email, otp: totp(secret) });
  assert.equal(replay.body.success, false);

  // a backup code works exactly once
  const code = enable.body.backupCodes[0];
  const viaBackup = await request(app).post('/auth/verify-otp').send({ email, otp: code });
  assert.equal(viaBackup.body.success, true);
  await request(app).post('/auth/login').send({ email, password: PW });
  assert.equal((await request(app).post('/auth/verify-otp').send({ email, otp: code })).body.success, false);
  const sec = await request(app).get('/auth/security').set(auth(viaBackup.body.token));
  assert.equal(sec.body.security.backupCodesRemaining, 9);
  assert.equal(sec.body.security.twoFactorMethod, 'totp');

  // regenerate needs the password
  const t2 = viaBackup.body.token;
  assert.equal((await request(app).post('/auth/backup-codes/regenerate').set(auth(t2)).send({ password: 'nope-nope1' })).status, 403);
  const regen = await request(app).post('/auth/backup-codes/regenerate').set(auth(t2)).send({ password: PW });
  assert.equal(regen.body.backupCodes.length, 10);

  // disabling goes back to no second factor and clears the secret
  const off = await request(app).post('/auth/2fa/method').set(auth(t2)).send({ method: 'none', password: PW });
  assert.equal(off.body.security.twoFactorMethod, 'none');
  const direct = await request(app).post('/auth/login').send({ email, password: PW });
  assert.ok(direct.body.token, 'no code needed when 2FA is off');
});

test('trusted device skips the second factor until revoked', async () => {
  const email = 'trust@example.com';
  await signUp(email);
  await request(app).post('/auth/login').send({ email, password: PW });
  const v = await request(app).post('/auth/verify-otp').send({ email, otp: otps.at(-1).otp, trust: true });
  assert.ok(v.body.deviceToken);
  const n = otps.length;
  const again = await request(app).post('/auth/login').send({ email, password: PW, deviceToken: v.body.deviceToken });
  assert.ok(again.body.token);
  assert.equal(again.body.method, 'trusted');
  assert.equal(otps.length, n, 'no mail');
  assert.equal((await request(app).post('/auth/login').send({ email, password: PW, deviceToken: 'bogus' })).body.token, undefined);
  await request(app).delete('/auth/trusted-devices').set(auth(v.body.token));
  const revoked = await request(app).post('/auth/login').send({ email, password: PW, deviceToken: v.body.deviceToken });
  assert.equal(revoked.body.token, undefined);
});

test('sessions list, revoke one, revoke others; sign-in log; change password', async () => {
  const email = 'sess@example.com';
  await signUp(email);
  const a = (await emailLogin(email)).token;
  const b = (await emailLogin(email)).token;
  const list = await request(app).get('/auth/sessions').set(auth(b));
  assert.equal(list.body.sessions.length, 2);
  assert.equal(list.body.sessions.filter((s) => s.current).length, 1);
  const other = list.body.sessions.find((s) => !s.current);
  assert.equal((await request(app).delete('/auth/sessions/unknown').set(auth(b))).status, 404);
  assert.equal((await request(app).delete(`/auth/sessions/${other.id}`).set(auth(b))).status, 200);
  const dead = await request(app).get('/auth/me').set(auth(a));
  assert.equal(dead.status, 401);
  assert.match(dead.body.message, /revoked/);

  const c = (await emailLogin(email)).token;
  assert.equal((await request(app).post('/auth/sessions/revoke-others').set(auth(c))).status, 200);
  assert.equal((await request(app).get('/auth/me').set(auth(b))).status, 401);
  assert.equal((await request(app).get('/auth/me').set(auth(c))).status, 200);

  const log = await request(app).get('/auth/activity').set(auth(c));
  assert.ok(log.body.events.length >= 3);
  assert.equal(log.body.events[0].event, 'login');
  assert.equal(log.body.events[0].ok, true);

  const bad = await request(app).post('/auth/change-password').set(auth(c)).send({ currentPassword: 'wrong-pass1', newPassword: 'newpass123' });
  assert.equal(bad.status, 403);
  assert.equal((await request(app).post('/auth/change-password').set(auth(c)).send({ currentPassword: PW, newPassword: 'short' })).status, 400);
  assert.equal((await request(app).post('/auth/change-password').set(auth(c)).send({ currentPassword: PW, newPassword: PW })).status, 400);
  const d = (await emailLogin(email)).token;
  const ok = await request(app).post('/auth/change-password').set(auth(d)).send({ currentPassword: PW, newPassword: 'newpass123' });
  assert.equal(ok.body.success, true);
  assert.equal((await request(app).get('/auth/me').set(auth(c))).status, 401, 'other sessions signed out');
  assert.equal((await request(app).get('/auth/me').set(auth(d))).status, 200, 'current session stays');
  assert.equal((await request(app).post('/auth/login').send({ email, password: PW })).body.success, false);
  assert.equal((await request(app).post('/auth/login').send({ email, password: 'newpass123' })).body.success, true);
});

test('lockout after repeated wrong passwords, with Retry-After', async () => {
  const email = 'lock@example.com';
  await signUp(email);
  let last;
  for (let i = 0; i < MAX_LOGIN_FAILURES; i++) last = await request(app).post('/auth/login').send({ email, password: 'wrong-pass1' });
  assert.match(last.body.message, /locked/);
  const blocked = await request(app).post('/auth/login').send({ email, password: PW });
  assert.equal(blocked.status, 423);
  assert.ok(blocked.body.retryAfterSeconds > 0);
  assert.ok(blocked.headers['retry-after']);
  await User.updateOne({ email }, { lockUntil: new Date(Date.now() - 1000) });
  assert.equal((await request(app).post('/auth/login').send({ email, password: PW })).body.success, true);
});

test('switching to e-mail / off requires the password', async () => {
  const email = 'method@example.com';
  await signUp(email);
  const t = (await emailLogin(email)).token;
  assert.equal((await request(app).post('/auth/2fa/method').set(auth(t)).send({ method: 'none', password: 'wrong-pass1' })).status, 403);
  assert.equal((await request(app).post('/auth/2fa/method').set(auth(t)).send({ method: 'sms', password: PW })).status, 400);
  assert.equal((await request(app).post('/auth/2fa/method').set(auth(t)).send({ method: 'none', password: PW })).body.security.twoFactorMethod, 'none');
  assert.equal((await request(app).post('/auth/backup-codes/regenerate').set(auth(t)).send({ password: PW })).status, 400);
});

test('account recovery: generic response, code needed, resets password and revokes sessions', async () => {
  const email = 'recover@example.com';
  await signUp(email);
  const t = (await emailLogin(email)).token;
  const unknown = await request(app).post('/auth/recover/request').send({ email: 'ghost@example.com' });
  assert.equal(unknown.body.success, true);
  assert.equal(recoveries.length, 0);
  const req1 = await request(app).post('/auth/recover/request').send({ email });
  assert.equal(req1.body.message, unknown.body.message, 'no account enumeration');
  const code = recoveries.at(-1).code;
  assert.match(code, /^\d{6}$/);
  assert.equal((await request(app).post('/auth/recover/reset').send({ email, code: code === '000000' ? '111111' : '000000', newPassword: 'brandnew99' })).status, 400);
  assert.equal((await request(app).post('/auth/recover/reset').send({ email, code, newPassword: 'weak' })).status, 400);
  const ok = await request(app).post('/auth/recover/reset').send({ email, code, newPassword: 'brandnew99' });
  assert.equal(ok.body.success, true);
  assert.equal((await request(app).get('/auth/me').set(auth(t))).status, 401, 'old sessions revoked');
  assert.equal((await request(app).post('/auth/recover/reset').send({ email, code, newPassword: 'brandnew99' })).status, 400, 'code is single use');
  const login = await request(app).post('/auth/login').send({ email, password: 'brandnew99' });
  assert.equal(login.body.success, true);
});
