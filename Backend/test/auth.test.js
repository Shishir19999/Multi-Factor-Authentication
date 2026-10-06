// Runs against a throwaway database (mfa_test_<pid>) with a stub mailer; the DB is dropped afterwards.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

process.env.JWT_SECRET = 'test-secret';
const BASE = process.env.TEST_MONGO_URI || 'mongodb://127.0.0.1:27017';

const { default: mongoose } = await import('mongoose');
const { default: request } = await import('supertest');
const { createApp, MAX_OTP_ATTEMPTS, RESEND_COOLDOWN_MS } = await import('../app.js');
const { default: User } = await import('../models/User.js');

const outbox = [];
let failMail = false;
const sendOtpEmail = async (email, otp) => {
  if (failMail) throw new Error('smtp down');
  outbox.push({ email, otp });
};
const app = createApp({ sendOtpEmail, limits: { login: 1000, verify: 1000, resend: 1000 } });

const EMAIL = 'user@example.com';
const PASSWORD = 'secret12';

before(async () => {
  await mongoose.connect(`${BASE}/mfa_test_${process.pid}`);
  await mongoose.connection.dropDatabase();
  await User.syncIndexes();
});
after(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.disconnect();
});
beforeEach(() => { outbox.length = 0; failMail = false; });

const lastOtp = () => outbox.at(-1).otp;
const login = () => request(app).post('/auth/login').send({ email: EMAIL, password: PASSWORD });
const verify = (otp) => request(app).post('/auth/verify-otp').send({ email: EMAIL, otp });

test('register validates input and rejects duplicates', async () => {
  assert.equal((await request(app).post('/auth/register').send({ email: 'bad', password: PASSWORD })).status, 400);
  assert.equal((await request(app).post('/auth/register').send({ email: EMAIL, password: '123' })).status, 400);
  const ok = await request(app).post('/auth/register').send({ email: 'User@Example.com', password: PASSWORD });
  assert.equal(ok.body.success, true);
  const dup = await request(app).post('/auth/register').send({ email: EMAIL, password: PASSWORD });
  assert.equal(dup.status, 400);
  assert.match(dup.body.message, /exists/);
  const stored = await User.findOne({ email: EMAIL });
  assert.notEqual(stored.password, PASSWORD, 'password is hashed');
});

test('login: bad credentials send no mail; good credentials mail a 6 digit OTP stored hashed', async () => {
  assert.equal((await request(app).post('/auth/login').send({ email: EMAIL })).status, 400);
  assert.equal((await request(app).post('/auth/login').send({ email: EMAIL, password: 'wrong' })).body.success, false);
  assert.equal((await request(app).post('/auth/login').send({ email: 'nobody@example.com', password: PASSWORD })).body.success, false);
  assert.equal(outbox.length, 0);

  const r = await login();
  assert.equal(r.body.success, true);
  assert.equal(outbox.length, 1);
  assert.match(lastOtp(), /^\d{6}$/);
  const u = await User.findOne({ email: EMAIL });
  assert.notEqual(u.otpHash, lastOtp());
  assert.ok(u.otpExpires > new Date());
});

test('verify: correct OTP returns a JWT, which is single-use', async () => {
  await login();
  const otp = lastOtp();
  const wrong = await verify(otp === '000000' ? '111111' : '000000');
  assert.equal(wrong.body.success, false);
  assert.match(wrong.body.message, /4 attempt/);
  const r = await verify(otp);
  assert.equal(r.body.success, true);
  assert.ok(r.body.token);
  assert.equal((await verify(otp)).body.success, false, 'OTP cannot be reused');
  const me = await request(app).get('/auth/me').set('Authorization', `Bearer ${r.body.token}`);
  assert.equal(me.body.user.email, EMAIL);
  assert.equal((await request(app).get('/auth/me')).status, 401);
  assert.equal((await request(app).get('/auth/me').set('Authorization', 'Bearer junk')).status, 401);
});

test('OTP lockout after too many wrong attempts, even with the right code afterwards', async () => {
  await login();
  const otp = lastOtp();
  const bad = otp === '123456' ? '654321' : '123456';
  let last;
  for (let i = 0; i < MAX_OTP_ATTEMPTS; i++) last = await verify(bad);
  assert.match(last.body.message, /Too many attempts/);
  const r = await verify(otp);
  assert.equal(r.body.success, false, 'correct OTP rejected after lockout');
  // logging in again issues a fresh OTP and works
  await login();
  assert.equal((await verify(lastOtp())).body.success, true);
});

test('OTP expiry', async () => {
  await login();
  await User.updateOne({ email: EMAIL }, { otpExpires: new Date(Date.now() - 1000) });
  const r = await verify(lastOtp());
  assert.equal(r.body.success, false);
  assert.match(r.body.message, /expired/i);
});

test('resend: needs a pending login, honours the cooldown, new OTP replaces the old', async () => {
  await User.updateOne({ email: EMAIL }, { $unset: { otpHash: 1, otpSentAt: 1 } });
  assert.equal((await request(app).post('/auth/resend-otp').send({ email: EMAIL })).status, 400, 'no pending login');

  await login();
  const first = lastOtp();
  const early = await request(app).post('/auth/resend-otp').send({ email: EMAIL });
  assert.equal(early.status, 429);
  assert.ok(early.body.retryAfterSeconds > 0);
  assert.ok(early.headers['retry-after']);
  assert.equal(outbox.length, 1, 'no mail during cooldown');

  await User.updateOne({ email: EMAIL }, { otpSentAt: new Date(Date.now() - RESEND_COOLDOWN_MS - 1000) });
  const ok = await request(app).post('/auth/resend-otp').send({ email: EMAIL });
  assert.equal(ok.status, 200);
  assert.equal(outbox.length, 2);
  const second = lastOtp();
  if (second !== first) assert.equal((await verify(first)).body.success, false, 'old OTP is invalidated');
  assert.equal((await verify(second)).body.success, true);
});

test('mail failure returns 500 and leaves no usable OTP', async () => {
  failMail = true;
  const r = await login();
  assert.equal(r.status, 500);
  const u = await User.findOne({ email: EMAIL });
  assert.equal(u.otpHash, undefined);
  assert.equal(u.otpSentAt, undefined);
});

test('logout revokes the token (all earlier tokens for that user)', async () => {
  await login();
  const t1 = (await verify(lastOtp())).body.token;
  await login();
  const t2 = (await verify(lastOtp())).body.token;
  const h = (t) => ({ Authorization: `Bearer ${t}` });
  assert.equal((await request(app).get('/auth/me').set(h(t1))).status, 200);
  assert.equal((await request(app).post('/auth/logout')).status, 401);
  assert.equal((await request(app).post('/auth/logout').set(h(t1))).status, 200);
  const stale = await request(app).get('/auth/me').set(h(t1));
  assert.equal(stale.status, 401);
  assert.match(stale.body.message, /revoked/);
  assert.equal((await request(app).get('/auth/me').set(h(t2))).status, 401);
  assert.equal((await request(app).post('/auth/logout').set(h(t1))).status, 401, 'cannot logout twice with a stale token');
  await login();
  const t3 = (await verify(lastOtp())).body.token;
  assert.equal((await request(app).get('/auth/me').set(h(t3))).status, 200, 'fresh login after logout works');
});

test('token of a deleted user is rejected', async () => {
  await request(app).post('/auth/register').send({ email: 'gone@example.com', password: PASSWORD });
  await request(app).post('/auth/login').send({ email: 'gone@example.com', password: PASSWORD });
  const v = await request(app).post('/auth/verify-otp').send({ email: 'gone@example.com', otp: lastOtp() });
  const t = v.body.token;
  assert.equal((await request(app).get('/auth/me').set({ Authorization: `Bearer ${t}` })).status, 200);
  await User.deleteOne({ email: 'gone@example.com' });
  assert.equal((await request(app).get('/auth/me').set({ Authorization: `Bearer ${t}` })).status, 401);
});

test('rate limiter returns 429 JSON', async () => {
  const limited = createApp({ sendOtpEmail, limits: { login: 2 } });
  for (let i = 0; i < 2; i++) await request(limited).post('/auth/login').send({ email: EMAIL, password: 'x' });
  const r = await request(limited).post('/auth/login').send({ email: EMAIL, password: 'x' });
  assert.equal(r.status, 429);
  assert.equal(r.body.success, false);
});
