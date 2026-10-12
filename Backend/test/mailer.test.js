// Pure unit tests for the mailer helpers - no network, no DB.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildOtpMessage, smtpOptions } from '../mailer.js';

test('OTP goes to the user by default', () => {
  const m = buildOtpMessage('user@example.com', '123456', { SMTP_USER: 'sender@example.com' });
  assert.equal(m.to, 'user@example.com');
  assert.equal(m.from, 'sender@example.com');
  assert.equal(m.subject, 'OTP Verification');
  assert.match(m.text, /123456/);
});

test('OTP_REDIRECT_EMAIL redirects every OTP and names the account in the subject', () => {
  const m = buildOtpMessage('user@example.com', '654321', { OTP_REDIRECT_EMAIL: 'you@example.com' });
  assert.equal(m.to, 'you@example.com');
  assert.match(m.subject, /user@example\.com/);
  assert.match(m.text, /654321/);
});

test('SMTP options: Gmail STARTTLS on 587, implicit TLS on 465, plain for local fake SMTP', () => {
  const gmail = smtpOptions({ SMTP_USER: 'a@example.com', SMTP_PASSWORD: 'x' });
  assert.deepEqual([gmail.host, gmail.port, gmail.secure, gmail.requireTLS], ['smtp.gmail.com', 587, false, true]);
  assert.equal(smtpOptions({ SMTP_PORT: '465' }).secure, true);
  const local = smtpOptions({ SMTP_HOST: '127.0.0.1', SMTP_PORT: '2525' });
  assert.equal(local.requireTLS, undefined);
  assert.equal(local.auth, undefined);
});

test('MAIL_FROM wins over SMTP_FROM and the SMTP login', async () => {
  const { fromAddress, buildMessage } = await import('../mailer.js');
  assert.equal(fromAddress({ MAIL_FROM: 'a@example.com', SMTP_FROM: 'b@example.com', SMTP_USER: 'c@example.com' }), 'a@example.com');
  assert.equal(fromAddress({ SMTP_FROM: 'b@example.com', SMTP_USER: 'c@example.com' }), 'b@example.com');
  assert.equal(fromAddress({ SMTP_USER: 'c@example.com' }), 'c@example.com');
  const m = buildMessage('verify-recovery-email', { to: 'r@example.com', code: '123456' }, { SMTP_USER: 'c@example.com' });
  assert.equal(m.to, 'r@example.com');
  assert.match(m.text, /123456/);
});

test('new-device mail escapes HTML and carries the review link; admin test mail is not redirected', async () => {
  const { buildMessage } = await import('../mailer.js');
  const m = buildMessage('new-device', { to: 'u@example.com', device: '<b>Chrome</b>', geo: 'Berlin, Germany', ip: '203.0.113.5', time: 'now', link: 'https://app.example/review?t=a.b.c' }, { SMTP_USER: 's@example.com' });
  assert.match(m.subject, /New sign-in/);
  assert.ok(m.html.includes('&lt;b&gt;Chrome&lt;/b&gt;'));
  assert.ok(!m.html.includes('<b>Chrome</b>'));
  assert.match(m.text, /review\?t=a\.b\.c/);
  const redirected = buildMessage('new-device', { to: 'u@example.com', device: 'd', geo: 'g', link: 'l', time: 't' }, { OTP_REDIRECT_EMAIL: 'dev@example.com' });
  assert.equal(redirected.to, 'dev@example.com');
  assert.match(redirected.subject, /u@example\.com/);
  const admin = buildMessage('admin-test', { to: 'ops@example.org', time: 'now' }, { OTP_REDIRECT_EMAIL: 'dev@example.com' });
  assert.equal(admin.to, 'ops@example.org', 'admin mail goes to the configured admin address');
  assert.throws(() => buildMessage('mystery', { to: 'x' }), /Unknown mail kind/);
});
