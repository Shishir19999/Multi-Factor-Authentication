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
