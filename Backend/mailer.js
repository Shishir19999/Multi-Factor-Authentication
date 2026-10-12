import nodemailer from 'nodemailer';

// SMTP settings come purely from env (defaults target Gmail):
//   SMTP_HOST (smtp.gmail.com), SMTP_PORT (587), SMTP_SECURE (true = implicit TLS, e.g. port 465),
//   SMTP_USER or SMTP_EMAIL (login), SMTP_PASSWORD (Gmail App Password), MAIL_FROM or SMTP_FROM (optional From address).
// Dev only: OTP_REDIRECT_EMAIL sends every user-facing mail to that address instead of the user's.
// Admin and test mail goes to ADMIN_NOTIFY_EMAIL (never hard-coded).
// Port 587 uses STARTTLS (secure=false); port 465 uses implicit TLS (secure=true).
const isLocalHost = (host) => ['127.0.0.1', 'localhost', '::1'].includes(host);

export function smtpUser(env = process.env) {
  return env.SMTP_USER || env.SMTP_EMAIL || '';
}

export function smtpOptions(env = process.env) {
  const host = env.SMTP_HOST || 'smtp.gmail.com';
  const port = Number(env.SMTP_PORT) || 587;
  const secure = env.SMTP_SECURE ? env.SMTP_SECURE === 'true' : port === 465;
  const user = smtpUser(env);
  return {
    host,
    port,
    secure,
    // Force STARTTLS on submission ports, but allow plain local fake SMTP servers (dev/tests).
    ...(!secure && !isLocalHost(host) ? { requireTLS: true } : {}),
    ...(user ? { auth: { user, pass: env.SMTP_PASSWORD || '' } } : {}),
    tls: { minVersion: 'TLSv1.2' },
  };
}

// Gmail only delivers mail whose From is the authenticated account, so From defaults to the SMTP login.
export function fromAddress(env = process.env) {
  return env.MAIL_FROM || env.SMTP_FROM || smtpUser(env) || 'no-reply@mfa.local';
}

const redirectOf = (env) => (env.OTP_REDIRECT_EMAIL || '').trim();
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Pure helper (unit-tested): builds the message, honouring OTP_REDIRECT_EMAIL.
export function buildOtpMessage(email, otp, env = process.env) {
  const redirect = redirectOf(env);
  return {
    from: fromAddress(env),
    to: redirect || email,
    subject: redirect ? `OTP Verification (for ${email})` : 'OTP Verification',
    text: redirect ? `Your OTP is: ${otp}\n\n(Dev redirect: this OTP was requested for ${email})` : `Your OTP is: ${otp}`,
  };
}

// Pure helper: account recovery message (also honours OTP_REDIRECT_EMAIL).
export function buildRecoveryMessage(email, code, env = process.env, { byAdmin = false } = {}) {
  const redirect = redirectOf(env);
  return {
    from: fromAddress(env),
    to: redirect || email,
    subject: redirect ? `Account recovery code (for ${email})` : 'Account recovery code',
    text: `Your account recovery code is: ${code}\n\n${byAdmin ? 'An administrator issued this code at your request. ' : ''}It is valid for 15 minutes. If you did not request it, you can ignore this message.`,
  };
}

// Builds any message the app sends. kind: otp | recovery | verify-recovery-email | new-device | admin-test
export function buildMessage(kind, data, env = process.env) {
  const redirect = redirectOf(env);
  const to = data.to;
  const base = { from: fromAddress(env), to: redirect || to };
  const tag = redirect ? ` (for ${to})` : '';
  if (kind === 'otp') return buildOtpMessage(to, data.code, env);
  if (kind === 'recovery') return buildRecoveryMessage(to, data.code, env, { byAdmin: !!data.byAdmin });
  if (kind === 'verify-recovery-email') {
    return { ...base, subject: `Confirm your recovery e-mail${tag}`, text: `Your recovery e-mail confirmation code is: ${data.code}\n\nIt is valid for 15 minutes.` };
  }
  if (kind === 'new-device') {
    const lines = [
      'We noticed a sign-in to your account from a device or place we have not seen before.',
      '',
      `Device: ${data.device}`,
      `Location: ${data.geo}`,
      `Time: ${data.time}`,
      `IP address: ${data.ip || 'unknown'}`,
      '',
      `Was this you? Review it here: ${data.link}`,
      '',
      'If it was not you, choose "No, secure my account": every session is signed out and you will be asked for a new password.',
    ];
    const html = `<p>We noticed a sign-in to your account from a device or place we have not seen before.</p>
<ul><li>Device: ${esc(data.device)}</li><li>Location: ${esc(data.geo)}</li><li>Time: ${esc(data.time)}</li><li>IP address: ${esc(data.ip || 'unknown')}</li></ul>
<p><a href="${esc(data.link)}">Was this you? Review the sign-in</a></p>
<p>If it was not you, choose &quot;No, secure my account&quot;: every session is signed out and you will be asked for a new password.</p>`;
    return { ...base, subject: `New sign-in to your account${tag}`, text: lines.join('\n'), html };
  }
  if (kind === 'admin-test') {
    return { from: fromAddress(env), to, subject: 'Security mail test', text: `This is a test message from the account security service, sent at ${data.time}.` };
  }
  throw new Error(`Unknown mail kind: ${kind}`);
}

let cached;
export function createTransport(env = process.env) {
  const opts = smtpOptions(env);
  const key = JSON.stringify(opts);
  if (cached?.key !== key) cached = { key, transport: nodemailer.createTransport(opts) };
  return cached.transport;
}

// Default delivery used by the server. Tests inject their own `mail(kind, data)` instead of this.
export async function deliver(kind, data) {
  const info = await createTransport().sendMail(buildMessage(kind, data));
  console.log(`Mail sent (${kind}): ${info.response || info.messageId}`);
}

export const sendOtpEmail = (email, otp) => deliver('otp', { to: email, code: otp });
export const sendRecoveryEmail = (email, code) => deliver('recovery', { to: email, code });

export function logMailStartupChecks(env = process.env, log = console) {
  if (!env.SMTP_PASSWORD) {
    log.warn('[mail] SMTP_PASSWORD is not set - e-mails will fail. For Gmail create an App Password and put it in Backend/.env (see README).');
  }
  if (redirectOf(env)) {
    log.warn('[mail] WARNING: OTP_REDIRECT_EMAIL is active - ALL user e-mails go to that address instead of the user. Dev only; unset it in production.');
  }
}
