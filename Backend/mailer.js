import nodemailer from 'nodemailer';

// SMTP settings come purely from env (defaults target Gmail):
//   SMTP_HOST (smtp.gmail.com), SMTP_PORT (587), SMTP_SECURE (true = implicit TLS, e.g. port 465),
//   SMTP_USER or SMTP_EMAIL (login), SMTP_PASSWORD (Gmail App Password), SMTP_FROM (optional From address).
// Dev only: OTP_REDIRECT_EMAIL sends every OTP email to that address instead of the user's.
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
  return env.SMTP_FROM || smtpUser(env) || 'no-reply@mfa.local';
}

// Pure helper (unit-tested): builds the message, honouring OTP_REDIRECT_EMAIL.
export function buildOtpMessage(email, otp, env = process.env) {
  const redirect = (env.OTP_REDIRECT_EMAIL || '').trim();
  return {
    from: fromAddress(env),
    to: redirect || email,
    subject: redirect ? `OTP Verification (for ${email})` : 'OTP Verification',
    text: redirect ? `Your OTP is: ${otp}\n\n(Dev redirect: this OTP was requested for ${email})` : `Your OTP is: ${otp}`,
  };
}

// Pure helper: account recovery message (also honours OTP_REDIRECT_EMAIL).
export function buildRecoveryMessage(email, code, env = process.env) {
  const redirect = (env.OTP_REDIRECT_EMAIL || '').trim();
  return {
    from: fromAddress(env),
    to: redirect || email,
    subject: redirect ? `Account recovery code (for ${email})` : 'Account recovery code',
    text: `Your account recovery code is: ${code}

It is valid for 15 minutes. If you did not request it, you can ignore this message.`,
  };
}

export function createTransport(env = process.env) {
  return nodemailer.createTransport(smtpOptions(env));
}

// Sends the OTP email. Tests inject a stub instead; see createApp({ sendOtpEmail }).
export async function sendOtpEmail(email, otp) {
  const info = await createTransport().sendMail(buildOtpMessage(email, otp));
  console.log('Email sent: ' + info.response);
}

export async function sendRecoveryEmail(email, code) {
  const info = await createTransport().sendMail(buildRecoveryMessage(email, code));
  console.log('Recovery email sent: ' + info.response);
}

export function logMailStartupChecks(env = process.env, log = console) {
  if (!env.SMTP_PASSWORD) {
    log.warn('[mail] SMTP_PASSWORD is not set - OTP emails will fail. For Gmail create an App Password and put it in Backend/.env (see README).');
  }
  if ((env.OTP_REDIRECT_EMAIL || '').trim()) {
    log.warn('[mail] WARNING: OTP_REDIRECT_EMAIL is active - ALL OTP emails go to that address instead of the user. Dev only; unset it in production.');
  }
}
