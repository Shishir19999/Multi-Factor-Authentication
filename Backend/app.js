import express from 'express';
import cors from 'cors';
import { deliver } from './mailer.js';
import { createContext, corsOptions, OTP_TTL_MS, MAX_OTP_ATTEMPTS, RESEND_COOLDOWN_MS, RECOVERY_TTL_MS } from './lib/context.js';
import authRoutes from './routes/auth.js';
import accountRoutes from './routes/account.js';
import adminRoutes from './routes/admin.js';
import { defaultPolicy } from './shared/policy.js';

export { corsOptions, OTP_TTL_MS, MAX_OTP_ATTEMPTS, RESEND_COOLDOWN_MS, RECOVERY_TTL_MS };
export const MAX_LOGIN_FAILURES = defaultPolicy().lockout.threshold;
export const LOCKOUT_MS = defaultPolicy().lockout.durationMinutes * 60 * 1000;

// createApp({ mail, limits, webauthn, breach, env })
//   mail(kind, data)        replaces SMTP delivery (tests use a capture function)
//   sendOtpEmail/sendRecoveryEmail   legacy shorthands for the "otp" and "recovery" kinds
//   limits                  overrides the per-window request limits (see shared/ratelimit.js)
//   webauthn                overrides { rpID, rpName, origins }
//   breach(password)        replaces the Have I Been Pwned lookup
export function createApp({ mail, sendOtpEmail, sendRecoveryEmail, limits = {}, webauthn = {}, breach, env = process.env } = {}) {
  const app = express();
  app.disable('x-powered-by');
  if (env.TRUST_PROXY) app.set('trust proxy', /^\d+$/.test(env.TRUST_PROXY) ? Number(env.TRUST_PROXY) : env.TRUST_PROXY);

  let deliverMail = mail;
  if (!deliverMail) {
    deliverMail = async (kind, data) => {
      if (kind === 'otp' && sendOtpEmail) return sendOtpEmail(data.to, data.code);
      if (kind === 'recovery' && sendRecoveryEmail) return sendRecoveryEmail(data.to, data.code);
      if (sendOtpEmail || sendRecoveryEmail) return undefined; // legacy hooks given: other kinds are not delivered
      return deliver(kind, data);
    };
  }
  const ctx = createContext({ mail: deliverMail, limits, webauthn, breach, env });

  app.use((req, res, next) => {
    res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' });
    if (/^\/(auth|admin)\b/.test(req.path)) res.set('Cache-Control', 'no-store');
    next();
  });
  app.use(express.json({ limit: '100kb' }));
  // Express 5 leaves req.body undefined when no body is sent; keep the Express 4 behavior (empty object).
  app.use((req, res, next) => { if (req.body === undefined) req.body = {}; next(); });
  app.use(cors(corsOptions(env)));

  authRoutes(app, ctx);
  accountRoutes(app, ctx);
  adminRoutes(app, ctx);

  app.get('/health', (req, res) => res.json({ ok: true }));
  app.use((req, res) => res.status(404).json({ success: false, message: 'Not found' }));
  app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    if (err?.type === 'entity.parse.failed') return res.status(400).json({ success: false, message: 'Invalid JSON' });
    console.error('Unhandled error:', err?.message);
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  });
  return app;
}
