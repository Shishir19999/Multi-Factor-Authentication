import express from 'express';
import cors from 'cors';
import randomize from 'randomatic';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import User from './models/User.js';
import { sendOtpEmail as defaultSendOtpEmail } from './mailer.js';

export const OTP_TTL_MS = 5 * 60 * 1000; // OTP valid for 5 minutes
export const MAX_OTP_ATTEMPTS = 5;
export const RESEND_COOLDOWN_MS = 30 * 1000;
const JWT_EXPIRES_IN = '1h';
const jwtSecret = () => process.env.JWT_SECRET;

// CORS_ORIGIN: comma-separated allowed origins (e.g. http://localhost:5173,http://192.168.1.20:5173); unset = any origin.
export function corsOptions() {
  const list = (process.env.CORS_ORIGIN || '').split(',').map((o) => o.trim()).filter(Boolean);
  return list.length ? { origin: list } : {};
}

const limiterOptions = (windowMs, limit, message) => ({
  windowMs,
  limit,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ success: false, message }),
});

const isStr = (v) => typeof v === 'string' && v.length > 0;
const normEmail = (e) => e.trim().toLowerCase();

// createApp({ sendOtpEmail, limits }) - sendOtpEmail(email, otp) can be replaced by a stub in tests.
export function createApp({ sendOtpEmail = defaultSendOtpEmail, limits = {} } = {}) {
  const app = express();
  const loginLimiter = rateLimit(limiterOptions(15 * 60 * 1000, limits.login ?? 10, 'Too many login attempts. Try again later.'));
  const verifyLimiter = rateLimit(limiterOptions(15 * 60 * 1000, limits.verify ?? 20, 'Too many verification attempts. Try again later.'));
  const resendLimiter = rateLimit(limiterOptions(15 * 60 * 1000, limits.resend ?? 10, 'Too many resend requests. Try again later.'));

  app.use(express.json());
  // Express 5 leaves req.body undefined when no body is sent; keep the Express 4 behavior (empty object).
  app.use((req, res, next) => { if (req.body === undefined) req.body = {}; next(); });
  app.use(cors(corsOptions()));

  function clearOtp(user) {
    user.otpHash = undefined;
    user.otpExpires = undefined;
    user.otpAttempts = 0;
  }

  // Issue a fresh OTP for the user, store only its hash, and email it
  async function issueOtp(user) {
    const otp = randomize('0', 6);
    user.otpHash = await bcrypt.hash(otp, 8);
    user.otpExpires = new Date(Date.now() + OTP_TTL_MS);
    user.otpAttempts = 0;
    user.otpSentAt = new Date();
    await user.save();
    try {
      await sendOtpEmail(user.email, otp);
    } catch (mailError) {
      console.error('Error sending email:', mailError.message);
      clearOtp(user);
      user.otpSentAt = undefined;
      await user.save();
      return false;
    }
    return true;
  }

  // Auth middleware: requires "Authorization: Bearer <jwt>" that matches the user's current tokenVersion
  async function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, message: 'Missing token' });
    let payload;
    try {
      payload = jwt.verify(token, jwtSecret());
    } catch {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
    try {
      const user = await User.findById(payload.sub).select('email tokenVersion');
      if (!user) return res.status(401).json({ success: false, message: 'User not found' });
      if ((payload.tv ?? 0) !== (user.tokenVersion ?? 0)) {
        return res.status(401).json({ success: false, message: 'Token has been revoked' });
      }
      req.auth = payload;
      req.user = user;
      return next();
    } catch (error) {
      console.error('Error in auth middleware:', error.message);
      return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
  }

  // Registration endpoint
  app.post('/auth/register', async (req, res) => {
    const { email: rawEmail, password } = req.body || {};

    try {
      if (typeof rawEmail !== 'string' || !/^\S+@\S+\.\S+$/.test(rawEmail.trim())) {
        return res.status(400).json({ success: false, message: 'A valid email is required' });
      }
      if (typeof password !== 'string' || password.length < 6) {
        return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
      }
      const email = normEmail(rawEmail);
      if (await User.findOne({ email })) {
        return res.status(400).json({ success: false, message: 'Email already exists' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      await new User({ email, password: hashedPassword }).save();
      return res.json({ success: true, message: 'User registered successfully', redirectTo: '/login' });
    } catch (error) {
      console.error('Error during registration:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred during registration' });
    }
  });

  // Login endpoint (step 1: password, then an OTP is emailed)
  app.post('/auth/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body || {};

    try {
      if (!isStr(email) || !isStr(password)) {
        return res.status(400).json({ success: false, message: 'Email and password are required' });
      }
      const user = await User.findOne({ email: normEmail(email) });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.json({ success: false, message: 'Invalid credentials' });
      }

      if (!(await issueOtp(user))) {
        return res.status(500).json({ success: false, message: 'Could not send the OTP email. Please try again later.' });
      }

      return res.json({ success: true, resendCooldownSeconds: RESEND_COOLDOWN_MS / 1000 });
    } catch (error) {
      console.error('Error during login:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred during login' });
    }
  });

  // Resend OTP (only after a successful password login created a pending OTP)
  app.post('/auth/resend-otp', resendLimiter, async (req, res) => {
    const { email } = req.body || {};

    try {
      if (!isStr(email)) {
        return res.status(400).json({ success: false, message: 'Email is required' });
      }
      const user = await User.findOne({ email: normEmail(email) });
      if (!user || !user.otpSentAt || !user.otpHash) {
        return res.status(400).json({ success: false, message: 'Please log in again' });
      }

      const waitMs = user.otpSentAt.getTime() + RESEND_COOLDOWN_MS - Date.now();
      if (waitMs > 0) {
        const retryAfterSeconds = Math.ceil(waitMs / 1000);
        res.set('Retry-After', String(retryAfterSeconds));
        return res.status(429).json({
          success: false,
          message: `Please wait ${retryAfterSeconds}s before requesting a new code`,
          retryAfterSeconds,
        });
      }

      if (!(await issueOtp(user))) {
        return res.status(500).json({ success: false, message: 'Could not send the OTP email. Please try again later.' });
      }
      return res.json({ success: true, resendCooldownSeconds: RESEND_COOLDOWN_MS / 1000 });
    } catch (error) {
      console.error('Error during OTP resend:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred while resending the OTP' });
    }
  });

  // OTP verification endpoint (step 2)
  app.post('/auth/verify-otp', verifyLimiter, async (req, res) => {
    const { email, otp } = req.body || {};

    try {
      if (!isStr(email) || !(isStr(otp) || typeof otp === 'number')) {
        return res.status(400).json({ success: false, message: 'Email and OTP are required' });
      }

      const user = await User.findOne({ email: normEmail(email) });

      if (!user || !user.otpHash || !user.otpExpires || user.otpExpires.getTime() < Date.now()) {
        return res.json({ success: false, message: 'Invalid or expired OTP' });
      }

      if (user.otpAttempts >= MAX_OTP_ATTEMPTS) {
        clearOtp(user);
        await user.save();
        return res.json({ success: false, message: 'Too many attempts. Please log in again.' });
      }

      const ok = await bcrypt.compare(String(otp).trim(), user.otpHash);
      if (!ok) {
        user.otpAttempts += 1;
        const remaining = MAX_OTP_ATTEMPTS - user.otpAttempts;
        if (remaining <= 0) clearOtp(user);
        await user.save();
        return res.json({
          success: false,
          message: remaining > 0 ? `Invalid OTP. ${remaining} attempt(s) left.` : 'Too many attempts. Please log in again.',
        });
      }

      clearOtp(user);
      user.otpSentAt = undefined;
      await user.save();

      const token = jwt.sign(
        { sub: String(user._id), email: user.email, tv: user.tokenVersion ?? 0 },
        jwtSecret(),
        { expiresIn: JWT_EXPIRES_IN },
      );
      return res.json({ success: true, token, user: { id: user._id, email: user.email } });
    } catch (error) {
      console.error('Error during OTP verification:', error.message);
      return res.status(500).json({ success: false, message: 'An error occurred during OTP verification' });
    }
  });

  // Current user (protected)
  app.get('/auth/me', requireAuth, (req, res) => {
    res.json({ success: true, user: { id: req.user._id, email: req.user.email } });
  });

  // Logout: bumps tokenVersion so every JWT issued so far for this user stops working.
  app.post('/auth/logout', requireAuth, async (req, res) => {
    try {
      await User.updateOne({ _id: req.user._id }, { $inc: { tokenVersion: 1 } });
      return res.json({ success: true, message: 'Logged out' });
    } catch (error) {
      console.error('Error during logout:', error.message);
      return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
  });

  return app;
}
