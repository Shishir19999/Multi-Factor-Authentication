import mongoose from 'mongoose';

const sessionSchema = new mongoose.Schema({
  sid: String,
  createdAt: Date,
  lastSeen: Date,
  ip: String,
  userAgent: String,
}, { _id: false });

const signInSchema = new mongoose.Schema({
  at: Date,
  event: String, // login | login-failed | code-failed | password-changed | 2fa-changed | recovery
  ok: Boolean,
  ip: String,
  userAgent: String,
}, { _id: false });

const trustedSchema = new mongoose.Schema({
  hash: String,
  expires: Date,
  userAgent: String,
}, { _id: false });

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  otpHash: String,
  otpAttempts: { type: Number, default: 0 },
  otpSentAt: Date,
  otpExpires: Date,
  // Bumped on logout; JWTs carry the version they were issued with, so older ones stop working.
  tokenVersion: { type: Number, default: 0 },
  // Second factor: 'email' (default), 'totp' (authenticator app) or 'none'.
  twoFactorMethod: { type: String, enum: ['email', 'totp', 'none'], default: 'email' },
  totpSecret: String,
  pendingTotpSecret: String,
  lastTotpStep: Number,
  backupCodes: { type: [String], default: [] },
  trustedDevices: { type: [trustedSchema], default: [] },
  sessions: { type: [sessionSchema], default: [] },
  signIns: { type: [signInSchema], default: [] },
  failedLogins: { type: Number, default: 0 },
  lockUntil: Date,
  recoveryHash: String,
  recoveryExpires: Date,
  recoveryAttempts: { type: Number, default: 0 },
  recoverySentAt: Date,
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.models.User || mongoose.model('User', userSchema);
