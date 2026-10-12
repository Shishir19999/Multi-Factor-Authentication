import mongoose from 'mongoose';

const sessionSchema = new mongoose.Schema({
  sid: String,
  createdAt: Date,
  lastSeen: Date,
  ip: String,
  userAgent: String,
  device: String, // e.g. "Chrome on Windows"
  geo: String, // approximate location label
  name: String, // optional name the user gave this device
  via: String, // password | passkey | trusted | recovery
  stepUpUntil: Date,
}, { _id: false });

const trustedSchema = new mongoose.Schema({
  hash: String,
  expires: Date,
  userAgent: String,
  device: String,
  createdAt: Date,
}, { _id: false });

const passkeySchema = new mongoose.Schema({
  credentialId: String, // base64url
  publicKey: String, // base64url COSE key
  counter: { type: Number, default: 0 },
  transports: { type: [String], default: [] },
  name: String,
  deviceType: String, // singleDevice | multiDevice
  backedUp: Boolean,
  createdAt: Date,
  lastUsedAt: Date,
}, { _id: false });

const alertSchema = new mongoose.Schema({
  id: String,
  at: Date,
  ip: String,
  userAgent: String,
  device: String,
  geo: String,
  family: String,
  placeKey: String,
  reasons: { type: [String], default: [] },
  level: String,
  status: { type: String, default: 'pending' }, // pending | confirmed | denied
  tokenHash: String,
}, { _id: false });

const tokenSchema = new mongoose.Schema({
  id: String,
  name: String,
  prefix: String, // first characters, for recognition in lists
  hash: String, // SHA-256 of the token; the token itself is shown once
  scopes: { type: [String], default: [] },
  createdAt: Date,
  lastUsedAt: Date,
  expiresAt: Date,
}, { _id: false });

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  otpHash: String,
  otpAttempts: { type: Number, default: 0 },
  otpSentAt: Date,
  otpExpires: Date,
  // Bumped on logout / revoke-all; JWTs carry the version they were issued with, so older ones stop working.
  tokenVersion: { type: Number, default: 0 },
  // Code method: 'email' (default), 'totp' (authenticator app) or 'none'. Passkeys are independent of it.
  twoFactorMethod: { type: String, enum: ['email', 'totp', 'none'], default: 'email' },
  totpSecret: String,
  pendingTotpSecret: String,
  lastTotpStep: Number,
  backupCodes: { type: [String], default: [] },
  passkeys: { type: [passkeySchema], default: [] },
  webauthnUserId: String,
  trustedDevices: { type: [trustedSchema], default: [] },
  sessions: { type: [sessionSchema], default: [] },
  apiTokens: { type: [tokenSchema], default: [] },
  alerts: { type: [alertSchema], default: [] },
  knownDevices: { type: [String], default: [] },
  knownPlaces: { type: [String], default: [] },
  // sign-in lockout (shared logic in shared/lockout.js)
  failedLogins: { type: Number, default: 0 },
  lockCount: { type: Number, default: 0 },
  lastFailureAt: Date,
  lockUntil: Date,
  // administrator controls
  adminLocked: { type: Boolean, default: false },
  adminLockReason: String,
  mustChangePassword: { type: Boolean, default: false },
  mustEnrollTwoFactor: { type: Boolean, default: false },
  assistRequestedAt: Date,
  assistMessage: String,
  // password lifecycle
  passwordChangedAt: { type: Date, default: Date.now },
  passwordHistory: { type: [String], default: [] },
  breachStatus: { type: String, enum: ['clean', 'pwned', 'unknown'], default: 'unknown' },
  breachCheckedAt: Date,
  // recovery
  recoveryHash: String,
  recoveryExpires: Date,
  recoveryAttempts: { type: Number, default: 0 },
  recoverySentAt: Date,
  recoveryEmail: String,
  recoveryEmailVerified: { type: Boolean, default: false },
  recoveryEmailPending: String,
  recoveryEmailHash: String,
  recoveryEmailExpires: Date,
  recoveryEmailAttempts: { type: Number, default: 0 },
  lastLoginAt: Date,
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.models.User || mongoose.model('User', userSchema);
