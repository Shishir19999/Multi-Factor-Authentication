import mongoose from 'mongoose';

const auditSchema = new mongoose.Schema({
  at: { type: Date, default: Date.now, index: true },
  event: { type: String, index: true },
  severity: String,
  category: String,
  ok: { type: Boolean, default: true },
  actorId: String,
  actorEmail: String,
  targetId: { type: String, index: true },
  targetEmail: String,
  ip: String,
  userAgent: String,
  device: String,
  geo: String,
  meta: mongoose.Schema.Types.Mixed,
});

const settingSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: mongoose.Schema.Types.Mixed,
  updatedAt: Date,
});

// Short-lived WebAuthn challenges (single use). MongoDB removes expired documents automatically.
const challengeSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  challenge: String,
  purpose: String, // register | login | mfa | stepup
  userId: String,
  expires: { type: Date, index: { expires: 0 } },
});

export const AuditEvent = mongoose.models.AuditEvent || mongoose.model('AuditEvent', auditSchema);
export const Setting = mongoose.models.Setting || mongoose.model('Setting', settingSchema);
export const Challenge = mongoose.models.Challenge || mongoose.model('Challenge', challengeSchema);
