import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  otpHash: String,
  otpAttempts: { type: Number, default: 0 },
  otpSentAt: Date,
  otpExpires: Date,
  // Bumped on logout; JWTs carry the version they were issued with, so older ones stop working.
  tokenVersion: { type: Number, default: 0 },
});

export default mongoose.models.User || mongoose.model('User', userSchema);
