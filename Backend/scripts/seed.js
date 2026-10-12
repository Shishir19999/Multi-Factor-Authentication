// Idempotent seed of SAMPLE accounts (password stored bcrypt-hashed). Run with `npm run seed`.
// Deterministic (faker seed 2024). Existing users are never modified (upsert with $setOnInsert).
// Sample accounts only - never use them in production. Login still e-mails a code for the e-mail-code accounts,
// so point SMTP_* at a mailbox you can read, use OTP_REDIRECT_EMAIL, or a local capture SMTP server.
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import { faker } from '@faker-js/faker';

dotenv.config();
faker.seed(2024);

const SAMPLE_PASSWORD = 'Sample@12345';
const SAMPLE_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
const SAMPLE_BACKUP_CODE = 'abcde-fghjk';
const TOTAL = 26;
// SAMPLE_EMAIL lets you point the first sample account at a mailbox you can read (default member@example.com).
const SAMPLE_EMAIL = (process.env.SAMPLE_EMAIL || 'member@example.com').trim().toLowerCase();
const ADMIN_SAMPLE = 'admin@example.com';
const emails = [SAMPLE_EMAIL, 'alice@example.com', 'bob@example.com', ADMIN_SAMPLE];
while (emails.length < TOTAL) {
  const e = `${faker.person.firstName()}.${faker.person.lastName()}`.toLowerCase().replace(/[^a-z.]/g, '') + '@example.com';
  if (!emails.includes(e)) emails.push(e);
}

await mongoose.connect(process.env.MONGODB_URL || 'mongodb://127.0.0.1:27017/mfa');
const users = mongoose.connection.collection('users');
const hash = await bcrypt.hash(SAMPLE_PASSWORD, 10);
const backupHash = crypto.createHash('sha256').update(SAMPLE_BACKUP_CODE.replace('-', '')).digest('hex');
let created = 0;
for (const email of emails) {
  const extra = email === 'alice@example.com'
    ? { twoFactorMethod: 'totp', totpSecret: SAMPLE_TOTP_SECRET, backupCodes: [backupHash] }
    : email === 'bob@example.com' ? { twoFactorMethod: 'none' } : {};
  const r = await users.updateOne(
    { email },
    { $setOnInsert: { email, password: hash, role: email === ADMIN_SAMPLE ? 'admin' : 'user', otpAttempts: 0, passwordChangedAt: new Date(), createdAt: new Date(), ...extra, __v: 0 } },
    { upsert: true },
  );
  if (r.upsertedCount) created++;
}
console.log(`Seed done: ${created} new users (total: ${await users.countDocuments()}) in "${mongoose.connection.name}".`);
console.log(`Sample logins (password ${SAMPLE_PASSWORD}): ${SAMPLE_EMAIL} (e-mail code), alice@example.com (authenticator), bob@example.com (no second step), ${ADMIN_SAMPLE} (administrator, e-mail code).`);
await mongoose.disconnect();
