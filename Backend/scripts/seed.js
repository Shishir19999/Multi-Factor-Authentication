// Idempotent seed: 25 users (password stored bcrypt-hashed). Run with `npm run seed`.
// Deterministic (faker seed 2024). Existing users are never modified (upsert with $setOnInsert).
// Note: login still emails an OTP, so use an address you can read or a local fake SMTP server.
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import { faker } from '@faker-js/faker';

dotenv.config();
faker.seed(2024);

const DEMO_PASSWORD = 'Demo@12345';
const TOTAL = 25;
// DEMO_EMAIL lets you point the demo account at a mailbox you can read (default demo@example.com).
const DEMO_EMAIL = (process.env.DEMO_EMAIL || 'demo@example.com').trim().toLowerCase();
const emails = [DEMO_EMAIL, 'alice@example.com', 'bob@example.com'];
while (emails.length < TOTAL) {
  const e = `${faker.person.firstName()}.${faker.person.lastName()}`.toLowerCase().replace(/[^a-z.]/g, '') + '@example.com';
  if (!emails.includes(e)) emails.push(e);
}

await mongoose.connect(process.env.MONGODB_URL || 'mongodb://127.0.0.1:27017/mfa');
const users = mongoose.connection.collection('users');
const hash = await bcrypt.hash(DEMO_PASSWORD, 10);
let created = 0;
for (const email of emails) {
  const r = await users.updateOne(
    { email },
    { $setOnInsert: { email, password: hash, otpAttempts: 0, __v: 0 } },
    { upsert: true },
  );
  if (r.upsertedCount) created++;
}
console.log(`Seed done: ${created} new users (total: ${await users.countDocuments()}) in "${mongoose.connection.name}". Demo user: ${DEMO_EMAIL} / password: ${DEMO_PASSWORD}`);
await mongoose.disconnect();
