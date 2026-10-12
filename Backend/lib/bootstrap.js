// First-run administrator: ADMIN_EMAIL promotes an existing account (or creates it when ADMIN_PASSWORD is set).
import bcrypt from 'bcrypt';
import User from '../models/User.js';
import { defaultPolicy, passwordError } from '../shared/policy.js';

export async function bootstrapAdmin(env = process.env, log = console) {
  const email = (env.ADMIN_EMAIL || '').trim().toLowerCase();
  if (!email) return null;
  let user = await User.findOne({ email });
  if (user) {
    if (user.role !== 'admin') {
      user.role = 'admin';
      await user.save();
      log.log('[admin] existing account promoted to administrator');
    }
    return user;
  }
  const password = env.ADMIN_PASSWORD || '';
  const problem = password ? passwordError(password, defaultPolicy(), { email }) : 'ADMIN_PASSWORD is not set';
  if (problem) {
    log.warn(`[admin] ADMIN_EMAIL is set but the account was not created: ${problem}. Register it first, or set ADMIN_PASSWORD.`);
    return null;
  }
  user = await new User({ email, password: await bcrypt.hash(password, 10), role: 'admin', passwordChangedAt: new Date() }).save();
  log.log('[admin] administrator account created');
  return user;
}
