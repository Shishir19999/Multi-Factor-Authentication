// Account security score (0-100) with ranked recommendations. Pure: callers pass plain facts.
import { passwordAge } from './policy.js';

// facts: twoFactorMethod, passkeyCount, backupCodesRemaining, passwordChangedAt, breachStatus ('clean'|'pwned'|'unknown'),
// recoveryEmailVerified, trustedDevices, sessionCount, unreviewedAlerts, riskyTokens
export function securityScore(facts, policy, now = Date.now()) {
  const method = facts.twoFactorMethod || 'none';
  const strong = method === 'totp' || facts.passkeyCount > 0;
  const age = passwordAge(facts.passwordChangedAt, policy, now);
  const items = [];
  const add = (id, label, max, points, tip, tab) => items.push({ id, label, max, points, ok: points >= max, tip: points >= max ? '' : tip, tab });

  add('factor', 'Second step', 30, strong ? 30 : method === 'email' ? 18 : 0,
    method === 'none' ? 'Turn on two-step verification.' : 'Use an authenticator app or a passkey instead of e-mail codes.', 'signin');
  add('passkey', 'Passkey', 10, facts.passkeyCount > 0 ? 10 : 0, 'Add a passkey for phishing-resistant sign-in.', 'signin');
  const backup = method === 'totp' && facts.backupCodesRemaining >= 3 ? 8 : 0;
  add('backup', 'Backup codes', 8, backup, method === 'totp' ? 'Generate new backup codes: fewer than 3 are left.' : 'Backup codes need an authenticator app.', method === 'totp' ? 'signin' : 'signin');
  add('recovery', 'Recovery e-mail', 7, facts.recoveryEmailVerified ? 7 : 0, 'Add and verify a recovery e-mail address.', 'recovery');
  add('age', 'Password age', 8, age.expired ? 0 : age.ageDays <= 365 ? 8 : 4, 'Change your password: it is more than a year old.', 'password');
  const breach = facts.breachStatus === 'clean' ? 12 : facts.breachStatus === 'pwned' ? 0 : 6;
  add('breach', 'Password not in known breaches', 12, breach,
    facts.breachStatus === 'pwned' ? 'Your password appears in a known data breach. Change it now.' : 'Check your password against known breaches by changing it with the breach check on.', 'password');
  add('alerts', 'No unreviewed sign-in alerts', 10, facts.unreviewedAlerts > 0 ? 0 : 10, 'Review the sign-in alerts waiting for you.', 'overview');
  add('sessions', 'Few active sessions', 5, facts.sessionCount <= 3 ? 5 : 2, 'Sign out sessions you do not recognise.', 'sessions');
  add('trusted', 'Few trusted devices', 5, facts.trustedDevices <= 2 ? 5 : 2, 'Forget trusted devices you no longer use.', 'signin');
  add('tokens', 'API tokens are scoped and expire', 5, facts.riskyTokens > 0 ? 0 : 5, 'Replace API tokens that never expire.', 'tokens');

  const score = items.reduce((n, i) => n + i.points, 0);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';
  const label = { A: 'Excellent', B: 'Good', C: 'Fair', D: 'Weak', F: 'At risk' }[grade];
  const recommendations = items.filter((i) => !i.ok).sort((a, b) => (b.max - b.points) - (a.max - a.points)).map((i) => ({ id: i.id, tip: i.tip, tab: i.tab, gain: i.max - i.points }));
  return { score, grade, label, items, recommendations };
}
