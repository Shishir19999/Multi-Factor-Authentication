// Password rules (from the shared policy engine) and a strength estimate for the forms.
import { defaultPolicy, passwordRules as sharedRules, passwordError } from '../shared/policy';

export { PASSWORD_MAX_BYTES } from '../shared/policy';

const COMMON = new Set([
  'password', 'password1', 'password123', 'passw0rd', '12345678', '123456789', '1234567890', 'qwerty123',
  'qwertyuiop', 'iloveyou1', 'letmein123', 'welcome123', 'admin1234', 'abc12345', 'secret123', 'secret12', 'sample@12345',
]);

export const passwordRules = (pw = '', policy = defaultPolicy(), ctx = {}) => sharedRules(pw, policy, ctx);
export const passwordValid = (pw, policy = defaultPolicy(), ctx = {}) => passwordError(pw, policy, ctx) === null;

export const STRENGTH_LABELS = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];

export function passwordStrength(pw = '', policy = defaultPolicy(), ctx = {}) {
  if (!pw) return { score: 0, label: 'Enter a password', empty: true };
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (classes >= 3) score++;
  if (pw.length >= 16 && classes >= 2) score++;
  if (COMMON.has(pw.toLowerCase()) || /^(.)\1+$/.test(pw) || new Set(pw).size <= 3) score = 0;
  if (!passwordValid(pw, policy, ctx)) score = Math.min(score, 1);
  return { score, label: STRENGTH_LABELS[score], empty: false };
}

export const isEmail = (v) => /^\S+@\S+\.\S+$/.test((v || '').trim());
