// Password rules and strength estimate shared by registration, reset and change-password forms.
export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 72;

const COMMON = new Set([
  'password', 'password1', 'password123', 'passw0rd', '12345678', '123456789', '1234567890', 'qwerty123',
  'qwertyuiop', 'iloveyou1', 'letmein123', 'welcome123', 'admin1234', 'abc12345', 'secret123', 'secret12',
]);

export function passwordRules(pw = '') {
  return [
    { id: 'len', label: `At least ${PASSWORD_MIN} characters`, ok: pw.length >= PASSWORD_MIN && pw.length <= PASSWORD_MAX },
    { id: 'letter', label: 'A letter', ok: /[A-Za-z]/.test(pw) },
    { id: 'number', label: 'A number', ok: /\d/.test(pw) },
  ];
}

export const passwordValid = (pw) => passwordRules(pw).every((r) => r.ok);

export const STRENGTH_LABELS = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];

export function passwordStrength(pw = '') {
  if (!pw) return { score: 0, label: 'Enter a password', empty: true };
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (classes >= 3) score++;
  if (pw.length >= 16 && classes >= 2) score++;
  if (COMMON.has(pw.toLowerCase()) || /^(.)\1+$/.test(pw) || new Set(pw).size <= 3) score = 0;
  if (!passwordValid(pw)) score = Math.min(score, 1);
  return { score, label: STRENGTH_LABELS[score], empty: false };
}

export const isEmail = (v) => /^\S+@\S+\.\S+$/.test((v || '').trim());
