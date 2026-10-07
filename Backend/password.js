// Server-side password policy (pure, unit-tested). The UI shows the same rules live.
export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 72; // bcrypt only uses the first 72 bytes

export function validatePassword(pw) {
  if (typeof pw !== 'string') return 'Password is required';
  if (pw.length < PASSWORD_MIN) return `Password must be at least ${PASSWORD_MIN} characters`;
  if (Buffer.byteLength(pw) > PASSWORD_MAX) return `Password must be at most ${PASSWORD_MAX} bytes`;
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'Password must contain at least one letter and one number';
  return null;
}
