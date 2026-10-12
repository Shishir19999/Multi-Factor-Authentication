// Security policy engine: defaults, validation, password rules, expiry and compliance checks.
// Pure functions, no I/O. The same file is used by the API server and by the in-browser Live preview.

export const POLICY_METHODS = ['email', 'totp'];

export function defaultPolicy() {
  return {
    password: {
      minLength: 8, requireLetter: true, requireNumber: true, requireUpper: false, requireSymbol: false,
      blockEmail: true, historyCount: 3, maxAgeDays: 0,
    },
    breachCheck: 'warn', // off | warn | block (Have I Been Pwned range API, k-anonymity)
    twoFactor: { required: 'none', methods: ['email', 'totp'] }, // required: none | admins | everyone
    session: { lifetimeMinutes: 480, idleMinutes: 0, stepUpMinutes: 5, maxSessions: 10 },
    lockout: { threshold: 5, durationMinutes: 15, progressive: true },
    trustedDeviceDays: 30,
    alerts: { newDevice: true },
  };
}

// path -> [type, ...args, label]
export const POLICY_SCHEMA = {
  'password.minLength': ['int', 6, 64, 'Minimum password length'],
  'password.requireLetter': ['bool', 'Require a letter'],
  'password.requireNumber': ['bool', 'Require a number'],
  'password.requireUpper': ['bool', 'Require an upper-case letter'],
  'password.requireSymbol': ['bool', 'Require a symbol'],
  'password.blockEmail': ['bool', 'Block passwords containing the e-mail name'],
  'password.historyCount': ['int', 0, 10, 'Password history'],
  'password.maxAgeDays': ['int', 0, 730, 'Password expiry (days)'],
  breachCheck: ['enum', ['off', 'warn', 'block'], 'Breached password check'],
  'twoFactor.required': ['enum', ['none', 'admins', 'everyone'], 'Two-step verification required for'],
  'twoFactor.methods': ['methods', 'Allowed code methods'],
  'session.lifetimeMinutes': ['int', 5, 43200, 'Session lifetime (minutes)'],
  'session.idleMinutes': ['int', 0, 1440, 'Idle timeout (minutes)'],
  'session.stepUpMinutes': ['int', 1, 60, 'Step-up validity (minutes)'],
  'session.maxSessions': ['int', 1, 50, 'Maximum sessions per account'],
  'lockout.threshold': ['int', 3, 20, 'Failed attempts before lockout'],
  'lockout.durationMinutes': ['int', 1, 1440, 'Lockout duration (minutes)'],
  'lockout.progressive': ['bool', 'Longer lockouts for repeat offenders'],
  trustedDeviceDays: ['int', 0, 90, 'Trusted device days (0 turns the feature off)'],
  'alerts.newDevice': ['bool', 'Alert on new device or location'],
};

const getPath = (obj, path) => path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
function setPath(obj, path, value) {
  const keys = path.split('.');
  const last = keys.pop();
  const target = keys.reduce((o, k) => (o[k] ??= {}), obj);
  target[last] = value;
}

// Validates a (partial) policy on top of `base`. Returns { policy, errors: [{ path, message }] }.
export function normalizePolicy(input, base = defaultPolicy()) {
  const policy = structuredClone(base);
  const errors = [];
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { policy, errors: [{ path: '', message: 'Policy must be an object' }] };
  }
  for (const [path, spec] of Object.entries(POLICY_SCHEMA)) {
    const raw = getPath(input, path);
    if (raw === undefined) continue;
    const label = spec[spec.length - 1];
    const type = spec[0];
    if (type === 'bool') {
      if (typeof raw !== 'boolean') errors.push({ path, message: `${label} must be on or off` });
      else setPath(policy, path, raw);
    } else if (type === 'int') {
      const n = typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : raw;
      if (!Number.isInteger(n) || n < spec[1] || n > spec[2]) errors.push({ path, message: `${label} must be a whole number from ${spec[1]} to ${spec[2]}` });
      else setPath(policy, path, n);
    } else if (type === 'enum') {
      if (!spec[1].includes(raw)) errors.push({ path, message: `${label} must be one of: ${spec[1].join(', ')}` });
      else setPath(policy, path, raw);
    } else if (type === 'methods') {
      if (!Array.isArray(raw) || raw.length === 0 || raw.some((m) => !POLICY_METHODS.includes(m))) errors.push({ path, message: `${label} must include at least one of: ${POLICY_METHODS.join(', ')}` });
      else setPath(policy, path, [...new Set(raw)]);
    }
  }
  return { policy, errors };
}

export function policyDiff(before, after) {
  return Object.keys(POLICY_SCHEMA).filter((p) => JSON.stringify(getPath(before, p)) !== JSON.stringify(getPath(after, p)));
}

export const PASSWORD_MAX_BYTES = 72; // bcrypt only uses the first 72 bytes
const byteLength = (s) => new TextEncoder().encode(s).length;

export function emailName(email) {
  return String(email || '').split('@')[0].toLowerCase();
}

// Live rule checklist used by both the forms and the server.
export function passwordRules(pw = '', policy = defaultPolicy(), ctx = {}) {
  const p = policy.password;
  const rules = [{ id: 'len', label: `At least ${p.minLength} characters`, ok: pw.length >= p.minLength && byteLength(pw) <= PASSWORD_MAX_BYTES }];
  if (p.requireLetter) rules.push({ id: 'letter', label: 'A letter', ok: /[A-Za-z]/.test(pw) });
  if (p.requireUpper) rules.push({ id: 'upper', label: 'An upper-case letter', ok: /[A-Z]/.test(pw) });
  if (p.requireNumber) rules.push({ id: 'number', label: 'A number', ok: /\d/.test(pw) });
  if (p.requireSymbol) rules.push({ id: 'symbol', label: 'A symbol such as ! or #', ok: /[^A-Za-z0-9]/.test(pw) });
  const name = emailName(ctx.email);
  if (p.blockEmail && name.length >= 3) rules.push({ id: 'email', label: 'Does not contain your e-mail name', ok: !pw.toLowerCase().includes(name) });
  return rules;
}

export function passwordError(pw, policy = defaultPolicy(), ctx = {}) {
  if (typeof pw !== 'string' || !pw) return 'Password is required';
  if (byteLength(pw) > PASSWORD_MAX_BYTES) return `Password must be at most ${PASSWORD_MAX_BYTES} bytes`;
  const failed = passwordRules(pw, policy, ctx).find((r) => !r.ok);
  return failed ? `Password needs: ${failed.label.charAt(0).toLowerCase()}${failed.label.slice(1)}` : null;
}

const DAY = 86400000;

// Password age and expiry. maxAgeDays 0 means passwords never expire.
export function passwordAge(changedAt, policy, now = Date.now()) {
  const at = changedAt ? new Date(changedAt).getTime() : now;
  const ageDays = Math.floor((now - at) / DAY);
  const max = policy.password.maxAgeDays;
  if (!max) return { ageDays, expires: false, expired: false, daysLeft: null };
  const daysLeft = Math.ceil((at + max * DAY - now) / DAY);
  return { ageDays, expires: true, expired: daysLeft <= 0, daysLeft };
}

export function twoFactorRequired(user, policy) {
  const r = policy.twoFactor.required;
  return r === 'everyone' || (r === 'admins' && user.role === 'admin');
}

// Everything the account must still do before it may be used. user: role, twoFactorMethod, passkeyCount,
// passwordChangedAt, mustChangePassword, mustEnrollTwoFactor.
export function compliance(user, policy, now = Date.now()) {
  const out = [];
  const age = passwordAge(user.passwordChangedAt, policy, now);
  if (user.mustChangePassword) out.push({ id: 'change-password', reason: 'forced', message: 'An administrator or a security alert requires you to choose a new password.' });
  else if (age.expired) out.push({ id: 'change-password', reason: 'expired', message: 'Your password has expired. Choose a new one.' });
  const method = user.twoFactorMethod || 'email';
  const hasFactor = method !== 'none' || (user.passkeyCount || 0) > 0;
  if ((twoFactorRequired(user, policy) || user.mustEnrollTwoFactor) && !hasFactor) {
    out.push({ id: 'enroll-2fa', message: 'Two-step verification is required for your account. Turn it on to continue.' });
  } else if (method !== 'none' && !policy.twoFactor.methods.includes(method) && !(user.passkeyCount > 0)) {
    out.push({ id: 'enroll-2fa', message: 'Your current second step is no longer allowed. Choose another method.' });
  }
  return out;
}

export const sessionLifetimeMs = (policy) => policy.session.lifetimeMinutes * 60000;
