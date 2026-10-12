// Audit event catalogue and CSV export (pure, shared).
// key -> [label, severity (info|warn|critical), category (signin|security|account|admin)]
export const EVENTS = {
  register: ['Account created', 'info', 'account'],
  login: ['Signed in', 'info', 'signin'],
  'login-failed': ['Failed sign-in (wrong password)', 'warn', 'signin'],
  'code-failed': ['Failed verification code', 'warn', 'signin'],
  'passkey-login': ['Signed in with a passkey', 'info', 'signin'],
  'passkey-failed': ['Failed passkey sign-in', 'warn', 'signin'],
  logout: ['Signed out', 'info', 'signin'],
  'account-locked': ['Account locked after failed attempts', 'critical', 'signin'],
  'password-changed': ['Password changed', 'info', 'security'],
  '2fa-changed': ['Two-step verification changed', 'info', 'security'],
  'backup-codes-regenerated': ['Backup codes regenerated', 'info', 'security'],
  recovery: ['Password reset via recovery', 'warn', 'security'],
  'recovery-requested': ['Recovery code requested', 'info', 'security'],
  'passkey-added': ['Passkey added', 'info', 'security'],
  'passkey-removed': ['Passkey removed', 'warn', 'security'],
  'trusted-devices-cleared': ['Trusted devices forgotten', 'info', 'security'],
  'session-revoked': ['Session signed out', 'info', 'security'],
  'sessions-revoked': ['Other sessions signed out', 'info', 'security'],
  'api-token-created': ['API token created', 'info', 'security'],
  'api-token-revoked': ['API token revoked', 'info', 'security'],
  'step-up': ['Identity re-confirmed', 'info', 'security'],
  'step-up-failed': ['Failed identity re-confirmation', 'warn', 'security'],
  'new-device-alert': ['Sign-in from a new device or location', 'warn', 'security'],
  'alert-confirmed': ['Sign-in alert confirmed as you', 'info', 'security'],
  'alert-denied': ['Sign-in alert reported as not you', 'critical', 'security'],
  'recovery-email-set': ['Recovery e-mail verified', 'info', 'security'],
  'recovery-email-removed': ['Recovery e-mail removed', 'info', 'security'],
  'activity-exported': ['Account activity exported', 'info', 'account'],
  'help-requested': ['Administrator help requested', 'info', 'account'],
  'admin-lock': ['Account locked by an administrator', 'warn', 'admin'],
  'admin-unlock': ['Account unlocked by an administrator', 'info', 'admin'],
  'admin-force-reset': ['Password reset forced by an administrator', 'warn', 'admin'],
  'admin-force-enroll': ['Two-step enrolment forced by an administrator', 'warn', 'admin'],
  'admin-reset-2fa': ['Two-step verification reset by an administrator', 'warn', 'admin'],
  'admin-revoke-sessions': ['Sessions revoked by an administrator', 'warn', 'admin'],
  'admin-role-change': ['Role changed by an administrator', 'warn', 'admin'],
  'admin-recovery-issued': ['Recovery code issued by an administrator', 'info', 'admin'],
  'admin-audit-exported': ['Audit log exported', 'info', 'admin'],
  'admin-test-mail': ['Test e-mail sent', 'info', 'admin'],
  'policy-updated': ['Security policy updated', 'warn', 'admin'],
};

export const eventLabel = (key) => EVENTS[key]?.[0] || key;
export const eventSeverity = (key) => EVENTS[key]?.[1] || 'info';
export const eventCategory = (key) => EVENTS[key]?.[2] || 'account';
export const EVENT_KEYS = Object.keys(EVENTS);
export const EVENT_CATEGORIES = [['signin', 'Sign-ins'], ['security', 'Security changes'], ['account', 'Account'], ['admin', 'Administration']];

// One CSV cell. Cells that would be read as formulas by spreadsheet software are prefixed with an apostrophe.
export function csvCell(value) {
  let s = value == null ? '' : value instanceof Date ? value.toISOString() : typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// columns: [[header, rowKey | (row) => value], ...]
export function toCsv(rows, columns) {
  const head = columns.map(([h]) => csvCell(h)).join(',');
  const body = rows.map((r) => columns.map(([, get]) => csvCell(typeof get === 'function' ? get(r) : r[get])).join(','));
  return `${[head, ...body].join('\r\n')}\r\n`;
}

export const AUDIT_COLUMNS = [
  ['Time (UTC)', (r) => new Date(r.at).toISOString()],
  ['Event', (r) => r.event],
  ['Description', (r) => eventLabel(r.event)],
  ['Severity', (r) => r.severity || eventSeverity(r.event)],
  ['Result', (r) => (r.ok ? 'success' : 'failed')],
  ['Actor', (r) => r.actorEmail || ''],
  ['Target', (r) => r.targetEmail || ''],
  ['IP', (r) => r.ip || ''],
  ['Device', (r) => r.device || ''],
  ['Location', (r) => r.geo || ''],
];
