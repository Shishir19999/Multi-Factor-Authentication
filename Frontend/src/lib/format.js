// Small display helpers (pure, unit-tested).
export function describeDevice(ua = '') {
  if (!ua || /node|axios|supertest|curl/i.test(ua)) return 'API client';
  const browser = /Edg\//.test(ua) ? 'Edge'
    : /OPR\/|Opera/.test(ua) ? 'Opera'
      : /Firefox\//.test(ua) ? 'Firefox'
        : /Chrome\/|CriOS/.test(ua) ? 'Chrome'
          : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows'
    : /Android/.test(ua) ? 'Android'
      : /iPhone|iPad|iPod/.test(ua) ? 'iOS'
        : /Mac OS X|Macintosh/.test(ua) ? 'macOS'
          : /Linux/.test(ua) ? 'Linux' : 'unknown OS';
  return `${browser} on ${os}`;
}

const UNITS = [['day', 86400], ['hour', 3600], ['minute', 60]];

export function timeAgo(date, now = Date.now()) {
  const secs = Math.round((now - new Date(date).getTime()) / 1000);
  if (secs < 45) return 'just now';
  for (const [name, size] of UNITS) {
    if (secs >= size) {
      const n = Math.round(secs / size);
      return `${n} ${name}${n === 1 ? '' : 's'} ago`;
    }
  }
  return 'a minute ago';
}

export const formatDateTime = (date) => new Date(date).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export const EVENT_LABELS = {
  login: 'Signed in',
  'login-failed': 'Failed sign-in (wrong password)',
  'code-failed': 'Failed verification code',
  'password-changed': 'Password changed',
  '2fa-changed': 'Two-step verification changed',
  recovery: 'Password reset via recovery',
};

export const eventLabel = (event) => EVENT_LABELS[event] || event;

export const METHOD_LABELS = { email: 'E-mail code', totp: 'Authenticator app', none: 'Off' };

export const formatBackupCodes = (codes) => codes.map((c, i) => `${String(i + 1).padStart(2, '0')}. ${c}`).join('\n');
