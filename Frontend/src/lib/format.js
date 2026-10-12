// Small display helpers (pure, unit-tested). Device naming and event labels come from the shared modules.
import { deviceLabel } from '../shared/risk';

export { eventLabel, EVENT_CATEGORIES } from '../shared/audit';
export { formatDuration } from '../shared/lockout';

export const describeDevice = (ua = '') => deviceLabel(ua);

const UNITS = [['day', 86400], ['hour', 3600], ['minute', 60]];

export function timeAgo(date, now = Date.now()) {
  if (!date) return 'never';
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

export function timeUntil(date, now = Date.now()) {
  const secs = Math.round((new Date(date).getTime() - now) / 1000);
  if (secs <= 0) return 'expired';
  for (const [name, size] of UNITS) {
    if (secs >= size) {
      const n = Math.round(secs / size);
      return `in ${n} ${name}${n === 1 ? '' : 's'}`;
    }
  }
  return 'in under a minute';
}

export const formatDateTime = (date) => (date ? new Date(date).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'never');
export const formatDate = (date) => (date ? new Date(date).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'never');

export const METHOD_LABELS = { email: 'E-mail code', totp: 'Authenticator app', none: 'Off' };
export const ROLE_LABELS = { user: 'Member', admin: 'Administrator' };
export const STATUS_LABELS = { active: 'Active', locked: 'Locked (too many attempts)', 'admin-locked': 'Locked by an administrator' };

export const formatBackupCodes = (codes) => codes.map((c, i) => `${String(i + 1).padStart(2, '0')}. ${c}`).join('\n');
