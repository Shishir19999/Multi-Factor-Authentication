// Personal API tokens: scopes, expiry options and the token format (pure, shared).
export const TOKEN_PREFIX = 'mfa_pat_';
export const MAX_TOKENS = 10;

export const TOKEN_SCOPES = {
  'profile:read': 'Read your profile (GET /auth/me)',
  'security:read': 'Read your security settings and score (GET /auth/security)',
  'activity:read': 'Read and export your account activity (GET /auth/activity)',
  'sessions:read': 'List your active sessions (GET /auth/sessions)',
};

// Which scope a token needs for each read-only route.
export const ROUTE_SCOPES = {
  'GET /auth/me': 'profile:read',
  'GET /auth/security': 'security:read',
  'GET /auth/activity': 'activity:read',
  'GET /auth/activity/export': 'activity:read',
  'GET /auth/sessions': 'sessions:read',
};

export const TOKEN_EXPIRY_OPTIONS = [
  { days: 7, label: '7 days' }, { days: 30, label: '30 days' }, { days: 90, label: '90 days' }, { days: 365, label: '1 year' }, { days: 0, label: 'Never expires (not recommended)' },
];

export function validateTokenRequest({ name, scopes, expiresInDays }) {
  const cleanName = typeof name === 'string' ? name.trim() : '';
  if (cleanName.length < 2 || cleanName.length > 40) return { error: 'Give the token a name of 2 to 40 characters.' };
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.some((s) => !(s in TOKEN_SCOPES))) return { error: 'Choose at least one valid scope.' };
  const days = Number(expiresInDays ?? 30);
  if (!TOKEN_EXPIRY_OPTIONS.some((o) => o.days === days)) return { error: 'Choose a valid expiry.' };
  return { value: { name: cleanName, scopes: [...new Set(scopes)], expiresInDays: days } };
}
