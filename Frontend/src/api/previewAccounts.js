// Documented SAMPLE accounts of the Live preview (shown on the sign-in page and seeded into the in-browser database).
export const PREVIEW_PASSWORD = 'Sample@12345';
export const PREVIEW_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
export const PREVIEW_BACKUP_CODE = 'abcde-fghjk';

export const PREVIEW_ACCOUNTS = [
  { email: 'member@example.com', method: 'email', role: 'user', note: 'Member. Second step by e-mail code; the code appears in the Preview inbox.' },
  { email: 'alice@example.com', method: 'totp', role: 'user', note: 'Member with an authenticator app. Use the live code below, your own app with the secret, or the backup code.' },
  { email: 'bob@example.com', method: 'none', role: 'user', note: 'Member with the second step turned off, so sign-in goes straight through.' },
  { email: 'admin@example.com', method: 'email', role: 'admin', note: 'Administrator: opens the admin console (users, audit log, policy). E-mail code in the Preview inbox.' },
];
