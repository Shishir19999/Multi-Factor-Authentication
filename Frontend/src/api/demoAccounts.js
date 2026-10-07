// Documented sample accounts of the demo (shown on the sign-in page and seeded into the demo database).
export const DEMO_PASSWORD = 'Demo@12345';
export const DEMO_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
export const DEMO_BACKUP_CODE = 'abcde-fghjk';

export const DEMO_ACCOUNTS = [
  { email: 'demo@example.com', method: 'email', note: 'E-mail code. The code appears in the Demo inbox.' },
  { email: 'alice@example.com', method: 'totp', note: 'Authenticator app. Use the live demo code below, your own app with the secret, or the backup code.' },
  { email: 'bob@example.com', method: 'none', note: 'Two-step verification is off, so you go straight in.' },
];
