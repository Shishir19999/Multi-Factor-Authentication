// `npm run mail:test` - sends ONE test e-mail through the SMTP configured in Backend/.env (or process env)
// and prints success/failure. The recipient comes from ADMIN_NOTIFY_EMAIL (never hard-coded).
import dotenv from 'dotenv';
import { createTransport, fromAddress, smtpOptions, logMailStartupChecks } from '../mailer.js';

dotenv.config();
logMailStartupChecks();

const to = (process.env.ADMIN_NOTIFY_EMAIL || '').trim();
if (!to) {
  console.error('FAIL: no recipient. Set ADMIN_NOTIFY_EMAIL in Backend/.env.');
  process.exit(1);
}
const o = smtpOptions();
console.log(`Sending test email via ${o.host}:${o.port} (secure=${o.secure}, auth=${o.auth ? 'yes' : 'no'}) ...`);
try {
  const info = await createTransport().sendMail({
    from: fromAddress(),
    to,
    subject: 'MFA mail test',
    text: `This is a test email from the MFA backend sent at ${new Date().toISOString()}.`,
  });
  console.log(`SUCCESS: sent (${info.response || info.messageId})`);
} catch (e) {
  console.error(`FAIL: ${e.code ? e.code + ' - ' : ''}${e.message}`);
  process.exit(1);
}
