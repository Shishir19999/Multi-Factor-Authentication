// `npm run mail:test` - sends ONE test email through the SMTP configured in Backend/.env (or process env)
// and prints success/failure. Recipient: MAIL_TEST_TO, else OTP_REDIRECT_EMAIL, else the SMTP login.
import dotenv from 'dotenv';
import { createTransport, fromAddress, smtpOptions, smtpUser, logMailStartupChecks } from '../mailer.js';

dotenv.config();
logMailStartupChecks();

const to = process.env.MAIL_TEST_TO || process.env.OTP_REDIRECT_EMAIL || smtpUser();
if (!to) {
  console.error('FAIL: no recipient. Set MAIL_TEST_TO (or OTP_REDIRECT_EMAIL / SMTP_USER).');
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
