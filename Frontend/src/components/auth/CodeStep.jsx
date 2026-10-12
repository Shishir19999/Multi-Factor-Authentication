import { useState } from 'react';
import { api } from '../../api';
import { errorMessage, retryAfter } from '../../api/errors';
import { IS_PREVIEW } from '../../config';
import { useCountdown } from '../../hooks/useCountdown';
import { passkeySignIn } from '../../lib/passkeyFlows';
import { passkeyErrorMessage } from '../../lib/webauthnClient';
import { canSimulate, realAvailable } from '../../lib/passkeyMode';
import { usePolicy } from '../../context/contexts';
import { OPEN_INBOX_EVENT } from '../preview/PreviewInbox';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Field from '../ui/Field';
import OtpInput from '../ui/OtpInput';
import RetryNotice from '../ui/RetryNotice';

// Second step of sign-in: e-mailed code, authenticator or backup code, or a passkey; with a resend countdown,
// a visible rate-limit countdown and "trust this device".
function CodeStep({ email, method, passkeys = false, initialCooldown = 0, onSuccess, onRestart, onToast }) {
  const { policy } = usePolicy();
  const [code, setCode] = useState('');
  const [backup, setBackup] = useState('');
  const [useBackup, setUseBackup] = useState(false);
  const [trust, setTrust] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useCountdown(initialCooldown);
  const [limited, setLimited] = useCountdown(0);

  const fail = (e, fallback) => {
    const wait = retryAfter(e);
    if (wait && e.status === 429) setLimited(wait);
    setError(e.name === 'ApiError' ? errorMessage(e, fallback) : passkeyErrorMessage(e));
    if (/log in again/i.test(e.message)) setTimeout(onRestart, 1800);
  };

  const submit = async (value) => {
    if (busy || limited > 0) return;
    setError('');
    setBusy(true);
    try {
      onSuccess(await api.verifyCode({ email, code: value, trust }));
    } catch (e) {
      fail(e, 'Could not verify the code.');
      setCode('');
      setBusy(false);
    }
  };

  const usePasskey = async () => {
    setError('');
    setBusy(true);
    try {
      onSuccess(await passkeySignIn({ purpose: 'mfa', email, trust }));
    } catch (e) {
      fail(e, 'Could not use the passkey.');
      setBusy(false);
    }
  };

  const resend = async () => {
    setError('');
    try {
      const res = await api.resendCode({ email });
      setCooldown(res.resendCooldownSeconds || 30);
      onToast('A new code has been sent.', 'success');
    } catch (e) {
      if (e.data?.retryAfterSeconds) (e.data.rateLimited ? setLimited : setCooldown)(e.data.retryAfterSeconds);
      setError(errorMessage(e, 'Could not resend the code.'));
    }
  };

  const isEmail = method === 'email';
  const canPasskey = passkeys && (realAvailable() || canSimulate);

  return (
    <div className="stack">
      <div>
        <h1 className="auth-title">{isEmail ? 'Check your e-mail' : 'Two-step verification'}</h1>
        <p className="muted">
          {isEmail
            ? <>We sent a 6-digit code to <strong>{email}</strong>. It is valid for 5 minutes.</>
            : <>Enter the 6-digit code from your authenticator app for <strong>{email}</strong>.</>}
        </p>
      </div>

      {IS_PREVIEW && isEmail && (
        <Alert type="info">
          Live preview: no real e-mail is sent. <button type="button" className="link-btn" onClick={() => window.dispatchEvent(new Event(OPEN_INBOX_EVENT))}>Open the Preview inbox</button> to read your code.
        </Alert>
      )}

      <RetryNotice seconds={limited} title="Too many attempts." />
      {error && limited === 0 && <Alert type="error">{error}</Alert>}

      {useBackup ? (
        <form className="stack" onSubmit={(e) => { e.preventDefault(); if (backup.trim()) submit(backup.trim()); }} noValidate>
          <Field label="Backup code" value={backup} onChange={(e) => setBackup(e.target.value)} placeholder="xxxxx-xxxxx" autoComplete="off" autoCapitalize="none" spellCheck={false} hint="Each backup code works once." />
          <Button type="submit" loading={busy} disabled={!backup.trim() || limited > 0}>Verify backup code</Button>
        </form>
      ) : (
        <OtpInput value={code} onChange={setCode} onComplete={submit} disabled={busy || limited > 0} autoFocus error={undefined} />
      )}

      {policy.trustedDeviceDays > 0 && (
        <label className="check">
          <input type="checkbox" checked={trust} onChange={(e) => setTrust(e.target.checked)} />
          <span>Trust this device for {policy.trustedDeviceDays} days</span>
        </label>
      )}

      {!useBackup && (
        <Button loading={busy} disabled={code.length !== 6 || limited > 0} onClick={() => submit(code)}>Verify and sign in</Button>
      )}
      {canPasskey && <Button variant="secondary" disabled={busy} onClick={usePasskey}>Use a passkey instead</Button>}

      <div className="row-between wrap">
        {isEmail ? (
          <Button variant="ghost" onClick={resend} disabled={cooldown > 0 || limited > 0}>
            {cooldown > 0 ? `Resend code (${cooldown}s)` : 'Resend code'}
          </Button>
        ) : (
          <button type="button" className="link-btn" onClick={() => { setUseBackup((b) => !b); setError(''); }}>
            {useBackup ? 'Use an authenticator code instead' : 'Use a backup code instead'}
          </button>
        )}
        <button type="button" className="link-btn" onClick={onRestart}>Use a different account</button>
      </div>
    </div>
  );
}

export default CodeStep;
