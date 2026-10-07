import { useEffect, useState } from 'react';
import { api } from '../../api';
import { errorMessage } from '../../api/errors';
import { IS_DEMO } from '../../config';
import { OPEN_INBOX_EVENT } from '../demo/DemoInbox';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Field from '../ui/Field';
import OtpInput from '../ui/OtpInput';

// Second step of sign-in: e-mailed code or authenticator/backup code, with resend countdown and "trust this device".
function CodeStep({ email, method, initialCooldown = 0, onSuccess, onRestart, onToast }) {
  const [code, setCode] = useState('');
  const [backup, setBackup] = useState('');
  const [useBackup, setUseBackup] = useState(false);
  const [trust, setTrust] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(initialCooldown);

  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  const submit = async (value) => {
    if (busy) return;
    setError('');
    setBusy(true);
    try {
      const res = await api.verifyCode({ email, code: value, trust });
      onSuccess(res);
    } catch (e) {
      setError(errorMessage(e, 'Could not verify the code.'));
      setCode('');
      setBusy(false);
      if (/log in again/i.test(e.message)) setTimeout(onRestart, 1800);
    }
  };

  const resend = async () => {
    setError('');
    try {
      const res = await api.resendCode({ email });
      setCooldown(res.resendCooldownSeconds || 30);
      onToast('A new code has been sent.', 'success');
    } catch (e) {
      if (e.data?.retryAfterSeconds) setCooldown(e.data.retryAfterSeconds);
      setError(errorMessage(e, 'Could not resend the code.'));
    }
  };

  const isEmail = method === 'email';

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

      {IS_DEMO && isEmail && (
        <Alert type="info">
          Demo: no real e-mail is sent. <button type="button" className="link-btn" onClick={() => window.dispatchEvent(new Event(OPEN_INBOX_EVENT))}>Open the Demo inbox</button> to read your code.
        </Alert>
      )}

      {error && <Alert type="error">{error}</Alert>}

      {useBackup ? (
        <form className="stack" onSubmit={(e) => { e.preventDefault(); if (backup.trim()) submit(backup.trim()); }} noValidate>
          <Field label="Backup code" value={backup} onChange={(e) => setBackup(e.target.value)} placeholder="xxxxx-xxxxx" autoComplete="off" autoCapitalize="none" spellCheck={false} hint="Each backup code works once." />
          <Button type="submit" loading={busy} disabled={!backup.trim()}>Verify backup code</Button>
        </form>
      ) : (
        <OtpInput value={code} onChange={setCode} onComplete={submit} disabled={busy} autoFocus error={undefined} />
      )}

      <label className="check">
        <input type="checkbox" checked={trust} onChange={(e) => setTrust(e.target.checked)} />
        <span>Trust this device for 30 days</span>
      </label>

      {!useBackup && (
        <Button loading={busy} disabled={code.length !== 6} onClick={() => submit(code)}>Verify and sign in</Button>
      )}

      <div className="row-between wrap">
        {isEmail ? (
          <Button variant="ghost" onClick={resend} disabled={cooldown > 0}>
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
