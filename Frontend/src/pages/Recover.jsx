import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { errorMessage, retryAfter } from '../api/errors';
import { IS_PREVIEW } from '../config';
import { usePolicy, useToast } from '../context/contexts';
import { useCountdown } from '../hooks/useCountdown';
import { isEmail, passwordValid } from '../lib/password';
import AuthShell from '../components/auth/AuthShell';
import { OPEN_INBOX_EVENT } from '../components/preview/PreviewInbox';
import Alert from '../components/ui/Alert';
import Button from '../components/ui/Button';
import Field, { PasswordField } from '../components/ui/Field';
import OtpInput from '../components/ui/OtpInput';
import { PasswordCreate } from '../components/ui/PasswordMeter';
import RetryNotice from '../components/ui/RetryNotice';

// Account recovery: e-mail a code (also to a verified recovery address), then choose a new password.
// "Ask an administrator" is the last resort when the mailbox is not reachable. Existing sessions are signed out.
function Recover() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { policy } = usePolicy();
  const [step, setStep] = useState('request');
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [message, setMessage] = useState('');
  const [touched, setTouched] = useState({});
  const [formError, setFormError] = useState('');
  const [assistDone, setAssistDone] = useState('');
  const [busy, setBusy] = useState(false);
  const [rateLeft, setRateLeft] = useCountdown(0);

  const errors = {
    email: !email.trim() ? 'Enter your e-mail address.' : !isEmail(email) ? 'Enter a valid e-mail address, for example you@example.com.' : '',
    code: code.length !== 6 ? 'Enter the 6-digit recovery code.' : '',
    password: !passwordValid(password, policy, { email }) ? 'The password does not meet all the rules below.' : '',
    confirm: confirm !== password ? 'The passwords do not match.' : '',
  };
  const touch = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  const run = async (fn, onOk) => {
    setFormError('');
    setBusy(true);
    try {
      await fn();
      onOk();
    } catch (err) {
      setRateLeft(retryAfter(err));
      setFormError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const request = (e) => {
    e.preventDefault();
    setTouched({ email: true });
    if (errors.email) return;
    run(() => api.recoverRequest({ email }), () => { setStep('reset'); setTouched({}); });
  };

  const reset = (e) => {
    e.preventDefault();
    setTouched({ code: true, password: true, confirm: true });
    if (errors.code || errors.password || errors.confirm) return;
    run(() => api.recoverReset({ email, code, newPassword: password }), () => {
      toast('Password updated. Sign in with the new password.', 'success');
      navigate('/login', { replace: true, state: { email: email.trim().toLowerCase() } });
    });
  };

  const assist = (e) => {
    e.preventDefault();
    setTouched({ email: true });
    if (errors.email) return;
    run(async () => setAssistDone((await api.recoverAssist({ email, message })).message), () => {});
  };

  if (step === 'request') {
    return (
      <AuthShell>
        <form className="stack" onSubmit={request} noValidate>
          <div>
            <h1 className="auth-title">Recover your account</h1>
            <p className="muted">Enter your e-mail address and we will send a recovery code. If you added a recovery e-mail, the code goes there too.</p>
          </div>
          <RetryNotice seconds={rateLeft} title="Too many recovery requests from this connection." />
          {formError && rateLeft === 0 && <Alert type="error">{formError}</Alert>}
          <Field label="E-mail address" type="email" autoComplete="username" placeholder="you@example.com" value={email}
            onChange={(e) => setEmail(e.target.value)} onBlur={touch('email')} error={touched.email ? errors.email : ''} />
          <Button type="submit" loading={busy} disabled={rateLeft > 0}>Send recovery code</Button>

          <details className="assist">
            <summary>I cannot read my e-mail: ask an administrator</summary>
            <div className="stack">
              <p className="muted">An administrator can check your identity and send you a recovery code or reset your second step. Locked by an administrator? Use this too.</p>
              <Field label="Note for the administrator (optional)" value={message} maxLength={300} onChange={(e) => setMessage(e.target.value)} placeholder="For example: I lost my phone" />
              {assistDone && <Alert type="success">{assistDone}</Alert>}
              <Button variant="secondary" loading={busy} onClick={assist} disabled={rateLeft > 0}>Ask an administrator for help</Button>
            </div>
          </details>
          <p className="muted center"><Link to="/login">Back to sign in</Link></p>
        </form>
      </AuthShell>
    );
  }

  return (
    <AuthShell>
      <form className="stack" onSubmit={reset} noValidate>
        <div>
          <h1 className="auth-title">Choose a new password</h1>
          <p className="muted">If an account exists for <strong>{email}</strong>, a 6-digit code is on its way. It is valid for 15 minutes.</p>
        </div>
        {IS_PREVIEW && (
          <Alert type="info">
            Live preview: <button type="button" className="link-btn" onClick={() => window.dispatchEvent(new Event(OPEN_INBOX_EVENT))}>open the Preview inbox</button> to read the code.
          </Alert>
        )}
        <RetryNotice seconds={rateLeft} title="Too many attempts from this connection." />
        {formError && rateLeft === 0 && <Alert type="error">{formError}</Alert>}
        <OtpInput value={code} onChange={setCode} label="Recovery code" error={touched.code ? errors.code : ''} autoFocus />
        <PasswordCreate label="New password" value={password} email={email} onChange={(e) => setPassword(e.target.value)} onBlur={touch('password')} error={touched.password ? errors.password : ''} />
        <PasswordField label="Confirm new password" autoComplete="new-password" value={confirm}
          onChange={(e) => setConfirm(e.target.value)} onBlur={touch('confirm')} error={touched.confirm ? errors.confirm : ''} />
        <Button type="submit" loading={busy} disabled={rateLeft > 0}>Reset password</Button>
        <button type="button" className="link-btn" onClick={() => { setStep('request'); setCode(''); }}>Use a different e-mail address</button>
      </form>
    </AuthShell>
  );
}

export default Recover;
