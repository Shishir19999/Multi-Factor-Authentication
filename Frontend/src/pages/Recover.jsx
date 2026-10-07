import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { errorMessage } from '../api/errors';
import { IS_DEMO } from '../config';
import { useToast } from '../context/contexts';
import { isEmail, passwordValid } from '../lib/password';
import AuthShell from '../components/auth/AuthShell';
import { OPEN_INBOX_EVENT } from '../components/demo/DemoInbox';
import Alert from '../components/ui/Alert';
import Button from '../components/ui/Button';
import Field, { PasswordField } from '../components/ui/Field';
import OtpInput from '../components/ui/OtpInput';
import PasswordMeter from '../components/ui/PasswordMeter';

// Account recovery: e-mail a code, then choose a new password. Existing sessions are signed out.
function Recover() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [step, setStep] = useState('request');
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [touched, setTouched] = useState({});
  const [formError, setFormError] = useState('');
  const [busy, setBusy] = useState(false);

  const errors = {
    email: !email.trim() ? 'Enter your e-mail address.' : !isEmail(email) ? 'Enter a valid e-mail address, for example you@example.com.' : '',
    code: code.length !== 6 ? 'Enter the 6-digit recovery code.' : '',
    password: !passwordValid(password) ? 'The password does not meet all the rules below.' : '',
    confirm: confirm !== password ? 'The passwords do not match.' : '',
  };

  const request = async (e) => {
    e.preventDefault();
    setTouched({ email: true });
    setFormError('');
    if (errors.email) return;
    setBusy(true);
    try {
      await api.recoverRequest({ email });
      setStep('reset');
      setTouched({});
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const reset = async (e) => {
    e.preventDefault();
    setTouched({ code: true, password: true, confirm: true });
    setFormError('');
    if (errors.code || errors.password || errors.confirm) return;
    setBusy(true);
    try {
      await api.recoverReset({ email, code, newPassword: password });
      toast('Password updated. Sign in with the new password.', 'success');
      navigate('/login', { replace: true, state: { email: email.trim().toLowerCase() } });
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const touch = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  if (step === 'request') {
    return (
      <AuthShell>
        <form className="stack" onSubmit={request} noValidate>
          <div>
            <h1 className="auth-title">Recover your account</h1>
            <p className="muted">Enter your e-mail address and we will send a recovery code.</p>
          </div>
          {formError && <Alert type="error">{formError}</Alert>}
          <Field label="E-mail address" type="email" autoComplete="username" placeholder="you@example.com" value={email}
            onChange={(e) => setEmail(e.target.value)} onBlur={touch('email')} error={touched.email ? errors.email : ''} />
          <Button type="submit" loading={busy}>Send recovery code</Button>
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
        {IS_DEMO && (
          <Alert type="info">
            Demo: <button type="button" className="link-btn" onClick={() => window.dispatchEvent(new Event(OPEN_INBOX_EVENT))}>open the Demo inbox</button> to read the code.
          </Alert>
        )}
        {formError && <Alert type="error">{formError}</Alert>}
        <OtpInput value={code} onChange={setCode} label="Recovery code" error={touched.code ? errors.code : ''} autoFocus />
        <div>
          <PasswordField label="New password" autoComplete="new-password" value={password}
            onChange={(e) => setPassword(e.target.value)} onBlur={touch('password')} error={touched.password ? errors.password : ''} />
          <PasswordMeter password={password} />
        </div>
        <PasswordField label="Confirm new password" autoComplete="new-password" value={confirm}
          onChange={(e) => setConfirm(e.target.value)} onBlur={touch('confirm')} error={touched.confirm ? errors.confirm : ''} />
        <Button type="submit" loading={busy}>Reset password</Button>
        <button type="button" className="link-btn" onClick={() => { setStep('request'); setCode(''); }}>Use a different e-mail address</button>
      </form>
    </AuthShell>
  );
}

export default Recover;
