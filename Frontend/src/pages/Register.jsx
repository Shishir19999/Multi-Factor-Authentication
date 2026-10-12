import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { errorMessage, retryAfter } from '../api/errors';
import { useAuth, usePolicy, useToast } from '../context/contexts';
import { useCountdown } from '../hooks/useCountdown';
import { isEmail, passwordValid } from '../lib/password';
import AuthShell from '../components/auth/AuthShell';
import Alert from '../components/ui/Alert';
import Button from '../components/ui/Button';
import Field, { PasswordField } from '../components/ui/Field';
import { PasswordCreate } from '../components/ui/PasswordMeter';
import RetryNotice from '../components/ui/RetryNotice';

function Register() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { policy } = usePolicy();
  const { status } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [touched, setTouched] = useState({});
  const [formError, setFormError] = useState('');
  const [busy, setBusy] = useState(false);
  const [rateLeft, setRateLeft] = useCountdown(0);

  const errors = {
    email: !email.trim() ? 'Enter your e-mail address.' : !isEmail(email) ? 'Enter a valid e-mail address, for example you@example.com.' : '',
    password: !password ? 'Choose a password.' : !passwordValid(password, policy, { email }) ? 'The password does not meet all the rules below.' : '',
    confirm: !confirm ? 'Repeat the password.' : confirm !== password ? 'The passwords do not match.' : '',
  };
  const touch = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  const submit = async (e) => {
    e.preventDefault();
    setTouched({ email: true, password: true, confirm: true });
    setFormError('');
    if (errors.email || errors.password || errors.confirm || rateLeft > 0) return;
    setBusy(true);
    try {
      const res = await api.register({ email, password });
      toast('Account created. Sign in to continue.', 'success');
      if (res.warning) toast(res.warning, 'info');
      navigate('/login', { replace: true, state: { email: email.trim().toLowerCase() } });
    } catch (err) {
      setRateLeft(retryAfter(err));
      setFormError(errorMessage(err, 'Could not create the account.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell>
      <form className="stack" onSubmit={submit} noValidate>
        <div>
          <h1 className="auth-title">Create your account</h1>
          <p className="muted">Protect it with e-mail codes, an authenticator app or a passkey.</p>
        </div>
        {status === 'authed' && <Alert type="info">You are already signed in. <Link to="/dashboard">Open your dashboard</Link>.</Alert>}
        <RetryNotice seconds={rateLeft} title="Too many sign-up attempts from this connection." />
        {formError && rateLeft === 0 && <Alert type="error">{formError}</Alert>}
        <Field label="E-mail address" type="email" autoComplete="username" placeholder="you@example.com" value={email}
          onChange={(e) => setEmail(e.target.value)} onBlur={touch('email')} error={touched.email ? errors.email : ''} />
        <PasswordCreate label="Password" value={password} email={email} onChange={(e) => setPassword(e.target.value)} onBlur={touch('password')} error={touched.password ? errors.password : ''} />
        <PasswordField label="Confirm password" autoComplete="new-password" value={confirm}
          onChange={(e) => setConfirm(e.target.value)} onBlur={touch('confirm')} error={touched.confirm ? errors.confirm : ''} />
        <Button type="submit" loading={busy} disabled={rateLeft > 0}>Create account</Button>
        <p className="muted center">Already registered? <Link to="/login">Sign in</Link></p>
      </form>
    </AuthShell>
  );
}

export default Register;
