import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { errorMessage } from '../api/errors';
import { useToast } from '../context/contexts';
import { isEmail, passwordValid } from '../lib/password';
import AuthShell from '../components/auth/AuthShell';
import Alert from '../components/ui/Alert';
import Button from '../components/ui/Button';
import Field, { PasswordField } from '../components/ui/Field';
import PasswordMeter from '../components/ui/PasswordMeter';

function Register() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [touched, setTouched] = useState({});
  const [formError, setFormError] = useState('');
  const [busy, setBusy] = useState(false);

  const errors = {
    email: !email.trim() ? 'Enter your e-mail address.' : !isEmail(email) ? 'Enter a valid e-mail address, for example you@example.com.' : '',
    password: !password ? 'Choose a password.' : !passwordValid(password) ? 'The password does not meet all the rules below.' : '',
    confirm: confirm !== password ? 'The passwords do not match.' : !confirm ? 'Repeat the password.' : '',
  };
  const touch = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  const submit = async (e) => {
    e.preventDefault();
    setTouched({ email: true, password: true, confirm: true });
    setFormError('');
    if (errors.email || errors.password || errors.confirm) return;
    setBusy(true);
    try {
      await api.register({ email, password });
      toast('Account created. Sign in to continue.', 'success');
      navigate('/login', { replace: true, state: { email: email.trim().toLowerCase() } });
    } catch (err) {
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
          <p className="muted">Protect it with e-mail codes or an authenticator app.</p>
        </div>
        {formError && <Alert type="error">{formError}</Alert>}
        <Field label="E-mail address" type="email" autoComplete="username" placeholder="you@example.com" value={email}
          onChange={(e) => setEmail(e.target.value)} onBlur={touch('email')} error={touched.email ? errors.email : ''} />
        <div>
          <PasswordField label="Password" autoComplete="new-password" value={password}
            onChange={(e) => setPassword(e.target.value)} onBlur={touch('password')} error={touched.password ? errors.password : ''} />
          <PasswordMeter password={password} />
        </div>
        <PasswordField label="Confirm password" autoComplete="new-password" value={confirm}
          onChange={(e) => setConfirm(e.target.value)} onBlur={touch('confirm')} error={touched.confirm ? errors.confirm : ''} />
        <Button type="submit" loading={busy}>Create account</Button>
        <p className="muted center">Already registered? <Link to="/login">Sign in</Link></p>
      </form>
    </AuthShell>
  );
}

export default Register;
