import { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { errorMessage } from '../api/errors';
import { IS_DEMO } from '../config';
import { useAuth, useToast } from '../context/contexts';
import { isEmail } from '../lib/password';
import AuthShell from '../components/auth/AuthShell';
import CodeStep from '../components/auth/CodeStep';
import DemoAccounts from '../components/demo/DemoAccounts';
import Alert from '../components/ui/Alert';
import Button from '../components/ui/Button';
import Field, { PasswordField } from '../components/ui/Field';

const mmss = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;

function Login() {
  const location = useLocation();
  const navigate = useNavigate();
  const { signIn } = useAuth();
  const { toast } = useToast();

  const [email, setEmail] = useState(location.state?.email || '');
  const [password, setPassword] = useState('');
  const [touched, setTouched] = useState({});
  const [formError, setFormError] = useState('');
  const [busy, setBusy] = useState(false);
  const [codeStep, setCodeStep] = useState(null); // { method, cooldown }
  const [lockLeft, setLockLeft] = useState(0);

  useEffect(() => {
    if (lockLeft <= 0) return undefined;
    const t = setTimeout(() => setLockLeft((s) => s - 1), 1000);
    return () => clearTimeout(t);
  }, [lockLeft]);

  const errors = {
    email: !email.trim() ? 'Enter your e-mail address.' : !isEmail(email) ? 'Enter a valid e-mail address, for example you@example.com.' : '',
    password: !password ? 'Enter your password.' : '',
  };

  const finish = ({ token, user }) => {
    signIn(token, user);
    toast('Signed in successfully.', 'success');
    navigate(location.state?.from?.pathname || '/dashboard', { replace: true });
  };

  const submit = async (e) => {
    e.preventDefault();
    setTouched({ email: true, password: true });
    setFormError('');
    if (errors.email || errors.password || lockLeft > 0) return;
    setBusy(true);
    try {
      const res = await api.login({ email, password });
      if (res.step === 'done') finish(res);
      else setCodeStep({ method: res.method, cooldown: res.resendCooldownSeconds || 0 });
    } catch (err) {
      if (err.data?.locked) setLockLeft(err.data.retryAfterSeconds || 900);
      const left = err.data?.attemptsLeft;
      setFormError(left ? `${errorMessage(err)} ${left} attempt${left === 1 ? '' : 's'} left before the account is locked for 15 minutes.` : errorMessage(err, 'Could not sign in.'));
    } finally {
      setBusy(false);
    }
  };

  const pick = (mail, pass) => {
    setEmail(mail);
    setPassword(pass);
    setTouched({});
    setFormError('');
    setLockLeft(0);
  };

  const aside = IS_DEMO ? <DemoAccounts onPick={pick} /> : null;

  if (codeStep) {
    return (
      <AuthShell aside={aside}>
        <CodeStep
          email={email}
          method={codeStep.method}
          initialCooldown={codeStep.cooldown}
          onSuccess={finish}
          onRestart={() => { setCodeStep(null); setPassword(''); }}
          onToast={toast}
        />
      </AuthShell>
    );
  }

  return (
    <AuthShell aside={aside}>
      <form className="stack" onSubmit={submit} noValidate>
        <div>
          <h1 className="auth-title">Welcome back</h1>
          <p className="muted">Sign in to manage your account security.</p>
        </div>

        {lockLeft > 0 && (
          <Alert type="warning">
            Too many failed attempts. The account is locked, try again in <strong>{mmss(lockLeft)}</strong> or <Link to="/recover">reset your password</Link>.
          </Alert>
        )}
        {formError && lockLeft === 0 && <Alert type="error">{formError}</Alert>}

        <Field
          label="E-mail address"
          type="email"
          autoComplete="username"
          placeholder="you@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          onBlur={() => setTouched((t) => ({ ...t, email: true }))}
          error={touched.email ? errors.email : ''}
        />
        <PasswordField
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onBlur={() => setTouched((t) => ({ ...t, password: true }))}
          error={touched.password ? errors.password : ''}
        />
        <div className="row-between wrap">
          <Link to="/recover">Forgot your password?</Link>
        </div>
        <Button type="submit" loading={busy} disabled={lockLeft > 0}>Sign in</Button>
        <p className="muted center">New here? <Link to="/register">Create an account</Link></p>
      </form>
    </AuthShell>
  );
}

export default Login;
