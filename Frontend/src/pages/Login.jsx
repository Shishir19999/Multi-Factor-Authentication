import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { errorMessage, retryAfter } from '../api/errors';
import { IS_PREVIEW } from '../config';
import { useAuth, useToast } from '../context/contexts';
import { useCountdown } from '../hooks/useCountdown';
import { isEmail } from '../lib/password';
import { passkeySignIn } from '../lib/passkeyFlows';
import { passkeyErrorMessage } from '../lib/webauthnClient';
import { canSimulate, realAvailable } from '../lib/passkeyMode';
import AuthShell from '../components/auth/AuthShell';
import CodeStep from '../components/auth/CodeStep';
import PreviewAccounts from '../components/preview/PreviewAccounts';
import Alert from '../components/ui/Alert';
import Button from '../components/ui/Button';
import Field, { PasswordField } from '../components/ui/Field';
import RetryNotice from '../components/ui/RetryNotice';

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
  const [codeStep, setCodeStep] = useState(null); // { method, cooldown, passkeys }
  const [lockLeft, setLockLeft] = useCountdown(0);
  const [rateLeft, setRateLeft] = useCountdown(0);
  const [adminLocked, setAdminLocked] = useState(false);

  const errors = {
    email: !email.trim() ? 'Enter your e-mail address.' : !isEmail(email) ? 'Enter a valid e-mail address, for example you@example.com.' : '',
    password: !password ? 'Enter your password.' : '',
  };

  const finish = ({ token, user, alert }) => {
    signIn(token, user);
    toast('Signed in successfully.', 'success');
    if (alert) toast(`We noticed a new ${alert.level === 'high' ? 'device and location' : 'device or location'}. A "was this you?" e-mail was sent and the alert is on your dashboard.`, 'info');
    navigate(location.state?.from?.pathname || '/dashboard', { replace: true });
  };

  const handleError = (err, fallback) => {
    setAdminLocked(!!err.data?.adminLocked);
    if (err.data?.locked && !err.data?.adminLocked) setLockLeft(err.data.retryAfterSeconds || 900);
    if (err.status === 429) setRateLeft(retryAfter(err));
    const left = err.data?.attemptsLeft;
    setFormError(left
      ? `${errorMessage(err)} ${left} attempt${left === 1 ? '' : 's'} left before the account is locked.`
      : errorMessage(err, fallback));
  };

  const submit = async (e) => {
    e.preventDefault();
    setTouched({ email: true, password: true });
    setFormError('');
    if (errors.email || errors.password || lockLeft > 0 || rateLeft > 0) return;
    setBusy(true);
    try {
      const res = await api.login({ email, password });
      if (res.step === 'done') finish(res);
      else setCodeStep({ method: res.method, cooldown: res.resendCooldownSeconds || 0, passkeys: !!res.passkeys });
    } catch (err) {
      handleError(err, 'Could not sign in.');
    } finally {
      setBusy(false);
    }
  };

  const withPasskey = async () => {
    setFormError('');
    setBusy(true);
    try {
      finish(await passkeySignIn({ purpose: 'login' }));
    } catch (err) {
      if (err.name === 'ApiError') handleError(err, 'Could not sign in with a passkey.');
      else setFormError(passkeyErrorMessage(err));
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
    setRateLeft(0);
    setAdminLocked(false);
  };

  const aside = IS_PREVIEW ? <PreviewAccounts onPick={pick} /> : null;
  const passkeysUsable = realAvailable() || canSimulate;

  if (codeStep) {
    return (
      <AuthShell aside={aside}>
        <CodeStep
          email={email}
          method={codeStep.method}
          passkeys={codeStep.passkeys}
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

        <RetryNotice seconds={lockLeft} title="The account is locked after too many failed attempts.">
          You can also <Link to="/recover">reset your password</Link>.
        </RetryNotice>
        <RetryNotice seconds={rateLeft} title="Too many sign-in attempts from this connection." />
        {formError && lockLeft === 0 && rateLeft === 0 && (
          <Alert type="error">
            {formError}
            {adminLocked && <> <Link to="/recover">Ask an administrator for help</Link>.</>}
          </Alert>
        )}

        <Field
          label="E-mail address"
          type="email"
          autoComplete="username webauthn"
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
        <Button type="submit" loading={busy} disabled={lockLeft > 0 || rateLeft > 0}>Sign in</Button>
        {passkeysUsable && (
          <>
            <p className="divider"><span>or</span></p>
            <Button variant="secondary" disabled={busy} onClick={withPasskey}>Sign in with a passkey</Button>
          </>
        )}
        <p className="muted center">New here? <Link to="/register">Create an account</Link></p>
      </form>
    </AuthShell>
  );
}

export default Login;
