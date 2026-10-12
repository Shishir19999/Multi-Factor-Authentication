import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import { errorMessage } from '../api/errors';
import { useAuth } from '../context/contexts';
import AuthShell from '../components/auth/AuthShell';
import Alert from '../components/ui/Alert';
import Button from '../components/ui/Button';

// "Was this you?" page opened from the sign-in alert e-mail. Works without being signed in.
function Review() {
  const [params] = useSearchParams();
  const token = params.get('t') || '';
  const { status } = useAuth();
  const [result, setResult] = useState(null); // 'confirmed' | 'denied'
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');

  const answer = async (a) => {
    setBusy(a); setError('');
    try {
      const res = await api.alertRespondByLink({ t: token, answer: a });
      setResult(res.status);
    } catch (e) {
      setError(errorMessage(e, 'Could not record your answer.'));
    } finally {
      setBusy('');
    }
  };

  return (
    <AuthShell>
      <div className="stack">
        <div>
          <h1 className="auth-title">Was this you?</h1>
          <p className="muted">We e-mailed you because your account was used from a device or place we had not seen before.</p>
        </div>
        {!token && <Alert type="error">This review link is incomplete. Open the link from the e-mail again.</Alert>}
        {error && <Alert type="error">{error}</Alert>}
        {result === 'confirmed' && <Alert type="success">Thanks. We marked this sign-in as yours.</Alert>}
        {result === 'denied' && (
          <Alert type="warning">
            We signed out every session and will ask for a new password the next time you sign in. <Link to="/recover">Reset your password now</Link>.
          </Alert>
        )}
        {!result && token && (
          <div className="stack">
            <Button loading={busy === 'yes'} disabled={!!busy} onClick={() => answer('yes')}>Yes, it was me</Button>
            <Button variant="danger" loading={busy === 'no'} disabled={!!busy} onClick={() => answer('no')}>No, secure my account</Button>
            <p className="hint">&quot;No&quot; signs out every session, forgets trusted devices and requires a new password.</p>
          </div>
        )}
        <p className="muted center"><Link to={status === 'authed' ? '/dashboard' : '/login'}>{status === 'authed' ? 'Open your dashboard' : 'Go to sign in'}</Link></p>
      </div>
    </AuthShell>
  );
}

export default Review;
