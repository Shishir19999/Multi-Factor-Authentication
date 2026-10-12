import { useEffect, useState } from 'react';
import { api, setStepUpHandler } from '../../api';
import { CancelledError, errorMessage } from '../../api/errors';
import { passkeyStepUp } from '../../lib/passkeyFlows';
import { passkeyErrorMessage } from '../../lib/webauthnClient';
import { usePolicy } from '../../context/contexts';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { PasswordField } from '../ui/Field';
import Modal from '../ui/Modal';
import OtpInput from '../ui/OtpInput';

// Step-up re-authentication. The API layer opens this whenever a sensitive action needs a recent confirmation
// (password, authenticator code or passkey) and retries the action once it succeeds.
function StepUpDialog() {
  const { policy } = usePolicy();
  const [state, setState] = useState(null); // { methods, resolve, reject }
  const [mode, setMode] = useState('password');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setStepUpHandler((methods) => new Promise((resolve, reject) => {
      setPassword(''); setCode(''); setError(''); setMode('password');
      setState({ methods: methods || { password: true }, resolve, reject });
    }));
    return () => setStepUpHandler(null);
  }, []);

  if (!state) return null;

  const cancel = () => { state.reject(new CancelledError()); setState(null); };
  const done = () => { state.resolve(true); setState(null); };

  const run = async (fn, fallback) => {
    setBusy(true); setError('');
    try {
      await fn();
      done();
    } catch (e) {
      setError(e.name === 'ApiError' ? errorMessage(e) : passkeyErrorMessage(e) || fallback);
      setCode('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open title="Confirm it is you" onClose={cancel}>
      <div className="stack">
        <p>For your security, confirm your identity to continue. This stays valid for {policy.session.stepUpMinutes} minutes.</p>
        {error && <Alert type="error">{error}</Alert>}
        {mode === 'password' ? (
          <form className="stack" onSubmit={(e) => { e.preventDefault(); if (!password) { setError('Enter your password to continue.'); return; } run(() => api.stepUp({ password })); }} noValidate>
            <PasswordField label="Current password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
            <div className="row gap end wrap">
              <Button variant="ghost" onClick={cancel}>Cancel</Button>
              <Button type="submit" loading={busy}>Confirm</Button>
            </div>
          </form>
        ) : (
          <div className="stack">
            <OtpInput value={code} onChange={setCode} onComplete={(c) => run(() => api.stepUp({ code: c }))} label="Code from your authenticator app" disabled={busy} autoFocus />
            <p className="hint">Open your authenticator app and enter the current code.</p>
            <div className="row gap end wrap">
              <Button variant="ghost" onClick={cancel}>Cancel</Button>
              <Button loading={busy} disabled={code.length !== 6} onClick={() => run(() => api.stepUp({ code }))}>Confirm</Button>
            </div>
          </div>
        )}
        {(state.methods.totp || state.methods.passkey) && (
          <div className="row gap wrap stepup-alt">
            {mode === 'password' && state.methods.totp && <button type="button" className="link-btn" onClick={() => { setMode('code'); setError(''); }}>Use an authenticator code instead</button>}
            {mode === 'code' && <button type="button" className="link-btn" onClick={() => { setMode('password'); setError(''); }}>Use my password instead</button>}
            {state.methods.passkey && <button type="button" className="link-btn" onClick={() => run(passkeyStepUp)}>Use a passkey instead</button>}
          </div>
        )}
      </div>
    </Modal>
  );
}

export default StepUpDialog;
