import { useState } from 'react';
import { api } from '../../api';
import { errorMessage } from '../../api/errors';
import { formatSecret } from '../../lib/totp';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { PasswordField } from '../ui/Field';
import Modal from '../ui/Modal';
import OtpInput from '../ui/OtpInput';
import QrCode from '../ui/QrCode';
import BackupCodes from './BackupCodes';

// Authenticator enrolment: password -> QR code + secret -> confirm a code -> save backup codes.
function TotpSetup({ open, email, onClose, onEnabled }) {
  const [step, setStep] = useState('password');
  const [password, setPassword] = useState('');
  const [setup, setSetup] = useState(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState([]);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const reset = () => {
    setStep('password'); setPassword(''); setSetup(null); setCode(''); setCodes([]); setSaved(false); setError('');
  };
  const close = () => {
    const done = step === 'codes';
    reset();
    onClose();
    if (done) onEnabled();
  };

  const start = async (e) => {
    e.preventDefault();
    if (!password) { setError('Enter your password to continue.'); return; }
    setBusy(true); setError('');
    try {
      setSetup(await api.totpSetup({ password }));
      setStep('scan');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const confirm = async (value) => {
    if (busy) return;
    setBusy(true); setError('');
    try {
      const res = await api.totpEnable({ code: value });
      setCodes(res.backupCodes);
      setStep('codes');
    } catch (err) {
      setError(errorMessage(err));
      setCode('');
    } finally {
      setBusy(false);
    }
  };

  let body;
  let footer = null;
  if (step === 'password') {
    body = (
      <form className="stack" onSubmit={start} noValidate>
        <p>Confirm your password to start setting up an authenticator app such as Google Authenticator.</p>
        {error && <Alert type="error">{error}</Alert>}
        <PasswordField label="Current password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
        <div className="row gap end">
          <Button variant="ghost" onClick={close}>Cancel</Button>
          <Button type="submit" loading={busy}>Continue</Button>
        </div>
      </form>
    );
  } else if (step === 'scan') {
    body = (
      <div className="stack">
        <ol className="plain-steps">
          <li>Open your authenticator app and choose <strong>Add account</strong> then <strong>Scan a QR code</strong>.</li>
          <li>Scan the code below, or enter the secret manually.</li>
          <li>Type the 6-digit code the app shows to confirm.</li>
        </ol>
        <div className="qr-row">
          <QrCode value={setup.otpauthUrl} label={`QR code for ${email}`} size={176} />
          <div>
            <p className="muted">Can&apos;t scan? Enter this secret (time-based, 6 digits):</p>
            <code className="secret">{formatSecret(setup.secret)}</code>
          </div>
        </div>
        {error && <Alert type="error">{error}</Alert>}
        <OtpInput value={code} onChange={setCode} onComplete={confirm} disabled={busy} label="Code from your app" autoFocus />
        <div className="row gap end">
          <Button variant="ghost" onClick={close}>Cancel</Button>
          <Button loading={busy} disabled={code.length !== 6} onClick={() => confirm(code)}>Verify and enable</Button>
        </div>
      </div>
    );
  } else {
    body = (
      <div className="stack">
        <Alert type="success">Authenticator app enabled. Save your backup codes now.</Alert>
        <BackupCodes codes={codes} email={email} />
        <label className="check">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          <span>I have saved my backup codes</span>
        </label>
      </div>
    );
    footer = <Button disabled={!saved} onClick={close}>Done</Button>;
  }

  return (
    <Modal open={open} title="Set up an authenticator app" onClose={step === 'codes' && !saved ? () => {} : close} footer={footer} wide>
      {body}
    </Modal>
  );
}

export default TotpSetup;
