import { useEffect, useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { formatSecret } from '../../lib/totp';
import { useToast } from '../../context/contexts';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Modal from '../ui/Modal';
import OtpInput from '../ui/OtpInput';
import QrCode from '../ui/QrCode';
import { Loading } from '../ui/States';
import BackupCodes from './BackupCodes';

// Authenticator enrolment: (step-up) -> QR code + secret -> confirm a code -> save backup codes.
function TotpSetup({ open, email, onClose, onEnabled }) {
  const { toast } = useToast();
  const [step, setStep] = useState('scan');
  const [setup, setSetup] = useState(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState([]);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return undefined;
    let cancelled = false;
    (async () => {
      try {
        const s = await api.totpSetup();
        if (!cancelled) setSetup(s);
      } catch (e) {
        if (cancelled) return;
        if (!isCancelled(e)) toast(errorMessage(e), 'error');
        onClose();
      }
    })();
    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const reset = () => { setStep('scan'); setSetup(null); setCode(''); setCodes([]); setSaved(false); setError(''); };
  const close = () => {
    const done = step === 'codes';
    reset();
    onClose();
    if (done) onEnabled();
  };

  const confirm = async (value) => {
    if (busy) return;
    setBusy(true); setError('');
    try {
      const res = await api.totpEnable({ code: value });
      setCodes(res.backupCodes);
      setStep('codes');
    } catch (err) {
      if (!isCancelled(err)) setError(errorMessage(err));
      setCode('');
    } finally {
      setBusy(false);
    }
  };

  let body;
  let footer = null;
  if (step === 'scan') {
    body = !setup ? <Loading label="Preparing your authenticator setup" lines={4} /> : (
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
