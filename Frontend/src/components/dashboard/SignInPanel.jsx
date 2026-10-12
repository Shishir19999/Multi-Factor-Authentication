import { useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { useAuth, useConfirm, usePolicy, useToast } from '../../context/contexts';
import { METHOD_LABELS } from '../../lib/format';
import Button from '../ui/Button';
import Modal from '../ui/Modal';
import { ErrorState, Loading } from '../ui/States';
import BackupCodes from './BackupCodes';
import PasskeyList from './PasskeyList';
import TotpSetup from './TotpSetup';

const OPTIONS = [
  { id: 'email', title: 'E-mail code', text: 'We e-mail a 6-digit code each time you sign in on a new device.' },
  { id: 'totp', title: 'Authenticator app', text: 'Use Google Authenticator or a compatible app. Works offline and comes with backup codes.' },
  { id: 'none', title: 'Off', text: 'Password only. Not recommended.' },
];

// Everything about how you prove it is you: code method, passkeys, backup codes and trusted devices.
// Sensitive changes ask for a recent confirmation through the step-up dialog (handled by the API layer).
function SignInPanel({ security, error, reload, email, onChange, onRequirementsChanged }) {
  const { toast } = useToast();
  const { confirm } = useConfirm();
  const { user } = useAuth();
  const { policy } = usePolicy();
  const [setupOpen, setSetupOpen] = useState(false);
  const [newCodes, setNewCodes] = useState(null);

  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!security) return <Loading label="Loading sign-in methods" lines={5} />;
  const current = security.twoFactorMethod;
  const required = policy.twoFactor.required === 'everyone' || (policy.twoFactor.required === 'admins' && user?.role === 'admin');
  const lockedOn = required && security.passkeys === 0;
  const allowed = (id) => id === 'none' ? !lockedOn : policy.twoFactor.methods.includes(id);

  const refreshAll = () => { reload(); onRequirementsChanged?.(); };

  const choose = async (id) => {
    if (id === current) return;
    if (id === 'totp') { setSetupOpen(true); return; }
    const ok = await confirm({
      title: id === 'none' ? 'Turn off the code step?' : 'Switch to e-mail codes?',
      message: id === 'none'
        ? 'Anyone with your password will be able to sign in (unless you have a passkey). Your authenticator app and backup codes will stop working.'
        : 'Your authenticator app and backup codes will stop working and codes will be e-mailed instead.',
      confirmLabel: id === 'none' ? 'Turn off' : 'Switch to e-mail',
      danger: id === 'none',
    });
    if (!ok) return;
    try {
      onChange(await api.setMethod({ method: id }));
      toast(id === 'none' ? 'The code step is off.' : 'E-mail codes are now your second step.', 'success');
      refreshAll();
    } catch (e) {
      if (!isCancelled(e)) toast(errorMessage(e), 'error');
    }
  };

  const regenerate = async () => {
    try {
      setNewCodes(await api.regenerateBackupCodes());
      toast('New backup codes created. The old ones no longer work.', 'success');
      reload();
    } catch (e) {
      if (!isCancelled(e)) toast(errorMessage(e), 'error');
    }
  };

  const forgetDevices = async () => {
    const ok = await confirm({
      title: 'Forget trusted devices?',
      message: 'Every device will have to enter a code again the next time it signs in.',
      confirmLabel: 'Forget devices',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.revokeTrustedDevices();
      toast('Trusted devices forgotten.', 'success');
      reload();
    } catch (e) {
      if (!isCancelled(e)) toast(errorMessage(e), 'error');
    }
  };

  return (
    <div className="stack-lg">
      <section className="card" aria-labelledby="tf-method">
        <h2 id="tf-method">Second step (code)</h2>
        <p className="muted">Current method: <strong>{METHOD_LABELS[current]}</strong>{security.passkeys > 0 && <> · {security.passkeys} passkey{security.passkeys === 1 ? '' : 's'}</>}</p>
        {required && <p className="muted">Your organisation requires two-step verification, so it cannot be turned off{security.passkeys > 0 ? '' : ' unless you add a passkey'}.</p>}
        <div className="options" role="radiogroup" aria-labelledby="tf-method">
          {OPTIONS.map((o) => (
            <div key={o.id} className={`option${current === o.id ? ' selected' : ''}`}>
              <div>
                <h3>{o.title}{current === o.id && <span className="pill pill-ok">Current</span>}</h3>
                <p>{o.text}</p>
              </div>
              {current !== o.id && (
                <Button variant={o.id === 'none' ? 'danger' : 'secondary'} disabled={!allowed(o.id)} onClick={() => choose(o.id)}>
                  {o.id === 'totp' ? 'Set up' : o.id === 'none' ? 'Turn off' : 'Use this'}
                  <span className="sr-only"> {o.title}</span>
                </Button>
              )}
              {current !== o.id && !allowed(o.id) && <p className="hint">Not available under the current security policy.</p>}
            </div>
          ))}
        </div>
      </section>

      <PasskeyList onChanged={refreshAll} />

      {current === 'totp' && (
        <section className="card" aria-labelledby="tf-backup">
          <h2 id="tf-backup">Backup codes</h2>
          <p>{security.backupCodesRemaining} of 10 codes remaining. Use one when you cannot reach your authenticator app.</p>
          <Button variant="secondary" onClick={regenerate}>Generate new codes</Button>
        </section>
      )}

      <section className="card" aria-labelledby="tf-trust">
        <h2 id="tf-trust">Trusted devices</h2>
        <p>
          {policy.trustedDeviceDays === 0
            ? 'Trusted devices are switched off by the security policy.'
            : security.trustedDevices === 0
              ? `No device is trusted. Tick "Trust this device" when you sign in to skip the code for ${policy.trustedDeviceDays} days.`
              : `${security.trustedDevices} trusted device${security.trustedDevices === 1 ? '' : 's'} can skip the second step.`}
        </p>
        <Button variant="secondary" disabled={security.trustedDevices === 0} onClick={forgetDevices}>Forget trusted devices</Button>
      </section>

      <TotpSetup
        open={setupOpen}
        email={email}
        onClose={() => setSetupOpen(false)}
        onEnabled={() => { toast('Authenticator app enabled.', 'success'); refreshAll(); }}
      />
      <Modal open={!!newCodes} title="Your new backup codes" onClose={() => setNewCodes(null)} footer={<Button onClick={() => setNewCodes(null)}>Done</Button>}>
        {newCodes && <BackupCodes codes={newCodes} email={email} />}
      </Modal>
    </div>
  );
}

export default SignInPanel;
