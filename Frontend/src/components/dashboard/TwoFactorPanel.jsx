import { useState } from 'react';
import { api } from '../../api';
import { useConfirm, useToast } from '../../context/contexts';
import { METHOD_LABELS } from '../../lib/format';
import Button from '../ui/Button';
import { ErrorState, Loading } from '../ui/States';
import Modal from '../ui/Modal';
import BackupCodes from './BackupCodes';
import PasswordPrompt from './PasswordPrompt';
import TotpSetup from './TotpSetup';

const OPTIONS = [
  { id: 'email', title: 'E-mail code', text: 'We e-mail a 6-digit code each time you sign in on a new device.' },
  { id: 'totp', title: 'Authenticator app', text: 'Use Google Authenticator or a compatible app. Works offline and comes with backup codes.' },
  { id: 'none', title: 'Off', text: 'Password only. Not recommended.' },
];

function TwoFactorPanel({ security, error, reload, email, onChange }) {
  const { toast } = useToast();
  const { confirm } = useConfirm();
  const [prompt, setPrompt] = useState(null); // { kind: 'email' | 'none' | 'regen' }
  const [setupOpen, setSetupOpen] = useState(false);
  const [newCodes, setNewCodes] = useState(null);

  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!security) return <Loading label="Loading two-step settings" lines={5} />;
  const current = security.twoFactorMethod;

  const choose = async (id) => {
    if (id === current) return;
    if (id === 'totp') { setSetupOpen(true); return; }
    const ok = await confirm({
      title: id === 'none' ? 'Turn off two-step verification?' : 'Switch to e-mail codes?',
      message: id === 'none'
        ? 'Anyone with your password will be able to sign in. Your authenticator app and backup codes will stop working.'
        : 'Your authenticator app and backup codes will stop working and codes will be e-mailed instead.',
      confirmLabel: id === 'none' ? 'Turn off' : 'Switch to e-mail',
      danger: id === 'none',
    });
    if (ok) setPrompt({ kind: id });
  };

  const submitPrompt = async (password) => {
    if (prompt.kind === 'regen') {
      setNewCodes(await api.regenerateBackupCodes({ password }));
      toast('New backup codes created. The old ones no longer work.', 'success');
    } else {
      const sec = await api.setMethod({ method: prompt.kind, password });
      onChange(sec);
      toast(prompt.kind === 'none' ? 'Two-step verification turned off.' : 'E-mail codes are now your second factor.', 'success');
    }
    setPrompt(null);
    reload();
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
      toast(e.message, 'error');
    }
  };

  const promptCopy = {
    email: { title: 'Confirm with your password', confirmLabel: 'Switch to e-mail codes' },
    none: { title: 'Confirm with your password', confirmLabel: 'Turn off', danger: true },
    regen: { title: 'Generate new backup codes', confirmLabel: 'Generate codes', description: 'The existing backup codes will stop working.' },
  }[prompt?.kind] || {};

  return (
    <div className="stack-lg">
      <section className="card" aria-labelledby="tf-method">
        <h2 id="tf-method">Second factor</h2>
        <p className="muted">Current method: <strong>{METHOD_LABELS[current]}</strong></p>
        <div className="options" role="radiogroup" aria-labelledby="tf-method">
          {OPTIONS.map((o) => (
            <div key={o.id} className={`option${current === o.id ? ' selected' : ''}`}>
              <div>
                <h3>{o.title}{current === o.id && <span className="pill pill-ok">Current</span>}</h3>
                <p>{o.text}</p>
              </div>
              {current !== o.id && (
                <Button variant={o.id === 'none' ? 'danger' : 'secondary'} onClick={() => choose(o.id)}>
                  {o.id === 'totp' ? 'Set up' : o.id === 'none' ? 'Turn off' : 'Use this'}
                  <span className="sr-only"> {o.title}</span>
                </Button>
              )}
            </div>
          ))}
        </div>
      </section>

      {current === 'totp' && (
        <section className="card" aria-labelledby="tf-backup">
          <h2 id="tf-backup">Backup codes</h2>
          <p>{security.backupCodesRemaining} of 10 codes remaining. Use one when you cannot reach your authenticator app.</p>
          <Button variant="secondary" onClick={() => setPrompt({ kind: 'regen' })}>Generate new codes</Button>
        </section>
      )}

      <section className="card" aria-labelledby="tf-trust">
        <h2 id="tf-trust">Trusted devices</h2>
        <p>{security.trustedDevices === 0 ? 'No device is trusted. Tick "Trust this device" when you sign in to skip the code for 30 days.' : `${security.trustedDevices} trusted device${security.trustedDevices === 1 ? '' : 's'} can skip the second step.`}</p>
        <Button variant="secondary" disabled={security.trustedDevices === 0} onClick={forgetDevices}>Forget trusted devices</Button>
      </section>

      <PasswordPrompt
        open={!!prompt}
        {...promptCopy}
        onSubmit={submitPrompt}
        onClose={() => setPrompt(null)}
      />
      <TotpSetup
        open={setupOpen}
        email={email}
        onClose={() => setSetupOpen(false)}
        onEnabled={() => { toast('Authenticator app enabled.', 'success'); reload(); }}
      />
      <Modal open={!!newCodes} title="Your new backup codes" onClose={() => setNewCodes(null)} footer={<Button onClick={() => setNewCodes(null)}>Done</Button>}>
        {newCodes && <BackupCodes codes={newCodes} email={email} />}
      </Modal>
    </div>
  );
}

export default TwoFactorPanel;
