import { useState } from 'react';
import { api } from '../../api';
import { errorMessage } from '../../api/errors';
import { useToast } from '../../context/contexts';
import { passwordValid } from '../../lib/password';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { PasswordField } from '../ui/Field';
import PasswordMeter from '../ui/PasswordMeter';

function PasswordPanel({ onChanged }) {
  const { toast } = useToast();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [touched, setTouched] = useState({});
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const errors = {
    current: !current ? 'Enter your current password.' : '',
    next: !passwordValid(next) ? 'The new password does not meet all the rules below.' : next === current ? 'Choose a password different from the current one.' : '',
    confirm: confirm !== next ? 'The passwords do not match.' : '',
  };
  const touch = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  const submit = async (e) => {
    e.preventDefault();
    setTouched({ current: true, next: true, confirm: true });
    setError('');
    if (errors.current || errors.next || errors.confirm) return;
    setBusy(true);
    try {
      await api.changePassword({ currentPassword: current, newPassword: next });
      toast('Password changed. Your other sessions were signed out.', 'success');
      setCurrent(''); setNext(''); setConfirm(''); setTouched({});
      onChanged?.();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card narrow" aria-labelledby="pw-title">
      <h2 id="pw-title">Change password</h2>
      <p className="muted">Changing your password signs out every other session and forgets trusted devices.</p>
      <form className="stack" onSubmit={submit} noValidate>
        {error && <Alert type="error">{error}</Alert>}
        <PasswordField label="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} onBlur={touch('current')} error={touched.current ? errors.current : ''} />
        <div>
          <PasswordField label="New password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} onBlur={touch('next')} error={touched.next ? errors.next : ''} />
          <PasswordMeter password={next} />
        </div>
        <PasswordField label="Confirm new password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} onBlur={touch('confirm')} error={touched.confirm ? errors.confirm : ''} />
        <div><Button type="submit" loading={busy}>Change password</Button></div>
      </form>
    </section>
  );
}

export default PasswordPanel;
