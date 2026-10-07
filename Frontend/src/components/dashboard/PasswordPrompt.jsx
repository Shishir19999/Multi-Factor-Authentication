import { useState } from 'react';
import { errorMessage } from '../../api/errors';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { PasswordField } from '../ui/Field';
import Modal from '../ui/Modal';

// Re-authentication dialog for sensitive actions. onSubmit(password) should throw on failure.
function PasswordPrompt({ open, title, description, confirmLabel = 'Confirm', danger = false, onSubmit, onClose }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const close = () => { setPassword(''); setError(''); onClose(); };

  const submit = async (e) => {
    e.preventDefault();
    if (!password) { setError('Enter your password to continue.'); return; }
    setBusy(true);
    setError('');
    try {
      await onSubmit(password);
      setPassword('');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open={open} title={title} onClose={close}>
      <form className="stack" onSubmit={submit} noValidate>
        {description && <p>{description}</p>}
        {error && <Alert type="error">{error}</Alert>}
        <PasswordField label="Current password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
        <div className="row gap end">
          <Button variant="ghost" onClick={close}>Cancel</Button>
          <Button type="submit" variant={danger ? 'danger' : 'primary'} loading={busy}>{confirmLabel}</Button>
        </div>
      </form>
    </Modal>
  );
}

export default PasswordPrompt;
