import { useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled, retryAfter } from '../../api/errors';
import { useAuth, usePolicy, useToast } from '../../context/contexts';
import { useCountdown } from '../../hooks/useCountdown';
import { passwordValid } from '../../lib/password';
import { timeAgo } from '../../lib/format';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { PasswordField } from '../ui/Field';
import { PasswordCreate } from '../ui/PasswordMeter';
import RetryNotice from '../ui/RetryNotice';

// Change password: policy rules, history, expiry and the breach check. Required changes (forced / expired) are explained.
function PasswordPanel({ security, requirement, onChanged }) {
  const { toast } = useToast();
  const { policy } = usePolicy();
  const { user } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [touched, setTouched] = useState({});
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [rateLeft, setRateLeft] = useCountdown(0);
  const email = user?.email || '';

  const errors = {
    current: !current ? 'Enter your current password.' : '',
    next: !passwordValid(next, policy, { email }) ? 'The new password does not meet all the rules below.' : next === current ? 'Choose a password different from the current one.' : '',
    confirm: confirm !== next ? 'The passwords do not match.' : '',
  };
  const touch = (k) => () => setTouched((t) => ({ ...t, [k]: true }));

  const submit = async (e) => {
    e.preventDefault();
    setTouched({ current: true, next: true, confirm: true });
    setError('');
    if (errors.current || errors.next || errors.confirm || rateLeft > 0) return;
    setBusy(true);
    try {
      const res = await api.changePassword({ currentPassword: current, newPassword: next });
      toast('Password changed. Your other sessions were signed out.', 'success');
      if (res.warning) toast(res.warning, 'info');
      setCurrent(''); setNext(''); setConfirm(''); setTouched({});
      onChanged?.();
    } catch (err) {
      if (isCancelled(err)) return;
      setRateLeft(retryAfter(err));
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const age = security?.passwordAge;
  const status = security?.breachStatus;

  return (
    <div className="stack-lg">
      {requirement && <Alert type="warning">{requirement.message}</Alert>}
      <section className="card narrow" aria-labelledby="pw-title">
        <h2 id="pw-title">Change password</h2>
        <p className="muted">
          {age && <>Last changed {timeAgo(security.passwordChangedAt)}{age.expires ? `; expires in ${Math.max(age.daysLeft, 0)} day${age.daysLeft === 1 ? '' : 's'}` : ''}. </>}
          Changing your password signs out every other session and forgets trusted devices.
          {policy.password.historyCount > 0 && ` You cannot reuse your last ${policy.password.historyCount} passwords.`}
        </p>
        {status === 'pwned' && <Alert type="error">The password you used to sign in appears in a known data breach. Choose a new one now.</Alert>}
        <form className="stack" onSubmit={submit} noValidate>
          <RetryNotice seconds={rateLeft} title="Too many attempts." />
          {error && rateLeft === 0 && <Alert type="error">{error}</Alert>}
          <PasswordField label="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} onBlur={touch('current')} error={touched.current ? errors.current : ''} />
          <PasswordCreate label="New password" value={next} email={email} onChange={(e) => setNext(e.target.value)} onBlur={touch('next')} error={touched.next ? errors.next : ''} />
          <PasswordField label="Confirm new password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} onBlur={touch('confirm')} error={touched.confirm ? errors.confirm : ''} />
          <div><Button type="submit" loading={busy} disabled={rateLeft > 0}>Change password</Button></div>
        </form>
      </section>
    </div>
  );
}

export default PasswordPanel;
