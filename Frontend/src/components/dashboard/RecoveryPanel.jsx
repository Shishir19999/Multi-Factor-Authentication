import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { IS_PREVIEW } from '../../config';
import { useConfirm, useToast } from '../../context/contexts';
import { isEmail } from '../../lib/password';
import { OPEN_INBOX_EVENT } from '../preview/PreviewInbox';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Field from '../ui/Field';
import OtpInput from '../ui/OtpInput';
import { ErrorState, Loading } from '../ui/States';

// Recovery options: backup codes, a verified recovery e-mail, the e-mailed recovery code and administrator help.
function RecoveryPanel({ security, error, reload, goTo }) {
  const { toast } = useToast();
  const { confirm } = useConfirm();
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [sentTo, setSentTo] = useState('');
  const [formError, setFormError] = useState('');
  const [busy, setBusy] = useState(false);

  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!security) return <Loading label="Loading recovery options" lines={5} />;

  const guard = async (fn, onOk) => {
    setFormError('');
    setBusy(true);
    try { await fn(); onOk?.(); } catch (e) { if (!isCancelled(e)) setFormError(errorMessage(e)); } finally { setBusy(false); }
  };

  const send = (e) => {
    e.preventDefault();
    if (!isEmail(email)) { setFormError('Enter a valid e-mail address.'); return; }
    guard(async () => { setSentTo((await api.setRecoveryEmail({ email })).message); }, () => setCode(''));
  };

  const verify = (value) => guard(async () => { await api.verifyRecoveryEmail({ code: value }); }, () => {
    toast('Recovery e-mail verified.', 'success'); setSentTo(''); setEmail(''); setCode(''); reload();
  });

  const remove = async () => {
    const ok = await confirm({ title: 'Remove the recovery e-mail?', message: 'Recovery codes will only go to your sign-in e-mail address.', confirmLabel: 'Remove', danger: true });
    if (ok) guard(async () => { await api.removeRecoveryEmail(); }, () => { toast('Recovery e-mail removed.', 'success'); reload(); });
  };

  const totp = security.twoFactorMethod === 'totp';

  return (
    <div className="stack-lg">
      <section className="card" aria-labelledby="rec-ready">
        <h2 id="rec-ready">Recovery readiness</h2>
        <p className="muted">If you lose a device or forget your password, these are the ways back in. Having more than one is safer.</p>
        <ul className="checklist">
          <li className={totp && security.backupCodesRemaining >= 3 ? 'ok' : 'todo'}>
            <span aria-hidden="true">{totp && security.backupCodesRemaining >= 3 ? '✓' : '!'}</span>
            <span>{totp ? `${security.backupCodesRemaining} backup code${security.backupCodesRemaining === 1 ? '' : 's'} left` : 'Backup codes (need an authenticator app)'}{' '}
              <button type="button" className="link-btn" onClick={() => goTo('signin')}>Manage</button></span>
          </li>
          <li className={security.recoveryEmail ? 'ok' : 'todo'}>
            <span aria-hidden="true">{security.recoveryEmail ? '✓' : '!'}</span>
            <span>{security.recoveryEmail ? `Recovery e-mail ${security.recoveryEmail}` : 'No recovery e-mail'}</span>
          </li>
          <li className="ok"><span aria-hidden="true">✓</span><span>Recovery code by e-mail to {security.email} (<Link to="/recover">recovery page</Link>)</span></li>
          <li className="ok"><span aria-hidden="true">✓</span><span>Administrator-assisted recovery is available from the recovery page</span></li>
        </ul>
      </section>

      <section className="card narrow" aria-labelledby="rec-email">
        <h2 id="rec-email">Recovery e-mail</h2>
        {security.recoveryEmail ? (
          <div className="stack">
            <p>Verified: <strong>{security.recoveryEmail}</strong>. Recovery codes are sent here as well as to your sign-in address.</p>
            <div><Button variant="danger" onClick={remove} loading={busy}>Remove recovery e-mail</Button></div>
          </div>
        ) : (
          <div className="stack">
            <p className="muted">Add a second address (for example a work or backup mailbox). You confirm it with a code, so nobody can add one they do not own.</p>
            {formError && <Alert type="error">{formError}</Alert>}
            {!sentTo ? (
              <form className="stack" onSubmit={send} noValidate>
                <Field label="Recovery e-mail address" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="backup@example.org" />
                <div><Button type="submit" loading={busy}>Send confirmation code</Button></div>
              </form>
            ) : (
              <div className="stack">
                <Alert type="info">{sentTo}{IS_PREVIEW && <> Live preview: <button type="button" className="link-btn" onClick={() => window.dispatchEvent(new Event(OPEN_INBOX_EVENT))}>open the Preview inbox</button>.</>}</Alert>
                <OtpInput value={code} onChange={setCode} onComplete={verify} label="Confirmation code" disabled={busy} autoFocus />
                <div className="row gap">
                  <Button loading={busy} disabled={code.length !== 6} onClick={() => verify(code)}>Verify</Button>
                  <Button variant="ghost" onClick={() => { setSentTo(''); setFormError(''); }}>Use another address</Button>
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      <section className="card" aria-labelledby="rec-admin">
        <h2 id="rec-admin">If you are locked out completely</h2>
        <p>If you cannot sign in and cannot read your e-mail, the recovery page lets you ask an administrator for help. They can issue a recovery code or reset your second step after checking it is you.</p>
        <Link className="btn btn-secondary" to="/recover">Open the recovery page</Link>
      </section>
    </div>
  );
}

export default RecoveryPanel;
