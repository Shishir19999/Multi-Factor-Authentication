import { formatDateTime, METHOD_LABELS } from '../../lib/format';
import { ErrorState, Loading } from '../ui/States';

function Check({ ok, children }) {
  return (
    <li className={ok ? 'ok' : 'todo'}>
      <span aria-hidden="true">{ok ? '✓' : '!'}</span>
      <span>{children}<span className="sr-only">{ok ? ' (done)' : ' (needs attention)'}</span></span>
    </li>
  );
}

function OverviewPanel({ security, loading, error, reload, goTo }) {
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!security) return <Loading label="Loading account overview" lines={5} />;
  const on = security.twoFactorMethod !== 'none';
  const totp = security.twoFactorMethod === 'totp';

  return (
    <div className="grid-2" aria-busy={loading || undefined}>
      <section className="card" aria-labelledby="ov-account">
        <h2 id="ov-account">Account</h2>
        <dl className="kv">
          <div><dt>E-mail</dt><dd>{security.email}</dd></div>
          <div><dt>Member since</dt><dd>{formatDateTime(security.createdAt)}</dd></div>
          <div><dt>Two-step verification</dt><dd><span className={`pill ${on ? 'pill-ok' : 'pill-warn'}`}>{METHOD_LABELS[security.twoFactorMethod]}</span></dd></div>
          <div><dt>Trusted devices</dt><dd>{security.trustedDevices}</dd></div>
          {totp && <div><dt>Backup codes left</dt><dd>{security.backupCodesRemaining}</dd></div>}
        </dl>
      </section>
      <section className="card" aria-labelledby="ov-check">
        <h2 id="ov-check">Security checklist</h2>
        <ul className="checklist">
          <Check ok={on}>Two-step verification is {on ? 'on' : 'off'}</Check>
          <Check ok={totp}>Authenticator app {totp ? 'enabled' : 'not set up'}</Check>
          <Check ok={!totp || security.backupCodesRemaining >= 3}>
            {totp ? `${security.backupCodesRemaining} backup code${security.backupCodesRemaining === 1 ? '' : 's'} remaining` : 'Backup codes are available with an authenticator app'}
          </Check>
        </ul>
        <div className="row gap wrap">
          <button type="button" className="btn btn-secondary" onClick={() => goTo('twofactor')}>Two-step settings</button>
          <button type="button" className="btn btn-secondary" onClick={() => goTo('sessions')}>Review sessions</button>
        </div>
      </section>
    </div>
  );
}

export default OverviewPanel;
