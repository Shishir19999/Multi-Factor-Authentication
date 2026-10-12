import { useCallback } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { useToast } from '../../context/contexts';
import { useAsync } from '../../hooks/useAsync';
import { formatDateTime, METHOD_LABELS, ROLE_LABELS, timeAgo } from '../../lib/format';
import Button from '../ui/Button';
import ScoreRing from '../ui/ScoreRing';
import { ErrorState, Loading } from '../ui/States';

// Unreviewed "was this you?" alerts with Yes / No buttons.
function AlertsCard({ onSignedOut, onAnswered }) {
  const { toast } = useToast();
  const load = useCallback(() => api.alerts(), []);
  const { data, reload } = useAsync(load);
  const pending = (data || []).filter((a) => a.status === 'pending');
  if (!pending.length) return null;

  const answer = async (a, ans) => {
    try {
      const res = await api.respondAlert({ id: a.id, answer: ans });
      if (res.signedOut) { toast('Everything was signed out. Choose a new password when you sign in again.', 'info'); onSignedOut?.(); return; }
      toast('Thanks, noted.', 'success');
      reload();
      onAnswered?.();
    } catch (e) {
      if (!isCancelled(e)) toast(errorMessage(e), 'error');
    }
  };

  return (
    <section className="card card-alert" aria-labelledby="alerts-title">
      <h2 id="alerts-title">Was this you?</h2>
      <p className="muted">These sign-ins came from a device or place we had not seen before.</p>
      <ul className="list">
        {pending.map((a) => (
          <li key={a.id} className="list-item">
            <div>
              <p className="item-title">{a.device} <span className={`pill ${a.level === 'high' ? 'pill-bad' : 'pill-warn'}`}>{a.level === 'high' ? 'High risk' : 'Unusual'}</span></p>
              <p className="muted">{a.geo} (estimated) · IP {a.ip || 'unknown'} · {formatDateTime(a.at)}</p>
              <p className="muted">{a.reasons.join(' · ')}</p>
            </div>
            <div className="row gap wrap">
              <Button variant="secondary" onClick={() => answer(a, 'yes')}>Yes, it was me<span className="sr-only"> ({a.device})</span></Button>
              <Button variant="danger" onClick={() => answer(a, 'no')}>No, secure my account<span className="sr-only"> ({a.device})</span></Button>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Check({ ok, children }) {
  return (
    <li className={ok ? 'ok' : 'todo'}>
      <span aria-hidden="true">{ok ? '✓' : '!'}</span>
      <span>{children}<span className="sr-only">{ok ? ' (done)' : ' (needs attention)'}</span></span>
    </li>
  );
}

function OverviewPanel({ security, loading, error, reload, goTo, onSignedOut }) {
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!security) return <Loading label="Loading account overview" lines={5} />;
  const s = security.score;
  const on = security.twoFactorMethod !== 'none';
  const strong = security.twoFactorMethod === 'totp' || security.passkeys > 0;

  return (
    <div className="stack-lg" aria-busy={loading || undefined}>
      <AlertsCard onSignedOut={onSignedOut} onAnswered={reload} />

      <div className="grid-2">
        <section className="card score-card" aria-labelledby="score-title">
          <h2 id="score-title">Security score</h2>
          <div className="score-head">
            <ScoreRing score={s.score} grade={s.grade} label={s.label} />
            <div>
              <p className="lead-sm">{s.recommendations.length === 0 ? 'Everything we check looks good.' : `${s.recommendations.length} recommendation${s.recommendations.length === 1 ? '' : 's'} to improve your account.`}</p>
              <p className="muted">The score is calculated from your own settings and is visible only to you.</p>
            </div>
          </div>
          {s.recommendations.length > 0 && (
            <ol className="recs">
              {s.recommendations.map((r) => (
                <li key={r.id}>
                  <span>{r.tip} <span className="muted">(+{r.gain} points)</span></span>
                  <Button variant="secondary" onClick={() => goTo(r.tab)}>Fix<span className="sr-only"> : {r.tip}</span></Button>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section className="card" aria-labelledby="ov-account">
          <h2 id="ov-account">Account</h2>
          <dl className="kv">
            <div><dt>E-mail</dt><dd>{security.email}</dd></div>
            <div><dt>Role</dt><dd>{ROLE_LABELS[security.role]}</dd></div>
            <div><dt>Member since</dt><dd>{formatDateTime(security.createdAt)}</dd></div>
            <div><dt>Second step</dt><dd><span className={`pill ${on ? 'pill-ok' : 'pill-warn'}`}>{METHOD_LABELS[security.twoFactorMethod]}</span></dd></div>
            <div><dt>Passkeys</dt><dd>{security.passkeys}</dd></div>
            <div><dt>Password changed</dt><dd>{timeAgo(security.passwordChangedAt)}{security.passwordAge.expires && ` (${security.passwordAge.daysLeft} days left)`}</dd></div>
            <div><dt>Recovery e-mail</dt><dd>{security.recoveryEmail || 'Not set'}</dd></div>
            <div><dt>Active sessions</dt><dd>{security.sessionCount}</dd></div>
          </dl>
        </section>
      </div>

      <div className="grid-2">
        <section className="card" aria-labelledby="ov-check">
          <h2 id="ov-check">Security checklist</h2>
          <ul className="checklist">
            <Check ok={on || security.passkeys > 0}>Two-step verification is {on || security.passkeys > 0 ? 'on' : 'off'}</Check>
            <Check ok={strong}>{strong ? 'Phishing-resistant second step (authenticator app or passkey)' : 'Use an authenticator app or a passkey'}</Check>
            <Check ok={security.recoveryEmail !== null}>{security.recoveryEmail ? 'Recovery e-mail verified' : 'No recovery e-mail yet'}</Check>
            <Check ok={security.breachStatus !== 'pwned'}>{security.breachStatus === 'pwned' ? 'Your password appears in a known breach' : 'Password not found in known breaches'}</Check>
            <Check ok={security.unreviewedAlerts === 0}>{security.unreviewedAlerts === 0 ? 'No sign-in alerts to review' : `${security.unreviewedAlerts} sign-in alert(s) to review`}</Check>
          </ul>
          <div className="row gap wrap">
            <Button variant="secondary" onClick={() => goTo('signin')}>Sign-in methods</Button>
            <Button variant="secondary" onClick={() => goTo('sessions')}>Review sessions</Button>
          </div>
        </section>

        <section className="card" aria-labelledby="ov-break">
          <h2 id="ov-break">How the score is made</h2>
          <ul className="breakdown">
            {s.items.map((i) => (
              <li key={i.id}>
                <span>{i.label}</span>
                <span className="muted"><span className="sr-only">Earned </span>{i.points} / {i.max}</span>
                <span className="bar" aria-hidden="true"><span style={{ width: `${(i.points / i.max) * 100}%` }} /></span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}

export default OverviewPanel;
