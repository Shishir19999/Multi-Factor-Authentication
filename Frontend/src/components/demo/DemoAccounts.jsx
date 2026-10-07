import { useEffect, useState } from 'react';
import { DEMO_ACCOUNTS, DEMO_BACKUP_CODE, DEMO_PASSWORD, DEMO_TOTP_SECRET } from '../../api/demoAccounts';
import { formatSecret, secondsRemaining, totpFromSecret } from '../../lib/totp';
import { METHOD_LABELS } from '../../lib/format';

// The authenticator code of the sample account, computed live with the same WebCrypto TOTP used for sign-in.
function LiveCode() {
  const [state, setState] = useState({ code: '------', left: 30 });
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      const code = await totpFromSecret(DEMO_TOTP_SECRET);
      if (!cancelled) setState({ code, left: secondsRemaining() });
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);
  return (
    <p className="live-code">
      Current code: <code>{state.code}</code> <span className="muted">(changes in {state.left}s)</span>
    </p>
  );
}

// Documented demo logins. "Use" fills the sign-in form.
function DemoAccounts({ onPick }) {
  return (
    <aside className="card demo-accounts" aria-labelledby="demo-accounts-title">
      <h2 id="demo-accounts-title">Demo logins</h2>
      <p className="muted">Password for all accounts: <code>{DEMO_PASSWORD}</code></p>
      <ul>
        {DEMO_ACCOUNTS.map((a) => (
          <li key={a.email}>
            <div className="demo-account-head">
              <div>
                <strong>{a.email}</strong>
                <span className="pill">{METHOD_LABELS[a.method]}</span>
              </div>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => onPick(a.email, DEMO_PASSWORD)}>
                Use<span className="sr-only"> {a.email}</span>
              </button>
            </div>
            <p className="muted">{a.note}</p>
            {a.method === 'totp' && (
              <div className="demo-totp">
                <LiveCode />
                <p className="muted">Secret for your own authenticator app: <code>{formatSecret(DEMO_TOTP_SECRET)}</code></p>
                <p className="muted">Backup code: <code>{DEMO_BACKUP_CODE}</code></p>
              </div>
            )}
          </li>
        ))}
      </ul>
    </aside>
  );
}

export default DemoAccounts;
