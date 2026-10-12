import { useEffect, useState } from 'react';
import { PREVIEW_ACCOUNTS, PREVIEW_BACKUP_CODE, PREVIEW_PASSWORD, PREVIEW_TOTP_SECRET } from '../../api/previewAccounts';
import { DEVICES, PLACES, getEnv, setEnv } from '../../api/previewEnv';
import { formatSecret, secondsRemaining, totpFromSecret } from '../../lib/totp';
import { METHOD_LABELS, ROLE_LABELS } from '../../lib/format';
import SelectField from '../ui/SelectField';

// The authenticator code of the sample account, computed live with the same WebCrypto TOTP used for sign-in.
function LiveCode() {
  const [state, setState] = useState({ code: '------', left: 30 });
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      const code = await totpFromSecret(PREVIEW_TOTP_SECRET);
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

// Lets the visitor pretend to sign in from another device / city (new-device and new-location alerts).
function Simulator() {
  const [env, setLocal] = useState(getEnv);
  const change = (key) => (e) => { setEnv({ [key]: e.target.value }); setLocal(getEnv()); };
  return (
    <div className="simulator">
      <h3>Simulate a different device or place</h3>
      <p className="muted">Sign in again from another device or city to see the &quot;was this you?&quot; alert. Nothing is detected; this only changes what the preview backend sees.</p>
      <SelectField label="Device" value={env.device} onChange={change('device')} options={DEVICES.map((d) => ({ value: d.id, label: d.label }))} />
      <SelectField label="Place (simulated)" value={env.place} onChange={change('place')} options={PLACES.map((p) => ({ value: p.id, label: p.label }))} />
    </div>
  );
}

// Documented sample logins. "Use" fills the sign-in form.
function PreviewAccounts({ onPick }) {
  return (
    <aside className="card preview-accounts" aria-labelledby="preview-accounts-title">
      <h2 id="preview-accounts-title">Sample logins</h2>
      <p className="muted">Sample accounts for the Live preview only. Password for all of them: <code>{PREVIEW_PASSWORD}</code></p>
      <ul>
        {PREVIEW_ACCOUNTS.map((a) => (
          <li key={a.email}>
            <div className="preview-account-head">
              <div>
                <strong>{a.email}</strong>
                <span className="pill">{ROLE_LABELS[a.role]}</span>
                <span className="pill">{METHOD_LABELS[a.method]}</span>
              </div>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => onPick(a.email, PREVIEW_PASSWORD)}>
                Use<span className="sr-only"> {a.email}</span>
              </button>
            </div>
            <p className="muted">{a.note}</p>
            {a.method === 'totp' && (
              <div className="preview-totp">
                <LiveCode />
                <p className="muted">Secret for your own authenticator app: <code>{formatSecret(PREVIEW_TOTP_SECRET)}</code></p>
                <p className="muted">Backup code: <code>{PREVIEW_BACKUP_CODE}</code></p>
              </div>
            )}
          </li>
        ))}
      </ul>
      <Simulator />
    </aside>
  );
}

export default PreviewAccounts;
