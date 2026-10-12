import { useCallback, useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { API_URL, IS_PREVIEW } from '../../config';
import { useConfirm, useToast } from '../../context/contexts';
import { useAsync } from '../../hooks/useAsync';
import { formatDateTime, timeAgo, timeUntil } from '../../lib/format';
import { ROUTE_SCOPES, TOKEN_EXPIRY_OPTIONS, TOKEN_SCOPES } from '../../shared/scopes';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Field from '../ui/Field';
import Modal from '../ui/Modal';
import SelectField from '../ui/SelectField';
import { EmptyState, ErrorState, Loading } from '../ui/States';

// Personal API tokens: read-only, scoped, hashed at rest and revocable. The plaintext is shown once.
function TokensPanel() {
  const { toast } = useToast();
  const { confirm } = useConfirm();
  const load = useCallback(() => api.tokens(), []);
  const { data, error, reload } = useAsync(load);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState(['profile:read']);
  const [days, setDays] = useState('30');
  const [formError, setFormError] = useState('');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(null);
  const [probe, setProbe] = useState({ token: '', route: 'GET /auth/me' });
  const [probeResult, setProbeResult] = useState(null);

  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return <Loading label="Loading API tokens" lines={4} />;

  const create = async (e) => {
    e.preventDefault();
    setFormError('');
    setBusy(true);
    try {
      const res = await api.createToken({ name, scopes, expiresInDays: Number(days) });
      setCreated(res.token);
      setProbe((p) => ({ ...p, token: res.token }));
      setName('');
      reload();
    } catch (err) {
      if (!isCancelled(err)) setFormError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (t) => {
    const ok = await confirm({ title: 'Revoke this token?', message: `"${t.name}" stops working immediately.`, confirmLabel: 'Revoke token', danger: true });
    if (!ok) return;
    try { await api.revokeToken(t.id); toast('Token revoked.', 'success'); reload(); } catch (err) { if (!isCancelled(err)) toast(errorMessage(err), 'error'); }
  };

  const copy = async () => {
    try { await navigator.clipboard.writeText(created); toast('Token copied.', 'success'); } catch { toast('Select the token and copy it manually.', 'info'); }
  };

  const send = async (e) => {
    e.preventDefault();
    setProbeResult(null);
    try { setProbeResult(await api.callWithToken(probe)); } catch (err) { setProbeResult({ status: 0, body: { message: errorMessage(err) } }); }
  };

  const toggle = (scope) => setScopes((s) => (s.includes(scope) ? s.filter((x) => x !== scope) : [...s, scope]));

  return (
    <div className="stack-lg">
      <section className="card" aria-labelledby="tok-title">
        <h2 id="tok-title">Personal API tokens</h2>
        <p className="muted">Tokens let a script read your own data without your password. They are read-only, limited to the scopes you pick, stored only as a hash and can be revoked any time.</p>
        {data.length === 0 ? <EmptyState title="No tokens yet">Create one below.</EmptyState> : (
          <ul className="list">
            {data.map((t) => (
              <li key={t.id} className="list-item">
                <div>
                  <p className="item-title">{t.name} <code>{t.prefix}…</code>{!t.expiresAt && <span className="pill pill-warn">Never expires</span>}</p>
                  <p className="muted">Scopes: {t.scopes.join(', ')}</p>
                  <p className="muted">Created {formatDateTime(t.createdAt)} · {t.lastUsedAt ? `last used ${timeAgo(t.lastUsedAt)}` : 'never used'} · {t.expiresAt ? `expires ${timeUntil(t.expiresAt)}` : 'no expiry'}</p>
                </div>
                <Button variant="danger" onClick={() => revoke(t)}>Revoke<span className="sr-only"> {t.name}</span></Button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="grid-2">
        <section className="card" aria-labelledby="tok-new">
          <h2 id="tok-new">Create a token</h2>
          <form className="stack" onSubmit={create} noValidate>
            {formError && <Alert type="error">{formError}</Alert>}
            <Field label="Name" value={name} maxLength={40} onChange={(e) => setName(e.target.value)} placeholder="For example: reporting script" />
            <fieldset className="fieldset">
              <legend>Scopes</legend>
              {Object.entries(TOKEN_SCOPES).map(([scope, text]) => (
                <label key={scope} className="check">
                  <input type="checkbox" checked={scopes.includes(scope)} onChange={() => toggle(scope)} />
                  <span><code>{scope}</code> {text}</span>
                </label>
              ))}
            </fieldset>
            <SelectField label="Expires" value={days} onChange={(e) => setDays(e.target.value)} options={TOKEN_EXPIRY_OPTIONS.map((o) => ({ value: String(o.days), label: o.label }))} />
            <div><Button type="submit" loading={busy}>Create token</Button></div>
          </form>
        </section>

        <section className="card" aria-labelledby="tok-try">
          <h2 id="tok-try">Try a token</h2>
          <p className="muted">
            {IS_PREVIEW ? 'Calls the in-browser preview API' : `Calls ${API_URL}`} with only the token, the way an external client would.
          </p>
          <form className="stack" onSubmit={send} noValidate>
            <Field label="Token" value={probe.token} onChange={(e) => setProbe({ ...probe, token: e.target.value })} placeholder="mfa_pat_..." autoComplete="off" spellCheck={false} />
            <SelectField label="Request" value={probe.route} onChange={(e) => setProbe({ ...probe, route: e.target.value })} options={Object.keys(ROUTE_SCOPES)} />
            <div><Button type="submit" variant="secondary" disabled={!probe.token}>Send request</Button></div>
          </form>
          {probeResult && (
            <div className="probe" role="status">
              <p><strong>Response {probeResult.status}</strong></p>
              <pre tabIndex={0}>{JSON.stringify(probeResult.body, null, 2).slice(0, 1500)}</pre>
            </div>
          )}
        </section>
      </div>

      <Modal open={!!created} title="Copy your new token now" onClose={() => setCreated(null)} footer={<Button onClick={() => setCreated(null)}>Done</Button>}>
        {created && (
          <div className="stack">
            <Alert type="warning">This is the only time the token is shown. We store just a hash.</Alert>
            <code className="secret token-secret">{created}</code>
            <div><Button variant="secondary" onClick={copy}>Copy token</Button></div>
          </div>
        )}
      </Modal>
    </div>
  );
}

export default TokensPanel;
