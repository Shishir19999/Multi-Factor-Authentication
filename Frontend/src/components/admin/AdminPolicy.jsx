import { useCallback, useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { usePolicy, useToast } from '../../context/contexts';
import { useAsync } from '../../hooks/useAsync';
import { defaultPolicy, normalizePolicy, POLICY_SCHEMA } from '../../shared/policy';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Field from '../ui/Field';
import SelectField from '../ui/SelectField';
import { ErrorState, Loading } from '../ui/States';

const get = (o, path) => path.split('.').reduce((a, k) => a?.[k], o);
function put(o, path, value) {
  const copy = structuredClone(o);
  const keys = path.split('.');
  const last = keys.pop();
  keys.reduce((a, k) => a[k], copy)[last] = value;
  return copy;
}

const labelOf = (path) => POLICY_SCHEMA[path][POLICY_SCHEMA[path].length - 1];

// Security policy settings: required factors, password rules, session lifetime, lockout thresholds, trusted-device days.
function AdminPolicy() {
  const { toast } = useToast();
  const { reload: reloadPolicy } = usePolicy();
  const load = useCallback(() => api.adminGetPolicy(), []);
  const { data, error, reload } = useAsync(load);
  const [edits, setEdits] = useState(null);
  const [problems, setProblems] = useState([]);
  const [busy, setBusy] = useState(false);
  const [mailBusy, setMailBusy] = useState(false);

  const draft = data ? (edits ?? normalizePolicy(data).policy) : null;
  const setDraft = setEdits;

  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!draft) return <Loading label="Loading security policy" lines={8} />;

  const num = (path) => (
    <Field key={path} label={labelOf(path)} type="number" inputMode="numeric" min={POLICY_SCHEMA[path][1]} max={POLICY_SCHEMA[path][2]}
      value={get(draft, path)} onChange={(e) => setDraft(put(draft, path, e.target.value === '' ? '' : Number(e.target.value)))}
      hint={`${POLICY_SCHEMA[path][1]} to ${POLICY_SCHEMA[path][2]}`} />
  );
  const bool = (path) => (
    <label key={path} className="check">
      <input type="checkbox" checked={!!get(draft, path)} onChange={(e) => setDraft(put(draft, path, e.target.checked))} />
      <span>{labelOf(path)}</span>
    </label>
  );
  const methods = draft.twoFactor.methods;
  const toggleMethod = (m) => setDraft(put(draft, 'twoFactor.methods', methods.includes(m) ? methods.filter((x) => x !== m) : [...methods, m]));

  const save = async (e) => {
    e.preventDefault();
    setBusy(true); setProblems([]);
    try {
      const res = await api.adminSetPolicy(draft);
      toast(res.changed.length ? `Policy saved (${res.changed.length} setting${res.changed.length === 1 ? '' : 's'} changed).` : 'No changes to save.', 'success');
      setEdits(null);
      reload();
      reloadPolicy();
    } catch (err) {
      if (!isCancelled(err)) setProblems(err.data?.errors?.map((x) => x.message) || [errorMessage(err)]);
    } finally {
      setBusy(false);
    }
  };

  const testMail = async () => {
    setMailBusy(true);
    try {
      toast((await api.adminTestMail()).message, 'success');
    } catch (err) {
      if (!isCancelled(err)) toast(errorMessage(err), 'error');
    } finally {
      setMailBusy(false);
    }
  };

  return (
    <form className="stack-lg" onSubmit={save} noValidate>
      {problems.length > 0 && <Alert type="error"><ul className="plain-list">{problems.map((p) => <li key={p}>{p}</li>)}</ul></Alert>}

      <section className="card" aria-labelledby="ap-2fa">
        <h2 id="ap-2fa">Two-step verification</h2>
        <SelectField label={labelOf('twoFactor.required')} value={draft.twoFactor.required} onChange={(e) => setDraft(put(draft, 'twoFactor.required', e.target.value))}
          options={[{ value: 'none', label: 'Nobody (optional)' }, { value: 'admins', label: 'Administrators' }, { value: 'everyone', label: 'Everyone' }]}
          hint="Accounts without a second step are blocked until they enrol." />
        <fieldset className="fieldset">
          <legend>{labelOf('twoFactor.methods')}</legend>
          <label className="check"><input type="checkbox" checked={methods.includes('email')} onChange={() => toggleMethod('email')} /><span>E-mail codes</span></label>
          <label className="check"><input type="checkbox" checked={methods.includes('totp')} onChange={() => toggleMethod('totp')} /><span>Authenticator app</span></label>
          <p className="hint">Passkeys are always allowed and satisfy the requirement.</p>
        </fieldset>
        {num('trustedDeviceDays')}
        {bool('alerts.newDevice')}
      </section>

      <section className="card" aria-labelledby="ap-pw">
        <h2 id="ap-pw">Password rules</h2>
        <div className="form-grid">
          {num('password.minLength')}
          {num('password.historyCount')}
          {num('password.maxAgeDays')}
        </div>
        <div className="stack-sm">
          {bool('password.requireLetter')}{bool('password.requireNumber')}{bool('password.requireUpper')}{bool('password.requireSymbol')}{bool('password.blockEmail')}
        </div>
        <SelectField label={labelOf('breachCheck')} value={draft.breachCheck} onChange={(e) => setDraft(put(draft, 'breachCheck', e.target.value))}
          options={[{ value: 'off', label: 'Off' }, { value: 'warn', label: 'Warn the user' }, { value: 'block', label: 'Block breached passwords' }]}
          hint="Uses the Have I Been Pwned range API; only the first 5 characters of a SHA-1 hash are sent. If the service is unreachable, passwords are accepted." />
      </section>

      <section className="card" aria-labelledby="ap-sess">
        <h2 id="ap-sess">Sessions and lockout</h2>
        <div className="form-grid">
          {num('session.lifetimeMinutes')}
          {num('session.idleMinutes')}
          {num('session.stepUpMinutes')}
          {num('session.maxSessions')}
          {num('lockout.threshold')}
          {num('lockout.durationMinutes')}
        </div>
        {bool('lockout.progressive')}
      </section>

      <div className="row gap wrap">
        <Button type="submit" loading={busy}>Save policy</Button>
        <Button variant="secondary" onClick={() => setDraft(defaultPolicy())}>Restore defaults (then save)</Button>
      </div>

      <section className="card" aria-labelledby="ap-mail">
        <h2 id="ap-mail">E-mail delivery</h2>
        <p className="muted">Sends a test message through the configured SMTP account. The recipient is set on the server (<code>ADMIN_NOTIFY_EMAIL</code>) and cannot be changed here.</p>
        <div><Button variant="secondary" onClick={testMail} loading={mailBusy}>Send test e-mail</Button></div>
      </section>
    </form>
  );
}

export default AdminPolicy;
