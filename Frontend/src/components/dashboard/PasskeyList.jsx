import { useCallback, useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { IS_PREVIEW } from '../../config';
import { useConfirm, useToast } from '../../context/contexts';
import { useAsync } from '../../hooks/useAsync';
import { formatDateTime, timeAgo } from '../../lib/format';
import { passkeyRegister } from '../../lib/passkeyFlows';
import { canSimulate, realAvailable, setWantsSimulation, wantsSimulation } from '../../lib/passkeyMode';
import { passkeyErrorMessage } from '../../lib/webauthnClient';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Field from '../ui/Field';
import Modal from '../ui/Modal';
import { EmptyState, ErrorState, Loading } from '../ui/States';

// Passkeys: list, add (real WebAuthn, or the labelled simulated authenticator in the Live preview), rename, remove.
function PasskeyList({ onChanged }) {
  const { toast } = useToast();
  const { confirm } = useConfirm();
  const load = useCallback(() => api.passkeys(), []);
  const { data, error, reload, setData } = useAsync(load);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState('');
  const [simulate, setSimulate] = useState(wantsSimulation);
  const [renaming, setRenaming] = useState(null); // { id, name }

  const real = realAvailable();
  const supported = real || canSimulate;

  const add = async (e) => {
    e.preventDefault();
    setFormError('');
    setBusy(true);
    try {
      setData(await passkeyRegister(name.trim() || undefined));
      setName('');
      toast('Passkey added.', 'success');
      onChanged?.();
    } catch (err) {
      if (!isCancelled(err)) setFormError(err.name === 'ApiError' ? errorMessage(err) : passkeyErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (p) => {
    const ok = await confirm({ title: 'Remove this passkey?', message: `"${p.name}" will no longer sign in to your account. Remove it from your device or password manager too.`, confirmLabel: 'Remove passkey', danger: true });
    if (!ok) return;
    try {
      setData(await api.removePasskey(p.id));
      toast('Passkey removed.', 'success');
      onChanged?.();
    } catch (err) {
      if (!isCancelled(err)) toast(errorMessage(err), 'error');
    }
  };

  const saveName = async (e) => {
    e.preventDefault();
    try {
      await api.renamePasskey(renaming.id, renaming.name);
      setRenaming(null);
      reload();
    } catch (err) {
      toast(errorMessage(err), 'error');
    }
  };

  return (
    <section className="card" aria-labelledby="pk-title">
      <h2 id="pk-title">Passkeys</h2>
      <p className="muted">A passkey signs you in with your device&apos;s screen lock, fingerprint or security key. It cannot be phished and counts as a full second step.</p>
      {IS_PREVIEW && (
        <Alert type="info">
          Live preview: passkeys are verified by a simulation of the server that runs in this browser. Your browser&apos;s real passkey prompt is used when it is available; otherwise (or if you tick the box below) a software authenticator stored in this browser stands in. It is labelled and for the preview only.
        </Alert>
      )}
      {error ? <ErrorState message={error.message} onRetry={reload} /> : !data ? <Loading label="Loading passkeys" lines={2} /> : (
        data.length === 0 ? (
          <EmptyState title="No passkeys yet">Add one below to sign in without typing a password.</EmptyState>
        ) : (
          <ul className="list">
            {data.map((p) => (
              <li key={p.id} className="list-item">
                <div>
                  <p className="item-title">{p.name}<span className="pill">{p.backedUp || p.deviceType === 'multiDevice' ? 'Synced' : 'This device only'}</span></p>
                  <p className="muted">Added {formatDateTime(p.createdAt)} · last used {p.lastUsedAt ? timeAgo(p.lastUsedAt) : 'never'}</p>
                </div>
                <div className="row gap">
                  <Button variant="secondary" onClick={() => setRenaming({ id: p.id, name: p.name })}>Rename<span className="sr-only"> {p.name}</span></Button>
                  <Button variant="danger" onClick={() => remove(p)}>Remove<span className="sr-only"> {p.name}</span></Button>
                </div>
              </li>
            ))}
          </ul>
        )
      )}
      {supported ? (
        <form className="stack passkey-add" onSubmit={add} noValidate>
          {formError && <Alert type="error">{formError}</Alert>}
          <Field label="Name for the new passkey (optional)" value={name} maxLength={40} onChange={(e) => setName(e.target.value)} placeholder="For example: Work laptop" />
          {canSimulate && (
            <label className="check">
              <input type="checkbox" checked={simulate || !real} disabled={!real} onChange={(e) => { setSimulate(e.target.checked); setWantsSimulation(e.target.checked); }} />
              <span>Use a simulated passkey (software authenticator in this browser, preview only){!real && ' - required here: this browser has no passkey support on this page'}</span>
            </label>
          )}
          <div><Button type="submit" loading={busy}>Add a passkey</Button></div>
        </form>
      ) : (
        <Alert type="warning">This browser or page cannot create passkeys (they need a secure https connection and a modern browser).</Alert>
      )}
      <Modal open={!!renaming} title="Rename passkey" onClose={() => setRenaming(null)}>
        {renaming && (
          <form className="stack" onSubmit={saveName} noValidate>
            <Field label="Name" value={renaming.name} maxLength={40} onChange={(e) => setRenaming({ ...renaming, name: e.target.value })} autoFocus />
            <div className="row gap end">
              <Button variant="ghost" onClick={() => setRenaming(null)}>Cancel</Button>
              <Button type="submit" disabled={!renaming.name.trim()}>Save</Button>
            </div>
          </form>
        )}
      </Modal>
    </section>
  );
}

export default PasskeyList;
