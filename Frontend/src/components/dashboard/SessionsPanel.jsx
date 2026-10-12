import { useCallback, useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { useAuth, useConfirm, useToast } from '../../context/contexts';
import { useAsync } from '../../hooks/useAsync';
import { describeDevice, formatDateTime, timeAgo } from '../../lib/format';
import Button from '../ui/Button';
import Field from '../ui/Field';
import Modal from '../ui/Modal';
import { EmptyState, ErrorState, Loading } from '../ui/States';

const VIA = { password: 'password', passkey: 'passkey', trusted: 'trusted device', recovery: 'recovery' };
const label = (s) => s.name || s.device || describeDevice(s.userAgent);

// Signed-in devices: friendly names, approximate place, last seen, rename, revoke one / all others / everywhere.
function SessionsPanel({ onSignedOut }) {
  const { toast } = useToast();
  const { confirm } = useConfirm();
  const { signOut } = useAuth();
  const load = useCallback(() => api.sessions(), []);
  const { data, error, loading, reload } = useAsync(load);
  const [renaming, setRenaming] = useState(null);

  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return <Loading label="Loading sessions" lines={5} />;

  const others = data.filter((s) => !s.current);
  const guard = async (fn, okText) => {
    try { await fn(); toast(okText, 'success'); reload(); } catch (e) { if (!isCancelled(e)) toast(errorMessage(e), 'error'); }
  };

  const revoke = async (s) => {
    const ok = await confirm({ title: 'Sign out this session?', message: `${label(s)} (${s.ip}) will be signed out immediately.`, confirmLabel: 'Sign out session', danger: true });
    if (ok) guard(() => api.revokeSession(s.id), 'Session signed out.');
  };

  const revokeOthers = async () => {
    const ok = await confirm({
      title: 'Sign out all other sessions?',
      message: `${others.length} other session${others.length === 1 ? '' : 's'} will be signed out. This device stays signed in.`,
      confirmLabel: 'Sign out others',
      danger: true,
    });
    if (ok) guard(() => api.revokeOtherSessions(), 'Other sessions signed out.');
  };

  const revokeAll = async () => {
    const ok = await confirm({ title: 'Sign out everywhere?', message: 'Every session, including this one, is signed out and you will need to sign in again.', confirmLabel: 'Sign out everywhere', danger: true });
    if (!ok) return;
    try {
      await api.revokeAllSessions();
      await signOut();
      onSignedOut?.();
    } catch (e) {
      if (!isCancelled(e)) toast(errorMessage(e), 'error');
    }
  };

  const saveName = async (e) => {
    e.preventDefault();
    try { await api.renameSession(renaming.id, renaming.name); setRenaming(null); reload(); } catch (err) { toast(errorMessage(err), 'error'); }
  };

  return (
    <section className="card" aria-labelledby="sess-title" aria-busy={loading || undefined}>
      <div className="row-between wrap">
        <h2 id="sess-title">Active sessions and devices</h2>
        <div className="row gap wrap">
          <Button variant="danger" disabled={others.length === 0} onClick={revokeOthers}>Sign out all other sessions</Button>
          <Button variant="secondary" onClick={revokeAll}>Sign out everywhere</Button>
        </div>
      </div>
      <p className="muted">Locations are estimates{' '}from the connection&apos;s address and may be wrong. Rename a device so you recognise it.</p>
      {data.length === 0 ? (
        <EmptyState title="No active sessions">Sign in again to start a session.</EmptyState>
      ) : (
        <ul className="list">
          {data.map((s) => (
            <li key={s.id} className="list-item">
              <div>
                <p className="item-title">
                  {label(s)}
                  {s.current && <span className="pill pill-ok">This device</span>}
                  {s.via && VIA[s.via] && <span className="pill">via {VIA[s.via]}</span>}
                </p>
                <p className="muted">{s.name ? `${s.device} · ` : ''}{s.geo || 'Unknown location'} · IP {s.ip || 'unknown'}</p>
                <p className="muted">Started {formatDateTime(s.createdAt)} · last seen {timeAgo(s.lastSeen)}</p>
              </div>
              <div className="row gap wrap">
                <Button variant="ghost" onClick={() => setRenaming({ id: s.id, name: s.name || '' })}>Rename<span className="sr-only"> {label(s)}</span></Button>
                {!s.current && <Button variant="secondary" onClick={() => revoke(s)}>Revoke<span className="sr-only"> {label(s)}</span></Button>}
              </div>
            </li>
          ))}
        </ul>
      )}
      {data.length > 0 && others.length === 0 && <p className="muted">This is the only active session.</p>}
      <Modal open={!!renaming} title="Name this device" onClose={() => setRenaming(null)}>
        {renaming && (
          <form className="stack" onSubmit={saveName} noValidate>
            <Field label="Device name" value={renaming.name} maxLength={40} placeholder="For example: Home laptop" onChange={(e) => setRenaming({ ...renaming, name: e.target.value })} autoFocus hint="Leave empty to use the detected name." />
            <div className="row gap end">
              <Button variant="ghost" onClick={() => setRenaming(null)}>Cancel</Button>
              <Button type="submit">Save</Button>
            </div>
          </form>
        )}
      </Modal>
    </section>
  );
}

export default SessionsPanel;
