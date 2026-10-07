import { useCallback } from 'react';
import { api } from '../../api';
import { useConfirm, useToast } from '../../context/contexts';
import { useAsync } from '../../hooks/useAsync';
import { describeDevice, formatDateTime, timeAgo } from '../../lib/format';
import Button from '../ui/Button';
import { EmptyState, ErrorState, Loading } from '../ui/States';

function SessionsPanel() {
  const { toast } = useToast();
  const { confirm } = useConfirm();
  const load = useCallback(() => api.sessions(), []);
  const { data, error, loading, reload } = useAsync(load);

  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return <Loading label="Loading sessions" lines={5} />;

  const others = data.filter((s) => !s.current);

  const revoke = async (s) => {
    const ok = await confirm({
      title: 'Sign out this session?',
      message: `${describeDevice(s.userAgent)} (${s.ip}) will be signed out immediately.`,
      confirmLabel: 'Sign out session',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.revokeSession(s.id);
      toast('Session signed out.', 'success');
      reload();
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const revokeAll = async () => {
    const ok = await confirm({
      title: 'Sign out all other sessions?',
      message: `${others.length} other session${others.length === 1 ? '' : 's'} will be signed out. This device stays signed in.`,
      confirmLabel: 'Sign out others',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.revokeOtherSessions();
      toast('Other sessions signed out.', 'success');
      reload();
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <section className="card" aria-labelledby="sess-title" aria-busy={loading || undefined}>
      <div className="row-between wrap">
        <h2 id="sess-title">Active sessions</h2>
        <Button variant="danger" disabled={others.length === 0} onClick={revokeAll}>Sign out all other sessions</Button>
      </div>
      {data.length === 0 ? (
        <EmptyState title="No active sessions">Sign in again to start a session.</EmptyState>
      ) : (
        <ul className="list">
          {data.map((s) => (
            <li key={s.id} className="list-item">
              <div>
                <p className="item-title">
                  {describeDevice(s.userAgent)}
                  {s.current && <span className="pill pill-ok">This device</span>}
                </p>
                <p className="muted">IP {s.ip || 'unknown'} · started {formatDateTime(s.createdAt)} · active {timeAgo(s.lastSeen)}</p>
              </div>
              {!s.current && <Button variant="secondary" onClick={() => revoke(s)}>Revoke<span className="sr-only"> {describeDevice(s.userAgent)}</span></Button>}
            </li>
          ))}
        </ul>
      )}
      {data.length > 0 && others.length === 0 && <p className="muted">This is the only active session.</p>}
    </section>
  );
}

export default SessionsPanel;
