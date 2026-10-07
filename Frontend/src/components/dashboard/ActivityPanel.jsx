import { useCallback } from 'react';
import { api } from '../../api';
import { useAsync } from '../../hooks/useAsync';
import { describeDevice, eventLabel, formatDateTime } from '../../lib/format';
import Button from '../ui/Button';
import { EmptyState, ErrorState, Loading } from '../ui/States';

function ActivityPanel() {
  const load = useCallback(() => api.activity(), []);
  const { data, error, loading, reload } = useAsync(load);

  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return <Loading label="Loading sign-in activity" lines={6} />;

  return (
    <section className="card" aria-labelledby="act-title" aria-busy={loading || undefined}>
      <div className="row-between wrap">
        <h2 id="act-title">Recent sign-in activity</h2>
        <Button variant="secondary" onClick={reload} loading={loading}>Refresh</Button>
      </div>
      {data.length === 0 ? (
        <EmptyState title="No activity yet">Sign-ins and security changes will be listed here.</EmptyState>
      ) : (
        <ul className="list">
          {data.map((e) => (
            <li key={e.id} className="list-item">
              <div>
                <p className="item-title">
                  <span className={`status-dot ${e.ok ? 'ok' : 'bad'}`} aria-hidden="true" />
                  {eventLabel(e.event)}
                  <span className={`pill ${e.ok ? 'pill-ok' : 'pill-bad'}`}>{e.ok ? 'Success' : 'Failed'}</span>
                </p>
                <p className="muted">{formatDateTime(e.at)} · {describeDevice(e.userAgent)} · IP {e.ip || 'unknown'}</p>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default ActivityPanel;
