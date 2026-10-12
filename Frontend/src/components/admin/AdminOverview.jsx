import { useCallback } from 'react';
import { api } from '../../api';
import { useAsync } from '../../hooks/useAsync';
import Button from '../ui/Button';
import { ErrorState, Loading } from '../ui/States';

function Tile({ label, value, note, tone }) {
  return (
    <div className={`tile${tone ? ` tile-${tone}` : ''}`}>
      <p className="tile-value">{value}</p>
      <p className="tile-label">{label}</p>
      {note && <p className="muted tile-note">{note}</p>}
    </div>
  );
}

// 7-day sign-in chart: bars for successes and failures, with a text table for screen readers.
function Chart({ series }) {
  const max = Math.max(1, ...series.map((d) => Math.max(d.signIns, d.failures)));
  const w = 520; const h = 160; const gap = w / series.length;
  return (
    <figure className="chart">
      <figcaption>Sign-ins and failures, last 7 days</figcaption>
      <svg viewBox={`0 0 ${w} ${h + 28}`} role="img" aria-label="Bar chart of daily sign-ins and failed sign-ins for the last 7 days. The same numbers are in the table below.">
        {series.map((d, i) => {
          const x = i * gap + gap / 2;
          const a = (d.signIns / max) * h;
          const b = (d.failures / max) * h;
          return (
            <g key={d.date}>
              <rect x={x - 22} y={h - a} width="20" height={a} className="bar-ok" rx="3" />
              <rect x={x + 2} y={h - b} width="20" height={b} className="bar-bad" rx="3" />
              <text x={x} y={h + 18} textAnchor="middle" className="chart-label">{d.date.slice(5)}</text>
            </g>
          );
        })}
      </svg>
      <p className="legend"><span className="swatch swatch-ok" aria-hidden="true" /> Successful <span className="swatch swatch-bad" aria-hidden="true" /> Failed</p>
      <table className="sr-only">
        <caption>Daily sign-ins and failures</caption>
        <thead><tr><th scope="col">Date</th><th scope="col">Successful</th><th scope="col">Failed</th></tr></thead>
        <tbody>{series.map((d) => <tr key={d.date}><th scope="row">{d.date}</th><td>{d.signIns}</td><td>{d.failures}</td></tr>)}</tbody>
      </table>
    </figure>
  );
}

function AdminOverview({ goTo }) {
  const load = useCallback(() => api.adminStats(), []);
  const { data: s, error, reload } = useAsync(load);
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!s) return <Loading label="Loading statistics" lines={6} />;
  const pct = s.users ? Math.round((s.with2fa / s.users) * 100) : 0;
  return (
    <div className="stack-lg">
      <div className="tiles">
        <Tile label="Accounts" value={s.users} note={`${s.admins} administrator${s.admins === 1 ? '' : 's'}`} />
        <Tile label="With a second step" value={`${pct}%`} note={`${s.withPasskeys} with a passkey`} />
        <Tile label="Locked now" value={s.locked + s.adminLocked} tone={s.locked + s.adminLocked ? 'warn' : undefined} note={`${s.adminLocked} by an administrator`} />
        <Tile label="Help requests" value={s.assist} tone={s.assist ? 'warn' : undefined} note="People who asked for admin help" />
        <Tile label="Failed sign-ins (24 h)" value={s.failures24h} tone={s.failures24h > 5 ? 'bad' : undefined} />
        <Tile label="New-device alerts (24 h)" value={s.alerts24h} />
      </div>
      <section className="card" aria-labelledby="ao-chart">
        <div className="row-between wrap">
          <h2 id="ao-chart">Sign-in activity</h2>
          <div className="row gap wrap">
            {s.assist > 0 && <Button variant="secondary" onClick={() => goTo('users', { assist: true })}>Review help requests</Button>}
            <Button variant="secondary" onClick={reload}>Refresh</Button>
          </div>
        </div>
        <Chart series={s.series} />
        <p className="muted">{s.events24h} audit events in the last 24 hours.</p>
      </section>
    </div>
  );
}

export default AdminOverview;
