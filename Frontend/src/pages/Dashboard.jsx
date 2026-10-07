import { useCallback, useRef, useState } from 'react';
import { api } from '../api';
import { useAuth } from '../context/contexts';
import { useAsync } from '../hooks/useAsync';
import ActivityPanel from '../components/dashboard/ActivityPanel';
import OverviewPanel from '../components/dashboard/OverviewPanel';
import PasswordPanel from '../components/dashboard/PasswordPanel';
import SessionsPanel from '../components/dashboard/SessionsPanel';
import TwoFactorPanel from '../components/dashboard/TwoFactorPanel';

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'twofactor', label: 'Two-step' },
  { id: 'sessions', label: 'Sessions' },
  { id: 'activity', label: 'Activity' },
  { id: 'password', label: 'Password' },
];

// Security dashboard. Deliberately static (no parallax / motion) because it is a dense, data-heavy screen.
function Dashboard() {
  const { user } = useAuth();
  const [tab, setTab] = useState('overview');
  const tabRefs = useRef({});
  const loadSecurity = useCallback(() => api.security(), []);
  const { data: security, error, loading, reload, setData } = useAsync(loadSecurity);

  const onKeyDown = (e) => {
    const i = TABS.findIndex((t) => t.id === tab);
    let next = null;
    if (e.key === 'ArrowRight') next = TABS[(i + 1) % TABS.length];
    if (e.key === 'ArrowLeft') next = TABS[(i - 1 + TABS.length) % TABS.length];
    if (e.key === 'Home') next = TABS[0];
    if (e.key === 'End') next = TABS[TABS.length - 1];
    if (next) { e.preventDefault(); setTab(next.id); tabRefs.current[next.id]?.focus(); }
  };

  return (
    <div className="container dashboard">
      <div className="dash-head">
        <p className="eyebrow">Security dashboard</p>
        <h1>{user ? <>Signed in as <span className="email">{user.email}</span></> : 'Your account'}</h1>
      </div>

      <div className="tabs" role="tablist" aria-label="Dashboard sections" onKeyDown={onKeyDown}>
        {TABS.map((t) => (
          <button
            key={t.id}
            ref={(el) => { tabRefs.current[t.id] = el; }}
            id={`tab-${t.id}`}
            role="tab"
            type="button"
            className="tab"
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`} tabIndex={0} className="tab-panel">
        {tab === 'overview' && <OverviewPanel security={security} loading={loading} error={error} reload={reload} goTo={setTab} />}
        {tab === 'twofactor' && <TwoFactorPanel security={security} error={error} reload={reload} email={user?.email || ''} onChange={setData} />}
        {tab === 'sessions' && <SessionsPanel />}
        {tab === 'activity' && <ActivityPanel />}
        {tab === 'password' && <PasswordPanel onChanged={reload} />}
      </div>
    </div>
  );
}

export default Dashboard;
