import { useCallback, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, UNAUTHORIZED_EVENT } from '../api';
import { clearToken } from '../auth/auth';
import { useAuth } from '../context/contexts';
import { useAsync } from '../hooks/useAsync';
import ActivityPanel from '../components/dashboard/ActivityPanel';
import OverviewPanel from '../components/dashboard/OverviewPanel';
import PasswordPanel from '../components/dashboard/PasswordPanel';
import RecoveryPanel from '../components/dashboard/RecoveryPanel';
import SessionsPanel from '../components/dashboard/SessionsPanel';
import SignInPanel from '../components/dashboard/SignInPanel';
import TokensPanel from '../components/dashboard/TokensPanel';
import Alert from '../components/ui/Alert';
import Tabs from '../components/ui/Tabs';

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'signin', label: 'Sign-in methods' },
  { id: 'recovery', label: 'Recovery' },
  { id: 'sessions', label: 'Sessions' },
  { id: 'activity', label: 'Activity' },
  { id: 'password', label: 'Password' },
  { id: 'tokens', label: 'API tokens' },
];
const PENDING_TABS = TABS.filter((t) => ['signin', 'password'].includes(t.id));

// Security dashboard. Deliberately static (no parallax / motion) because it is a dense, data-heavy screen.
// An account with pending requirements (forced password change, required 2FA) only sees the screens that fix them.
function Dashboard() {
  const { user, refresh } = useAuth();
  const navigate = useNavigate();
  const [tab, setTab] = useState('overview');
  const loadSecurity = useCallback(() => api.security(), []);
  const { data: security, error, loading, reload, setData } = useAsync(loadSecurity);

  const requirements = security?.requirements ?? user?.requirements ?? [];
  const pending = requirements.length > 0;
  const tabs = (pending ? PENDING_TABS : TABS).map((t) => (t.id === 'overview' && security?.unreviewedAlerts ? { ...t, badge: security.unreviewedAlerts } : t));
  const active = tabs.some((t) => t.id === tab) ? tab : (requirements[0]?.id === 'change-password' ? 'password' : 'signin');

  const requirementsChanged = async () => { await refresh(); reload(); };
  const afterSignedOut = () => { clearToken(); window.dispatchEvent(new Event(UNAUTHORIZED_EVENT)); navigate('/login', { replace: true }); };

  return (
    <div className="container dashboard">
      <div className="dash-head">
        <p className="eyebrow">Security dashboard</p>
        <h1>{user ? <>Signed in as <span className="email">{user.email}</span></> : 'Your account'}</h1>
        {user?.role === 'admin' && <p><Link className="btn btn-secondary btn-sm" to="/admin">Open the admin console</Link></p>}
      </div>

      {pending && (
        <Alert type="warning">
          <strong>Action required.</strong> {requirements.map((r) => r.message).join(' ')}
        </Alert>
      )}

      <Tabs id="dash" label="Dashboard sections" tabs={tabs} active={active} onChange={setTab} />

      <div id={`dash-panel-${active}`} role="tabpanel" aria-labelledby={`dash-tab-${active}`} tabIndex={0} className="tab-panel">
        {active === 'overview' && <OverviewPanel security={security} loading={loading} error={error} reload={reload} goTo={setTab} onSignedOut={afterSignedOut} />}
        {active === 'signin' && <SignInPanel security={security} error={error} reload={reload} email={user?.email || ''} onChange={setData} onRequirementsChanged={requirementsChanged} />}
        {active === 'recovery' && <RecoveryPanel security={security} error={error} reload={reload} goTo={setTab} />}
        {active === 'sessions' && <SessionsPanel onSignedOut={afterSignedOut} />}
        {active === 'activity' && <ActivityPanel />}
        {active === 'password' && <PasswordPanel security={security} requirement={requirements.find((r) => r.id === 'change-password')} onChanged={requirementsChanged} />}
        {active === 'tokens' && <TokensPanel />}
      </div>
    </div>
  );
}

export default Dashboard;
