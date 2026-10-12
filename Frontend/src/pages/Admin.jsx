import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/contexts';
import AdminAudit from '../components/admin/AdminAudit';
import AdminOverview from '../components/admin/AdminOverview';
import AdminPolicy from '../components/admin/AdminPolicy';
import AdminUsers from '../components/admin/AdminUsers';
import Tabs from '../components/ui/Tabs';

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'users', label: 'Users' },
  { id: 'audit', label: 'Audit log' },
  { id: 'policy', label: 'Security policy' },
];

// Administrator console. Same restraint as the dashboard: no motion, dense and keyboard friendly.
function Admin() {
  const { user } = useAuth();
  const [tab, setTab] = useState('overview');
  const [usersInitial, setUsersInitial] = useState({});

  if (user?.role !== 'admin') {
    return (
      <div className="container section not-found">
        <h1>Administrator access required</h1>
        <p className="muted">Your account does not have access to this page.</p>
        <Link className="btn btn-primary" to="/dashboard">Back to your dashboard</Link>
      </div>
    );
  }

  const goTo = (id, initial = {}) => { setUsersInitial(initial); setTab(id); };

  return (
    <div className="container dashboard">
      <div className="dash-head">
        <p className="eyebrow">Administrator console</p>
        <h1>Manage accounts and security</h1>
        <p className="muted">Every action here is confirmed, needs a recent re-confirmation and is written to the audit log.</p>
      </div>
      <Tabs id="adm" label="Admin sections" tabs={TABS} active={tab} onChange={(id) => goTo(id)} />
      <div id={`adm-panel-${tab}`} role="tabpanel" aria-labelledby={`adm-tab-${tab}`} tabIndex={0} className="tab-panel">
        {tab === 'overview' && <AdminOverview goTo={goTo} />}
        {tab === 'users' && <AdminUsers key={JSON.stringify(usersInitial)} currentId={user.id} initial={usersInitial} />}
        {tab === 'audit' && <AdminAudit />}
        {tab === 'policy' && <AdminPolicy />}
      </div>
    </div>
  );
}

export default Admin;
