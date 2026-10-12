import { useCallback, useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { useAsync } from '../../hooks/useAsync';
import { useConfirm, useToast } from '../../context/contexts';
import { formatDateTime, METHOD_LABELS, ROLE_LABELS, STATUS_LABELS, timeAgo } from '../../lib/format';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Field from '../ui/Field';
import Modal from '../ui/Modal';
import Pagination from '../ui/Pagination';
import SelectField from '../ui/SelectField';
import { EmptyState, ErrorState, Loading } from '../ui/States';

const STATUS_PILL = { active: 'pill-ok', locked: 'pill-warn', 'admin-locked': 'pill-bad' };

// Detail dialog with the administrator actions (every action is confirmed, step-up protected and audited).
function UserDialog({ id, currentId, onClose, onChanged }) {
  const { toast } = useToast();
  const { confirm } = useConfirm();
  const load = useCallback(() => api.adminUser(id), [id]);
  const { data, error, reload } = useAsync(load);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState('');

  const u = data?.user;
  const self = id === currentId;

  const act = async (action, body, { title, message, confirmLabel, danger, done }) => {
    const ok = await confirm({ title, message, confirmLabel, danger });
    if (!ok) return;
    setBusy(action);
    try {
      await api.adminAction(id, action, body);
      toast(done, 'success');
      reload();
      onChanged();
    } catch (e) {
      if (!isCancelled(e)) toast(errorMessage(e), 'error');
    } finally {
      setBusy('');
    }
  };

  return (
    <Modal open title={u ? `Manage ${u.email}` : 'Manage user'} onClose={onClose} wide footer={<Button onClick={onClose}>Close</Button>}>
      {error ? <ErrorState message={error.message} onRetry={reload} /> : !u ? <Loading label="Loading user" lines={5} /> : (
        <div className="stack">
          <dl className="kv">
            <div><dt>Status</dt><dd><span className={`pill ${STATUS_PILL[u.status]}`}>{STATUS_LABELS[u.status]}</span></dd></div>
            <div><dt>Role</dt><dd>{ROLE_LABELS[u.role]}</dd></div>
            <div><dt>Second step</dt><dd>{METHOD_LABELS[u.twoFactorMethod]}{u.passkeys ? ` + ${u.passkeys} passkey${u.passkeys === 1 ? '' : 's'}` : ''}</dd></div>
            <div><dt>Active sessions</dt><dd>{u.sessions}</dd></div>
            <div><dt>Last sign-in</dt><dd>{u.lastLoginAt ? formatDateTime(u.lastLoginAt) : 'Never'}</dd></div>
            <div><dt>Recovery e-mail</dt><dd>{u.recoveryEmail || 'None'}</dd></div>
            {u.mustChangePassword && <div><dt>Pending</dt><dd>Password change required</dd></div>}
            {u.mustEnrollTwoFactor && <div><dt>Pending</dt><dd>Two-step enrolment required</dd></div>}
            {u.adminLockReason && <div><dt>Lock reason</dt><dd>{u.adminLockReason}</dd></div>}
          </dl>

          {u.assistRequestedAt && (
            <Alert type="warning">
              <strong>Help requested {timeAgo(u.assistRequestedAt)}.</strong> {u.assistMessage ? `"${u.assistMessage}"` : 'No note.'} Verify the person&apos;s identity before issuing a code.
              <div className="row gap wrap assist-actions">
                <Button variant="secondary" loading={busy === 'issue-recovery'} onClick={() => act('issue-recovery', {}, { title: 'Send a recovery code?', message: `A one-time recovery code is e-mailed to ${u.email}.`, confirmLabel: 'Send code', done: 'Recovery code sent.' })}>Send recovery code</Button>
                <Button variant="ghost" onClick={() => act('clear-assist', {}, { title: 'Dismiss the request?', message: 'The help request is cleared without any other change.', confirmLabel: 'Dismiss', done: 'Request dismissed.' })}>Dismiss</Button>
              </div>
            </Alert>
          )}

          <h3>Actions</h3>
          {self && <p className="muted">This is your own account: locking and role changes are disabled.</p>}
          <div className="action-grid">
            {u.status === 'admin-locked' ? (
              <Button variant="secondary" loading={busy === 'unlock'} onClick={() => act('unlock', {}, { title: 'Unlock this account?', message: 'The person can sign in again.', confirmLabel: 'Unlock', done: 'Account unlocked.' })}>Unlock account</Button>
            ) : u.status === 'locked' ? (
              <Button variant="secondary" loading={busy === 'unlock'} onClick={() => act('unlock', {}, { title: 'Clear the lockout?', message: 'The failed-attempt lockout is cleared.', confirmLabel: 'Clear lockout', done: 'Lockout cleared.' })}>Clear lockout</Button>
            ) : null}
            <Button variant="secondary" loading={busy === 'force-reset'} onClick={() => act('force-reset', {}, { title: 'Force a password reset?', message: 'Every session is signed out and a new password is required at the next sign-in.', confirmLabel: 'Force reset', danger: true, done: 'Password reset forced.' })}>Force password reset</Button>
            <Button variant="secondary" loading={busy === 'force-enroll'} onClick={() => act('force-enroll', {}, { title: 'Require two-step enrolment?', message: 'If the account has no second step, it must set one up before continuing.', confirmLabel: 'Require enrolment', done: 'Enrolment required.' })}>Force 2FA enrolment</Button>
            <Button variant="secondary" loading={busy === 'reset-2fa'} onClick={() => act('reset-2fa', {}, { title: 'Reset the second step?', message: 'Authenticator app, backup codes, passkeys and trusted devices are removed and sessions are signed out. The account falls back to e-mail codes.', confirmLabel: 'Reset second step', danger: true, done: 'Second step reset.' })}>Reset 2FA</Button>
            <Button variant="secondary" loading={busy === 'revoke-sessions'} onClick={() => act('revoke-sessions', {}, { title: 'Sign out every session?', message: `${u.sessions} active session(s) are signed out.`, confirmLabel: 'Revoke sessions', danger: true, done: 'Sessions revoked.' })}>Revoke sessions</Button>
            <Button variant="secondary" loading={busy === 'issue-recovery'} onClick={() => act('issue-recovery', {}, { title: 'Send a recovery code?', message: `A one-time recovery code is e-mailed to ${u.email}.`, confirmLabel: 'Send code', done: 'Recovery code sent.' })}>Send recovery code</Button>
            <Button variant="secondary" disabled={self} loading={busy === 'role'} onClick={() => act('role', { role: u.role === 'admin' ? 'user' : 'admin' }, { title: u.role === 'admin' ? 'Make this account a member?' : 'Make this account an administrator?', message: u.role === 'admin' ? 'They lose access to the admin console.' : 'They get full access to the admin console.', confirmLabel: 'Change role', danger: u.role !== 'admin', done: 'Role changed.' })}>{u.role === 'admin' ? 'Make member' : 'Make administrator'}</Button>
          </div>
          {u.status !== 'admin-locked' && (
            <form className="row gap wrap lock-form" onSubmit={(e) => { e.preventDefault(); act('lock', { reason }, { title: 'Lock this account?', message: 'The person is signed out everywhere and cannot sign in until you unlock it.', confirmLabel: 'Lock account', danger: true, done: 'Account locked.' }); }}>
              <Field label="Reason (optional)" value={reason} maxLength={200} onChange={(e) => setReason(e.target.value)} disabled={self} />
              <Button type="submit" variant="danger" disabled={self} loading={busy === 'lock'}>Lock account</Button>
            </form>
          )}

          <h3>Recent activity</h3>
          {data.events.length === 0 ? <p className="muted">No activity yet.</p> : (
            <ul className="list compact">
              {data.events.map((e) => (
                <li key={e.id} className="list-item">
                  <span>{e.label}{e.byAdmin && ' (administrator)'}</span>
                  <span className="muted">{formatDateTime(e.at)} · {e.geo || 'unknown'}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Modal>
  );
}

const ROLE_OPTIONS = [{ value: '', label: 'Any role' }, { value: 'user', label: 'Members' }, { value: 'admin', label: 'Administrators' }];
const STATUS_OPTIONS = [{ value: '', label: 'Any status' }, { value: 'active', label: 'Active' }, { value: 'locked', label: 'Locked (attempts)' }, { value: 'admin-locked', label: 'Locked by admin' }];

function AdminUsers({ currentId, initial = {} }) {
  const [q, setQ] = useState('');
  const [role, setRole] = useState('');
  const [status, setStatus] = useState('');
  const [assist, setAssist] = useState(!!initial.assist);
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState(null);
  const load = useCallback(() => api.adminUsers({ q: q || undefined, role: role || undefined, status: status || undefined, assist: assist || undefined, page }), [q, role, status, assist, page]);
  const { data, error, loading, reload } = useAsync(load);
  const set = (fn) => (e) => { fn(e.target.value); setPage(1); };

  return (
    <section className="card" aria-labelledby="au-title" aria-busy={loading || undefined}>
      <h2 id="au-title">Users</h2>
      <div className="filters">
        <Field label="Search by e-mail" type="search" value={q} onChange={set(setQ)} placeholder="name@example.com" />
        <SelectField label="Role" value={role} onChange={set(setRole)} options={ROLE_OPTIONS} />
        <SelectField label="Status" value={status} onChange={set(setStatus)} options={STATUS_OPTIONS} />
        <label className="check filter-check">
          <input type="checkbox" checked={assist} onChange={(e) => { setAssist(e.target.checked); setPage(1); }} />
          <span>Help requests only</span>
        </label>
      </div>
      {error ? <ErrorState message={error.message} onRetry={reload} /> : !data ? <Loading label="Loading users" lines={6} /> : data.users.length === 0 ? (
        <EmptyState title="No users match">Try a different search or filter.</EmptyState>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <caption className="sr-only">User accounts</caption>
              <thead><tr><th scope="col">E-mail</th><th scope="col">Role</th><th scope="col">Second step</th><th scope="col">Status</th><th scope="col">Last sign-in</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {data.users.map((u) => (
                  <tr key={u.id}>
                    <th scope="row" data-label="E-mail">{u.email}{u.assistRequestedAt && <span className="pill pill-warn">Needs help</span>}</th>
                    <td data-label="Role">{ROLE_LABELS[u.role]}</td>
                    <td data-label="Second step">{METHOD_LABELS[u.twoFactorMethod]}{u.passkeys ? ` + passkey` : ''}</td>
                    <td data-label="Status"><span className={`pill ${STATUS_PILL[u.status]}`}>{u.status === 'active' ? 'Active' : u.status === 'locked' ? 'Locked' : 'Admin-locked'}</span></td>
                    <td data-label="Last sign-in">{u.lastLoginAt ? timeAgo(u.lastLoginAt) : 'Never'}</td>
                    <td data-label=""><Button variant="secondary" onClick={() => setOpen(u.id)}>Manage<span className="sr-only"> {u.email}</span></Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={data.page} pages={data.pages} total={data.total} onPage={setPage} noun="users" />
        </>
      )}
      {open && <UserDialog id={open} currentId={currentId} onClose={() => setOpen(null)} onChanged={reload} />}
    </section>
  );
}

export default AdminUsers;
