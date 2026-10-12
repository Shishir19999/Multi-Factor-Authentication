import { useCallback, useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { useToast } from '../../context/contexts';
import { useAsync } from '../../hooks/useAsync';
import { downloadText } from '../../lib/download';
import { EVENT_CATEGORIES, formatDateTime } from '../../lib/format';
import Button from '../ui/Button';
import Field from '../ui/Field';
import Pagination from '../ui/Pagination';
import SelectField from '../ui/SelectField';
import { EmptyState, ErrorState, Loading } from '../ui/States';

const CATEGORY_OPTIONS = [{ value: '', label: 'All categories' }, ...EVENT_CATEGORIES.map(([value, label]) => ({ value, label }))];
const SEVERITY_OPTIONS = [{ value: '', label: 'Any severity' }, { value: 'info', label: 'Info' }, { value: 'warn', label: 'Warning' }, { value: 'critical', label: 'Critical' }];
const RESULT_OPTIONS = [{ value: '', label: 'Any result' }, { value: 'true', label: 'Success' }, { value: 'false', label: 'Failed' }];
const SEV_PILL = { info: '', warn: 'pill-warn', critical: 'pill-bad' };
const EMPTY = { q: '', category: '', severity: '', ok: '', from: '', to: '' };

// Audit log with filters, pagination and CSV export (formula-safe on the server and in the preview).
function AdminAudit() {
  const { toast } = useToast();
  const [form, setForm] = useState(EMPTY);
  const [applied, setApplied] = useState(EMPTY);
  const [page, setPage] = useState(1);
  const [exporting, setExporting] = useState(false);
  const params = useCallback(() => Object.fromEntries(Object.entries(applied).filter(([, v]) => v)), [applied]);
  const load = useCallback(() => api.adminAudit({ ...params(), page }), [params, page]);
  const { data, error, loading, reload } = useAsync(load);
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const exportCsv = async () => {
    setExporting(true);
    try {
      const file = await api.adminAuditExport(params());
      downloadText(file.filename, file.text, file.mime);
      toast('Audit log exported.', 'success');
    } catch (e) {
      if (!isCancelled(e)) toast(errorMessage(e), 'error');
    } finally {
      setExporting(false);
    }
  };

  return (
    <section className="card" aria-labelledby="aa-title" aria-busy={loading || undefined}>
      <div className="row-between wrap">
        <h2 id="aa-title">Audit log</h2>
        <Button variant="secondary" onClick={exportCsv} loading={exporting}>Export CSV</Button>
      </div>
      <form className="filters" onSubmit={(e) => { e.preventDefault(); setApplied(form); setPage(1); }}>
        <Field label="E-mail or IP" type="search" value={form.q} onChange={set('q')} placeholder="name@example.com" />
        <SelectField label="Category" value={form.category} onChange={set('category')} options={CATEGORY_OPTIONS} />
        <SelectField label="Severity" value={form.severity} onChange={set('severity')} options={SEVERITY_OPTIONS} />
        <SelectField label="Result" value={form.ok} onChange={set('ok')} options={RESULT_OPTIONS} />
        <Field label="From" type="date" value={form.from} onChange={set('from')} />
        <Field label="To" type="date" value={form.to} onChange={set('to')} />
        <div className="filter-actions">
          <Button type="submit">Apply filters</Button>
          <Button variant="ghost" onClick={() => { setForm(EMPTY); setApplied(EMPTY); setPage(1); }}>Clear</Button>
        </div>
      </form>
      {error ? <ErrorState message={error.message} onRetry={reload} /> : !data ? <Loading label="Loading audit log" lines={8} /> : data.events.length === 0 ? (
        <EmptyState title="No events match">Change or clear the filters.</EmptyState>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <caption className="sr-only">Audit events, newest first</caption>
              <thead><tr><th scope="col">Time</th><th scope="col">Event</th><th scope="col">Who</th><th scope="col">Where</th><th scope="col">Result</th></tr></thead>
              <tbody>
                {data.events.map((e) => (
                  <tr key={e.id}>
                    <td data-label="Time">{formatDateTime(e.at)}</td>
                    <th scope="row" data-label="Event">{e.label}{SEV_PILL[e.severity] !== undefined && e.severity !== 'info' && <span className={`pill ${SEV_PILL[e.severity]}`}>{e.severity === 'critical' ? 'Critical' : 'Warning'}</span>}</th>
                    <td data-label="Who">{e.actorEmail && e.targetEmail && e.actorEmail !== e.targetEmail ? `${e.actorEmail} → ${e.targetEmail}` : (e.targetEmail || e.actorEmail || (e.meta?.email ? `${e.meta.email} (unknown)` : '—'))}</td>
                    <td data-label="Where">{e.device || '—'} · {e.geo || 'unknown'} · {e.ip || '—'}</td>
                    <td data-label="Result"><span className={`pill ${e.ok ? 'pill-ok' : 'pill-bad'}`}>{e.ok ? 'Success' : 'Failed'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={data.page} pages={data.pages} total={data.total} onPage={setPage} noun="events" />
        </>
      )}
    </section>
  );
}

export default AdminAudit;
