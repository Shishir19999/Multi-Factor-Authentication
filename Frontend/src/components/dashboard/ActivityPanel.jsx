import { useCallback, useState } from 'react';
import { api } from '../../api';
import { errorMessage, isCancelled } from '../../api/errors';
import { useToast } from '../../context/contexts';
import { useAsync } from '../../hooks/useAsync';
import { downloadText } from '../../lib/download';
import { describeDevice, EVENT_CATEGORIES, eventLabel, formatDateTime } from '../../lib/format';
import Button from '../ui/Button';
import SelectField from '../ui/SelectField';
import { EmptyState, ErrorState, Loading } from '../ui/States';

const CATEGORY_OPTIONS = [{ value: '', label: 'All activity' }, ...EVENT_CATEGORIES.map(([value, label]) => ({ value, label }))];

// Account activity with category filter and export (CSV or JSON). Exporting asks for a recent confirmation.
function ActivityPanel() {
  const { toast } = useToast();
  const [category, setCategory] = useState('');
  const [onlyProblems, setOnlyProblems] = useState(false);
  const [exporting, setExporting] = useState('');
  const load = useCallback(() => api.activity({ category: category || undefined }), [category]);
  const { data, error, loading, reload } = useAsync(load);

  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return <Loading label="Loading account activity" lines={6} />;

  const rows = onlyProblems ? data.filter((e) => !e.ok || e.severity !== 'info') : data;

  const exportAs = async (format) => {
    setExporting(format);
    try {
      const file = await api.exportActivity({ format });
      downloadText(file.filename, file.text, file.mime);
      toast(`Exported ${file.filename}.`, 'success');
    } catch (e) {
      if (!isCancelled(e)) toast(errorMessage(e), 'error');
    } finally {
      setExporting('');
    }
  };

  return (
    <section className="card" aria-labelledby="act-title" aria-busy={loading || undefined}>
      <div className="row-between wrap">
        <h2 id="act-title">Account activity</h2>
        <div className="row gap wrap">
          <Button variant="secondary" onClick={() => exportAs('csv')} loading={exporting === 'csv'}>Export CSV</Button>
          <Button variant="secondary" onClick={() => exportAs('json')} loading={exporting === 'json'}>Export JSON</Button>
          <Button variant="secondary" onClick={reload} loading={loading}>Refresh</Button>
        </div>
      </div>
      <div className="filters">
        <SelectField label="Show" value={category} onChange={(e) => setCategory(e.target.value)} options={CATEGORY_OPTIONS} />
        <label className="check filter-check">
          <input type="checkbox" checked={onlyProblems} onChange={(e) => setOnlyProblems(e.target.checked)} />
          <span>Only failures and warnings</span>
        </label>
      </div>
      {rows.length === 0 ? (
        <EmptyState title="No activity to show">Sign-ins and security changes will be listed here.</EmptyState>
      ) : (
        <ul className="list">
          {rows.map((e) => (
            <li key={e.id} className="list-item">
              <div>
                <p className="item-title">
                  <span className={`status-dot ${e.ok ? 'ok' : 'bad'}`} aria-hidden="true" />
                  {e.label || eventLabel(e.event)}
                  <span className={`pill ${e.ok ? 'pill-ok' : 'pill-bad'}`}>{e.ok ? 'Success' : 'Failed'}</span>
                  {e.byAdmin && <span className="pill pill-warn">By an administrator</span>}
                </p>
                <p className="muted">{formatDateTime(e.at)} · {e.device || describeDevice(e.userAgent)} · {e.geo || 'Unknown location'} · IP {e.ip || 'unknown'}</p>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default ActivityPanel;
