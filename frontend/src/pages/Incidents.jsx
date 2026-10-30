import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { tracker } from '../api.js';
import { usePolling } from '../hooks.js';
import { Card, ErrorBanner } from '../components/Card.jsx';
import { SeverityBadge, StatusBadge } from '../components/Badges.jsx';
import { SEVERITIES, STATUSES, formatTime, label, timeAgo } from '../format.js';
import NewIncidentForm from './NewIncidentForm.jsx';

export default function Incidents() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [showNew, setShowNew] = useState(false);

  const filters = {
    status: params.getAll('status'),
    severity: params.getAll('severity'),
    assignee: params.get('assignee') || '',
    q: params.get('q') || '',
    page: Number(params.get('page') || 0),
  };
  const key = params.toString();
  const { data, error, loading, reload } = usePolling(
    () => tracker.list({ ...filters, size: 20 }), 15000, [key]);
  const analysts = usePolling(() => tracker.analysts());

  const update = (name, value) => {
    const next = new URLSearchParams(params);
    next.delete(name);
    next.delete('page');
    (Array.isArray(value) ? value : [value]).filter(Boolean).forEach((v) => next.append(name, v));
    setParams(next);
  };
  const toggle = (name, value) => {
    const current = params.getAll(name);
    update(name, current.includes(value) ? current.filter((v) => v !== value) : [...current, value]);
  };

  return (
    <div className="page">
      <header className="page-header">
        <h1>Incidents</h1>
        <button className="btn primary" onClick={() => setShowNew((v) => !v)}>
          {showNew ? 'Cancel' : '+ New incident'}
        </button>
      </header>

      {showNew && (
        <NewIncidentForm onCreated={(inc) => navigate(`/incidents/${inc.id}`)} />
      )}

      <Card>
        <div className="filters">
          <div className="chip-group">
            {STATUSES.map((s) => (
              <button key={s} className={`chip ${filters.status.includes(s) ? 'on' : ''}`}
                      onClick={() => toggle('status', s)}>{label(s)}</button>
            ))}
          </div>
          <div className="chip-group">
            {SEVERITIES.map((s) => (
              <button key={s} className={`chip sev-chip-${s.toLowerCase()} ${filters.severity.includes(s) ? 'on' : ''}`}
                      onClick={() => toggle('severity', s)}>{s}</button>
            ))}
          </div>
          <select value={filters.assignee} onChange={(e) => update('assignee', e.target.value)}>
            <option value="">Any assignee</option>
            <option value="unassigned">Unassigned</option>
            {analysts.data?.map((a) => <option key={a.username} value={a.username}>{a.displayName}</option>)}
          </select>
          <input placeholder="Search title / description" defaultValue={filters.q}
                 onKeyDown={(e) => e.key === 'Enter' && update('q', e.target.value)} />
          <button className="btn" onClick={reload}>Refresh</button>
        </div>
      </Card>

      <ErrorBanner error={error} />

      <Card>
        <div className="table-wrap">
          <table className="table clickable-rows">
            <thead>
              <tr>
                <th>#</th><th>Severity</th><th>Title</th><th>Status</th><th>Rule</th>
                <th>User</th><th>Source IP</th><th>Assignee</th><th>Hits</th><th>Created</th>
              </tr>
            </thead>
            <tbody>
              {data?.content?.map((i) => (
                <tr key={i.id} onClick={() => navigate(`/incidents/${i.id}`)}>
                  <td>{i.id}</td>
                  <td><SeverityBadge severity={i.severity} /></td>
                  <td className="title-cell">{i.title}</td>
                  <td><StatusBadge status={i.status} /></td>
                  <td className="mono small">{i.ruleId || <span className="muted">manual</span>}</td>
                  <td>{i.affectedUser || '—'}</td>
                  <td className="mono">{i.sourceIp || '—'}</td>
                  <td>{i.assignee || <span className="muted">unassigned</span>}</td>
                  <td>{i.detectionCount}</td>
                  <td className="nowrap" title={formatTime(i.createdAt)}>{timeAgo(i.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!loading && data?.content?.length === 0 && <div className="empty">No incidents match these filters.</div>}
        </div>
        {data && data.totalPages > 1 && (
          <div className="pager">
            <button className="btn" disabled={filters.page === 0}
                    onClick={() => update('page', String(filters.page - 1))}>← Prev</button>
            <span>Page {data.page + 1} of {data.totalPages} · {data.totalElements} incidents</span>
            <button className="btn" disabled={filters.page + 1 >= data.totalPages}
                    onClick={() => update('page', String(filters.page + 1))}>Next →</button>
          </div>
        )}
      </Card>
    </div>
  );
}
