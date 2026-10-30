import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { detection, tracker } from '../api.js';
import { useAuth } from '../auth.jsx';
import { usePolling } from '../hooks.js';
import { Card, ErrorBanner } from '../components/Card.jsx';
import { SeverityBadge, StatusBadge } from '../components/Badges.jsx';
import EventTable from '../components/EventTable.jsx';
import { SEVERITIES, formatTime, label, timeAgo } from '../format.js';

export default function IncidentDetail() {
  const { id } = useParams();
  const { auth } = useAuth();
  const incident = usePolling(() => tracker.get(id), 15000, [id]);
  const analysts = usePolling(() => tracker.analysts());
  const [actionError, setActionError] = useState(null);
  const [pendingStatus, setPendingStatus] = useState(null);
  const [resolution, setResolution] = useState('');
  const [comment, setComment] = useState('');
  const [note, setNote] = useState('');

  const inc = incident.data;
  const related = usePolling(() => {
    if (!inc) return Promise.resolve([]);
    const params = inc.affectedUser ? { username: inc.affectedUser } : inc.sourceIp ? { sourceIp: inc.sourceIp } : null;
    return params ? detection.timeline({ ...params, minutes: 1440, size: 100 }) : Promise.resolve([]);
  }, 0, [inc?.id, inc?.affectedUser, inc?.sourceIp]);

  const run = async (fn) => {
    setActionError(null);
    try {
      await fn();
      await incident.reload();
    } catch (e) {
      setActionError(e);
    }
  };

  if (incident.error) return <div className="page"><ErrorBanner error={incident.error} /></div>;
  if (!inc) return <div className="page muted">Loading…</div>;

  const needsResolution = pendingStatus === 'RESOLVED' || pendingStatus === 'FALSE_POSITIVE';
  const evidence = inc.evidence;

  return (
    <div className="page">
      <Link to="/incidents" className="back">← Incidents</Link>
      <header className="page-header incident-header">
        <div>
          <h1>#{inc.id} {inc.title}</h1>
          <div className="meta-row">
            <SeverityBadge severity={inc.severity} />
            <StatusBadge status={inc.status} />
            <span className="muted">{inc.source === 'DETECTION' ? `Detected by ${inc.ruleId}` : `Manual — ${inc.createdBy}`}</span>
            {inc.detectionCount > 1 && <span className="badge event">re-triggered ×{inc.detectionCount}</span>}
          </div>
        </div>
      </header>
      <ErrorBanner error={actionError} />

      <div className="grid-detail">
        <div className="col">
          <Card title="Summary">
            <p className="pre">{inc.description || <span className="muted">No description.</span>}</p>
            <dl className="facts">
              <dt>Affected user</dt><dd>{inc.affectedUser
                ? <Link to={`/events?username=${encodeURIComponent(inc.affectedUser)}`}>{inc.affectedUser}</Link> : '—'}</dd>
              <dt>Source IP</dt><dd className="mono">{inc.sourceIp
                ? <Link to={`/events?sourceIp=${encodeURIComponent(inc.sourceIp)}`}>{inc.sourceIp}</Link> : '—'}</dd>
              <dt>First detected</dt><dd>{formatTime(inc.detectedAt)}</dd>
              <dt>Created</dt><dd>{formatTime(inc.createdAt)}</dd>
              <dt>Acknowledged</dt><dd>{formatTime(inc.acknowledgedAt)}</dd>
              <dt>Resolved</dt><dd>{formatTime(inc.resolvedAt)}</dd>
            </dl>
            {inc.resolution && (
              <div className="resolution"><strong>Resolution:</strong> <span className="pre">{inc.resolution}</span></div>
            )}
          </Card>

          {evidence && (
            <Card title="Evidence">
              {evidence.count !== undefined && (
                <p>
                  <strong>{evidence.count}</strong> events (threshold {evidence.threshold}) in {evidence.window}
                  {evidence.sourceIps?.length > 0 && <> from <span className="mono">{evidence.sourceIps.join(', ')}</span></>}
                  {evidence.paths?.length > 0 && <> on <span className="mono">{evidence.paths.join(', ')}</span></>}
                </p>
              )}
              {evidence.samples?.length > 0 && <EventTable events={evidence.samples} />}
              <details>
                <summary>Raw evidence JSON</summary>
                <pre className="json">{JSON.stringify(evidence, null, 2)}</pre>
              </details>
            </Card>
          )}

          <Card className="scroll-card" title={`Related event timeline (${inc.affectedUser ? `user ${inc.affectedUser}` : `IP ${inc.sourceIp || '—'}`}, 24h)`}>
            <EventTable events={related.data} />
          </Card>
        </div>

        <div className="col">
          <Card title="Triage">
            <label className="field">Assignee
              <select value={inc.assignee || ''} onChange={(e) => run(() => tracker.assign(inc.id, e.target.value || null))}>
                <option value="">Unassigned</option>
                {analysts.data?.map((a) => <option key={a.username} value={a.username}>{a.displayName} ({a.username})</option>)}
              </select>
            </label>
            {inc.assignee !== auth.username && (
              <button className="btn small" onClick={() => run(() => tracker.assign(inc.id, auth.username))}>Assign to me</button>
            )}
            <label className="field">Severity
              <select value={inc.severity} onChange={(e) => run(() => tracker.updateSeverity(inc.id, e.target.value))}>
                {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </label>
            <div className="field">
              <span>Move to</span>
              <div className="btn-row">
                {inc.allowedTransitions.map((s) => (
                  <button key={s} className={`btn small ${pendingStatus === s ? 'primary' : ''}`}
                          onClick={() => setPendingStatus(pendingStatus === s ? null : s)}>{label(s)}</button>
                ))}
              </div>
            </div>
            {pendingStatus && (
              <form className="status-form" onSubmit={(e) => {
                e.preventDefault();
                run(async () => {
                  await tracker.updateStatus(inc.id, { status: pendingStatus, resolution: resolution || undefined, comment: comment || undefined });
                  setPendingStatus(null); setResolution(''); setComment('');
                });
              }}>
                {needsResolution && (
                  <label>Resolution summary (required)
                    <textarea rows={3} value={resolution} onChange={(e) => setResolution(e.target.value)} required />
                  </label>
                )}
                <label>Comment (optional)
                  <textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} />
                </label>
                <button className="btn primary">Confirm → {label(pendingStatus)}</button>
              </form>
            )}
          </Card>

          <Card title={`Investigation notes (${inc.notes.length})`}>
            <form className="note-form" onSubmit={(e) => {
              e.preventDefault();
              run(async () => { await tracker.addNote(inc.id, note); setNote(''); });
            }}>
              <textarea rows={3} placeholder="Document findings, IOCs, actions taken…" value={note}
                        onChange={(e) => setNote(e.target.value)} />
              <button className="btn primary" disabled={!note.trim()}>Add note</button>
            </form>
            <ul className="notes">
              {[...inc.notes].reverse().map((n) => (
                <li key={n.id}>
                  <div className="note-meta"><strong>{n.author}</strong> <span className="muted">{timeAgo(n.createdAt)}</span></div>
                  <div className="pre">{n.content}</div>
                </li>
              ))}
            </ul>
          </Card>

          <Card title="Audit history">
            <ol className="timeline">
              {[...inc.history].reverse().map((h) => (
                <li key={h.id}>
                  <span className="timeline-time">{formatTime(h.timestamp)}</span>
                  <span><strong>{h.actor}</strong> {label(h.action)}
                    {h.fromValue && <> from <code>{h.fromValue}</code></>}
                    {h.toValue && <> to <code>{h.toValue}</code></>}
                  </span>
                </li>
              ))}
            </ol>
          </Card>
        </div>
      </div>
    </div>
  );
}
