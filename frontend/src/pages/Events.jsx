import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { detection } from '../api.js';
import { usePolling } from '../hooks.js';
import { Card, ErrorBanner } from '../components/Card.jsx';
import EventTable from '../components/EventTable.jsx';
import ActivityChart from '../components/ActivityChart.jsx';

const WINDOWS = [
  { label: '15 min', value: 15 },
  { label: '1 hour', value: 60 },
  { label: '24 hours', value: 1440 },
  { label: '7 days', value: 10080 },
];

export default function Events() {
  const [params, setParams] = useSearchParams();
  const username = params.get('username') || '';
  const sourceIp = params.get('sourceIp') || '';
  const correlationId = params.get('correlationId') || '';
  const minutes = Number(params.get('minutes') || 60);
  const pivot = username || sourceIp || correlationId;

  const [draft, setDraft] = useState({ username, sourceIp, correlationId });
  const key = params.toString();

  const events = usePolling(
    () => (pivot
      ? detection.timeline({ username, sourceIp, correlationId, minutes: Math.max(minutes, 60), size: 500 })
      : detection.recentEvents({ size: 200, minutes })),
    15000, [key]);
  const activity = usePolling(() => detection.activity(Math.min(minutes, 1440)), 15000, [minutes]);

  const apply = (e) => {
    e.preventDefault();
    const next = { minutes: String(minutes) };
    Object.entries(draft).forEach(([k, v]) => { if (v.trim()) next[k] = v.trim(); });
    setParams(next);
  };

  return (
    <div className="page">
      <header className="page-header">
        <h1>Event Explorer</h1>
        <div className="chip-group">
          {WINDOWS.map((w) => (
            <button key={w.value} className={`chip ${minutes === w.value ? 'on' : ''}`}
                    onClick={() => { const n = new URLSearchParams(params); n.set('minutes', w.value); setParams(n); }}>
              {w.label}
            </button>
          ))}
        </div>
      </header>

      <Card>
        <form className="filters" onSubmit={apply}>
          <input placeholder="Username" value={draft.username} onChange={(e) => setDraft({ ...draft, username: e.target.value })} />
          <input placeholder="Source IP" value={draft.sourceIp} onChange={(e) => setDraft({ ...draft, sourceIp: e.target.value })} />
          <input placeholder="Correlation ID" value={draft.correlationId}
                 onChange={(e) => setDraft({ ...draft, correlationId: e.target.value })} />
          <button className="btn primary">Pivot</button>
          {pivot && <button type="button" className="btn" onClick={() => { setDraft({ username: '', sourceIp: '', correlationId: '' }); setParams({ minutes: String(minutes) }); }}>Clear</button>}
        </form>
      </Card>

      {!pivot && (
        <Card title="Suspicious activity">
          <ActivityChart series={activity.data?.series || []} />
        </Card>
      )}

      <ErrorBanner error={events.error} />
      <Card title={pivot
        ? `Timeline for ${[username && `user ${username}`, sourceIp && `IP ${sourceIp}`, correlationId && `request ${correlationId}`].filter(Boolean).join(', ')} (all events, oldest first)`
        : 'Suspicious events (newest first)'}>
        <EventTable events={events.data} />
      </Card>
    </div>
  );
}
