import { Link, useNavigate } from 'react-router-dom';
import { detection, tracker } from '../api.js';
import { usePolling } from '../hooks.js';
import { Card, ErrorBanner, StatCard } from '../components/Card.jsx';
import BarList from '../components/BarList.jsx';
import ActivityChart from '../components/ActivityChart.jsx';
import EventTable from '../components/EventTable.jsx';
import { SeverityBadge, StatusBadge } from '../components/Badges.jsx';
import { SEVERITIES, STATUSES, label, minutes, timeAgo } from '../format.js';

const REFRESH = 10000;

export default function Dashboard() {
  const navigate = useNavigate();
  const stats = usePolling(() => tracker.stats(), REFRESH);
  const alertSummary = usePolling(() => detection.alertSummary(24), REFRESH);
  const activity = usePolling(() => detection.activity(60), REFRESH);
  const events = usePolling(() => detection.recentEvents({ size: 12, minutes: 60 }), REFRESH);
  const recent = usePolling(() => tracker.list({ size: 8, status: ['OPEN', 'INVESTIGATING', 'CONTAINED'] }), REFRESH);

  const s = stats.data;
  const a = alertSummary.data;
  const criticalHigh = s ? (s.activeBySeverity.CRITICAL || 0) + (s.activeBySeverity.HIGH || 0) : null;

  return (
    <div className="page">
      <header className="page-header">
        <h1>Security Overview</h1>
        <span className="muted">Auto-refreshing every {REFRESH / 1000}s</span>
      </header>
      <ErrorBanner error={stats.error || alertSummary.error || activity.error} />

      <div className="stats-row">
        <StatCard label="Active incidents" value={s?.active} tone={s?.active ? 'warn' : 'default'} />
        <StatCard label="Critical / High active" value={criticalHigh} tone={criticalHigh ? 'danger' : 'default'} />
        <StatCard label="Unassigned" value={s?.unassignedActive} tone={s?.unassignedActive ? 'warn' : 'default'} />
        <StatCard label="Alerts (24h)" value={a?.total} />
        <StatCard label="Mean time to acknowledge" value={minutes(s?.meanTimeToAcknowledgeMinutes)} />
        <StatCard label="Mean time to resolve" value={minutes(s?.meanTimeToResolveMinutes)} />
      </div>

      <div className="grid-2">
        <Card title="Suspicious activity — last 60 min">
          <ActivityChart series={activity.data?.series || []} />
        </Card>
        <Card title="Alerts by severity (24h)">
          <BarList
            items={SEVERITIES.map((sev) => ({ key: sev, count: a?.bySeverity?.[sev] || 0 }))}
            colorFor={(k) => `sev-${k.toLowerCase()}`}
            onSelect={(sev) => navigate(`/alerts?severity=${sev}`)}
          />
          <h3 className="subhead">Top firing rules</h3>
          <BarList items={Object.entries(a?.byRule || {}).map(([key, count]) => ({ key, count }))}
                   empty="No rules have fired" />
        </Card>
      </div>

      <div className="grid-3">
        <Card title="Incident status">
          <BarList
            items={STATUSES.map((st) => ({ key: st, label: label(st), count: s?.byStatus?.[st] || 0 }))}
            colorFor={(k) => `status-${k.toLowerCase()}`}
            onSelect={(st) => navigate(`/incidents?status=${st}`)}
          />
        </Card>
        <Card title="Affected users (suspicious events, 60 min)">
          <BarList items={activity.data?.topUsers?.filter((u) => u.key !== 'anonymous') || []}
                   onSelect={(u) => navigate(`/events?username=${encodeURIComponent(u)}`)} />
        </Card>
        <Card title="Top source IPs (suspicious events, 60 min)">
          <BarList items={activity.data?.topSourceIps || []}
                   onSelect={(ip) => navigate(`/events?sourceIp=${encodeURIComponent(ip)}`)} />
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Open incidents" actions={<Link to="/incidents">View all →</Link>}>
          {recent.data?.content?.length ? (
            <ul className="incident-list">
              {recent.data.content.map((i) => (
                <li key={i.id} onClick={() => navigate(`/incidents/${i.id}`)}>
                  <SeverityBadge severity={i.severity} />
                  <span className="incident-title">#{i.id} {i.title}</span>
                  <StatusBadge status={i.status} />
                  <span className="muted small">{i.assignee || 'unassigned'} · {timeAgo(i.createdAt)}</span>
                </li>
              ))}
            </ul>
          ) : <div className="empty">No open incidents 🎉</div>}
        </Card>
        <Card title="Recent suspicious events" actions={<Link to="/events">Explore →</Link>}>
          <EventTable events={events.data} compact />
        </Card>
      </div>
    </div>
  );
}
