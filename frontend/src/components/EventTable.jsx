import { Link } from 'react-router-dom';
import { EventTypeBadge } from './Badges.jsx';
import { formatTime } from '../format.js';

export default function EventTable({ events, compact = false }) {
  if (!events || events.length === 0) return <div className="empty">No events in this window.</div>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Event</th>
            <th>User</th>
            <th>Source IP</th>
            <th>Request</th>
            {!compact && <th>Status</th>}
            {!compact && <th>Correlation ID</th>}
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={`${e.correlation_id}-${e['@timestamp']}-${i}`}>
              <td className="nowrap">{formatTime(e['@timestamp'])}</td>
              <td><EventTypeBadge type={e.event_type} /></td>
              <td>{e.username && e.username !== 'anonymous'
                ? <Link to={`/events?username=${encodeURIComponent(e.username)}`}>{e.username}</Link>
                : <span className="muted">{e.username || '—'}</span>}</td>
              <td>{e.source_ip
                ? <Link to={`/events?sourceIp=${encodeURIComponent(e.source_ip)}`}>{e.source_ip}</Link> : '—'}</td>
              <td className="mono">{e.http_method} {e.http_path || <span className="muted">{e.message}</span>}</td>
              {!compact && <td>{e.http_status ?? '—'}</td>}
              {!compact && (
                <td className="mono small">
                  {e.correlation_id
                    ? <Link to={`/events?correlationId=${e.correlation_id}`}>{e.correlation_id.slice(0, 8)}…</Link>
                    : '—'}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
