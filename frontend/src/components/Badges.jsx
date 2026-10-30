import { label } from '../format.js';

export function SeverityBadge({ severity }) {
  if (!severity) return null;
  return <span className={`badge sev-${severity.toLowerCase()}`}>{severity}</span>;
}

export function StatusBadge({ status }) {
  if (!status) return null;
  return <span className={`badge status-${status.toLowerCase()}`}>{label(status)}</span>;
}

export function EventTypeBadge({ type }) {
  return <span className="badge event">{type}</span>;
}
