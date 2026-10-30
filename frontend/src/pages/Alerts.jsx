import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { detection } from '../api.js';
import { usePolling } from '../hooks.js';
import { Card, ErrorBanner } from '../components/Card.jsx';
import { SeverityBadge } from '../components/Badges.jsx';
import { SEVERITIES, formatTime, timeAgo } from '../format.js';

export default function Alerts() {
  const [params, setParams] = useSearchParams();
  const severity = params.get('severity') || '';
  const alerts = usePolling(() => detection.alerts({ size: 100, severity }), 10000, [severity]);
  const rules = usePolling(() => detection.rules(), 15000);
  const [runResult, setRunResult] = useState(null);
  const [runError, setRunError] = useState(null);

  const runNow = async () => {
    setRunError(null);
    try {
      const r = await detection.runRules();
      setRunResult(`${r.fired} new alert(s)`);
      alerts.reload();
      rules.reload();
    } catch (e) {
      setRunError(e);
    }
  };

  return (
    <div className="page">
      <header className="page-header">
        <h1>Alerts &amp; Detection Rules</h1>
        <div className="btn-row">
          {runResult && <span className="muted">{runResult}</span>}
          <button className="btn primary" onClick={runNow}>Run detection now</button>
        </div>
      </header>
      <ErrorBanner error={alerts.error || runError} />

      <Card title="Alert feed" actions={
        <select value={severity} onChange={(e) => setParams(e.target.value ? { severity: e.target.value } : {})}>
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
      }>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr><th>Fired</th><th>Severity</th><th>Rule</th><th>Entity</th><th>Count</th><th>Window</th>
                <th>Source IPs</th><th>Incident</th></tr>
            </thead>
            <tbody>
              {alerts.data?.map((a) => (
                <tr key={a.alertId}>
                  <td className="nowrap" title={formatTime(a['@timestamp'])}>{timeAgo(a['@timestamp'])}</td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td>{a.ruleName}<div className="muted small mono">{a.ruleId}{a.mitre && ` · ${a.mitre}`}</div></td>
                  <td>
                    <Link to={`/events?${a.groupBy === 'username' ? 'username' : 'sourceIp'}=${encodeURIComponent(a.entity)}`}>
                      {a.entity}
                    </Link>
                    <div className="muted small">{a.groupBy}</div>
                  </td>
                  <td>{a.count} <span className="muted small">/ {a.threshold}</span></td>
                  <td>{a.window}</td>
                  <td className="mono small">{a.sourceIps?.join(', ')}</td>
                  <td>{a.incidentId ? <Link to={`/incidents/${a.incidentId}`}>#{a.incidentId}</Link> : <span className="muted">pending</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {alerts.data?.length === 0 && <div className="empty">No alerts yet. Run <code>scripts/simulate-attacks.sh</code> to generate some.</div>}
        </div>
      </Card>

      <Card title="Detection rules">
        <div className="rules">
          {rules.data?.map(({ rule, status }) => (
            <div key={rule.id} className={`rule ${rule.enabled ? '' : 'disabled'}`}>
              <div className="rule-head">
                <SeverityBadge severity={rule.severity} />
                <strong>{rule.name}</strong>
                <span className="mono small muted">{rule.id}</span>
              </div>
              <p className="small">{rule.description}</p>
              <div className="rule-logic mono small">
                count(<b>{Object.entries(rule.match).map(([k, v]) => `${k} ∈ [${v.join(', ')}]`).join(' ∧ ')}
                {rule.pathPrefix && ` ∧ http_path ^= ${rule.pathPrefix}`}</b>) by <b>{rule.groupBy}</b> ≥ <b>{rule.threshold}</b> in <b>{rule.window}</b>
                {rule.escalateAt && <> · ≥ {rule.escalateAt} → {rule.escalateTo}</>}
              </div>
              <div className="small muted">
                {status ? <>Last run {timeAgo(status.lastRun)} · {status.lastMatches} over threshold · {status.totalFired} fired</> : 'Not run yet'}
                {status?.lastError && <span className="error-text"> · {status.lastError}</span>}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
