// Stacked column chart of suspicious event types per time bucket (plain SVG, no chart lib).

const SERIES = [
  { key: 'LOGIN_FAILURE', label: 'Login failure', className: 'c-login' },
  { key: 'UNAUTHORIZED', label: '401 Unauthorized', className: 'c-unauth' },
  { key: 'ACCESS_DENIED', label: '403 Access denied', className: 'c-denied' },
  { key: 'TOKEN_INVALID', label: 'Invalid token', className: 'c-token' },
  { key: 'RESOURCE_OWNERSHIP_VIOLATION', label: 'IDOR attempt', className: 'c-idor' },
  { key: 'MALICIOUS_REQUEST', label: 'Malicious payload / scanner', className: 'c-malicious' },
];

export default function ActivityChart({ series = [], height = 180 }) {
  const width = 720;
  const pad = { top: 10, right: 8, bottom: 22, left: 34 };
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const totals = series.map((p) => SERIES.reduce((s, def) => s + (p[def.key] || 0), 0));
  const max = Math.max(4, ...totals);
  const barW = series.length ? innerW / series.length : innerW;
  const ticks = [0, Math.round(max / 2), max];

  return (
    <div className="chart">
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img"
           aria-label="Suspicious events over time">
        {ticks.map((t) => {
          const y = pad.top + innerH - (t / max) * innerH;
          return (
            <g key={t}>
              <line x1={pad.left} x2={width - pad.right} y1={y} y2={y} className="grid" />
              <text x={pad.left - 6} y={y + 4} className="axis" textAnchor="end">{t}</text>
            </g>
          );
        })}
        {series.map((point, i) => {
          let y = pad.top + innerH;
          const x = pad.left + i * barW + 1;
          return (
            <g key={point.time}>
              <title>{`${new Date(point.time).toLocaleTimeString()} — ${totals[i]} suspicious / ${point.total} total`}</title>
              {SERIES.map((def) => {
                const v = point[def.key] || 0;
                if (!v) return null;
                const h = (v / max) * innerH;
                y -= h;
                return <rect key={def.key} x={x} y={y} width={Math.max(1, barW - 2)} height={h} className={def.className} />;
              })}
            </g>
          );
        })}
        {series.length > 0 && [0, Math.floor(series.length / 2), series.length - 1].map((i) => (
          <text key={i} x={pad.left + i * barW + barW / 2} y={height - 6} className="axis" textAnchor="middle">
            {new Date(series[i].time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </text>
        ))}
      </svg>
      <div className="legend">
        {SERIES.map((s) => (
          <span key={s.key}><i className={s.className} />{s.label}</span>
        ))}
      </div>
    </div>
  );
}
