export function Card({ title, actions, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-header">
          <h2>{title}</h2>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function StatCard({ label, value, hint, tone = 'default' }) {
  return (
    <div className={`stat stat-${tone}`}>
      <div className="stat-value">{value ?? '—'}</div>
      <div className="stat-label">{label}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function ErrorBanner({ error }) {
  if (!error) return null;
  return <div className="error-banner">⚠ {error.message || String(error)}</div>;
}

export function Empty({ children = 'Nothing to show yet.' }) {
  return <div className="empty">{children}</div>;
}
