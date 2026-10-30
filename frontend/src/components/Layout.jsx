import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../auth.jsx';
import { usePolling } from '../hooks.js';
import { detection } from '../api.js';

export default function Layout() {
  const { auth, logout } = useAuth();
  const { data: pipeline } = usePolling(() => detection.pipeline(), 30000);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <img src="/shield.svg" alt="" width="26" height="26" />
          <span>Mini SOC</span>
        </div>
        <nav>
          <NavLink to="/" end>Overview</NavLink>
          <NavLink to="/incidents">Incidents</NavLink>
          <NavLink to="/alerts">Alerts &amp; Rules</NavLink>
          <NavLink to="/events">Event Explorer</NavLink>
        </nav>
        <div className="sidebar-footer">
          <div className="pipeline">
            <span className={`dot ${pipeline?.opensearch === 'UP' ? 'ok' : 'bad'}`} />
            SIEM {pipeline?.opensearch ?? '…'}
            {pipeline?.pendingIncidentForwards > 0 && (
              <span className="muted"> · {pipeline.pendingIncidentForwards} queued</span>
            )}
          </div>
          <div className="user">
            <span>{auth.username}</span>
            <button className="link" onClick={logout}>Sign out</button>
          </div>
        </div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
