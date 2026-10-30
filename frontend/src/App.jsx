import { Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from './auth.jsx';
import Layout from './components/Layout.jsx';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Incidents from './pages/Incidents.jsx';
import IncidentDetail from './pages/IncidentDetail.jsx';
import Alerts from './pages/Alerts.jsx';
import Events from './pages/Events.jsx';

export default function App() {
  const { auth } = useAuth();
  if (!auth) return <Login />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="events" element={<Events />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
