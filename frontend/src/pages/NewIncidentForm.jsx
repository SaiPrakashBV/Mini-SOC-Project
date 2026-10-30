import { useState } from 'react';
import { tracker } from '../api.js';
import { Card, ErrorBanner } from '../components/Card.jsx';
import { SEVERITIES } from '../format.js';

export default function NewIncidentForm({ onCreated }) {
  const [form, setForm] = useState({ title: '', description: '', severity: 'MEDIUM', affectedUser: '', sourceIp: '' });
  const [error, setError] = useState(null);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const submit = async (e) => {
    e.preventDefault();
    try {
      const body = Object.fromEntries(Object.entries(form).filter(([, v]) => v !== ''));
      onCreated(await tracker.create(body));
    } catch (err) {
      setError(err);
    }
  };

  return (
    <Card title="Open a manual incident">
      <form className="form-grid" onSubmit={submit}>
        <label className="span-2">Title<input value={form.title} onChange={set('title')} required maxLength={200} /></label>
        <label>Severity
          <select value={form.severity} onChange={set('severity')}>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <label>Affected user<input value={form.affectedUser} onChange={set('affectedUser')} /></label>
        <label>Source IP<input value={form.sourceIp} onChange={set('sourceIp')} /></label>
        <label className="span-3">Description
          <textarea rows={3} value={form.description} onChange={set('description')} />
        </label>
        <ErrorBanner error={error} />
        <div><button className="btn primary" disabled={!form.title}>Create incident</button></div>
      </form>
    </Card>
  );
}
