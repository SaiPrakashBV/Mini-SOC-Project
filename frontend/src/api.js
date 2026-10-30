// Small fetch wrapper. Both backends sit behind the same origin (nginx / Vite proxy):
//   /tracker/*   -> incident-tracker
//   /detection/* -> detection-service

const STORAGE_KEY = 'mini-soc-auth';

export function getStoredAuth() {
  try {
    return JSON.parse(sessionStorage.getItem(STORAGE_KEY));
  } catch {
    return null;
  }
}

export function storeAuth(auth) {
  if (auth) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(auth));
  else sessionStorage.removeItem(STORAGE_KEY);
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

async function request(base, path, { method = 'GET', body, token } = {}) {
  const auth = token ?? getStoredAuth()?.token;
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      Accept: 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(auth ? { Authorization: `Basic ${auth}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && !token) onUnauthorized();
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const data = await res.json();
      message = data.detail || data.message || message;
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, message);
  }
  if (res.status === 204) return null;
  return res.json();
}

const qs = (params) => {
  const sp = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v === undefined || v === null || v === '') return;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
    else sp.append(k, v);
  });
  const s = sp.toString();
  return s ? `?${s}` : '';
};

export const tracker = {
  me: (token) => request('/tracker', '/api/me', { token }),
  analysts: () => request('/tracker', '/api/analysts'),
  stats: () => request('/tracker', '/api/incidents/stats'),
  list: (params = {}) => request('/tracker', `/api/incidents${qs(params)}`),
  get: (id) => request('/tracker', `/api/incidents/${id}`),
  create: (body) => request('/tracker', '/api/incidents', { method: 'POST', body }),
  updateStatus: (id, body) => request('/tracker', `/api/incidents/${id}/status`, { method: 'PATCH', body }),
  assign: (id, assignee) => request('/tracker', `/api/incidents/${id}/assign`, { method: 'PATCH', body: { assignee } }),
  updateSeverity: (id, severity) =>
    request('/tracker', `/api/incidents/${id}/severity`, { method: 'PATCH', body: { severity } }),
  addNote: (id, content) => request('/tracker', `/api/incidents/${id}/notes`, { method: 'POST', body: { content } }),
};

export const detection = {
  alerts: (params = {}) => request('/detection', `/api/alerts${qs(params)}`),
  alertSummary: (hours = 24) => request('/detection', `/api/alerts/summary${qs({ hours })}`),
  rules: () => request('/detection', '/api/rules'),
  runRules: () => request('/detection', '/api/rules/run', { method: 'POST' }),
  recentEvents: (params = {}) => request('/detection', `/api/events/recent${qs(params)}`),
  timeline: (params) => request('/detection', `/api/events/timeline${qs(params)}`),
  activity: (minutes = 60) => request('/detection', `/api/events/activity${qs({ minutes })}`),
  pipeline: () => request('/detection', '/api/health/pipeline'),
};
