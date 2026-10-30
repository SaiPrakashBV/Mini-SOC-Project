import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { getStoredAuth, setUnauthorizedHandler, storeAuth, tracker } from './api.js';

const AuthContext = createContext(null);

// Credentials are kept in sessionStorage (cleared when the tab closes) and sent as
// HTTP Basic to both backends. Fine for a local lab; use OIDC for anything real.
export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(getStoredAuth);

  const logout = useCallback(() => {
    storeAuth(null);
    setAuth(null);
  }, []);

  useEffect(() => setUnauthorizedHandler(logout), [logout]);

  const login = useCallback(async (username, password) => {
    const token = btoa(`${username}:${password}`);
    const me = await tracker.me(token);
    const value = { token, username: me.username, roles: me.roles };
    storeAuth(value);
    setAuth(value);
  }, []);

  const value = useMemo(() => ({ auth, login, logout }), [auth, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
