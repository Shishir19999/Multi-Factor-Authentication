import { useCallback, useEffect, useMemo, useState } from 'react';
import { AuthContext } from './contexts';
import { api, UNAUTHORIZED_EVENT, ACTION_REQUIRED_EVENT } from '../api';
import { clearToken, getToken, setToken } from '../auth/auth';

// Holds the signed-in user (id, e-mail, role, pending requirements). A stored hint is validated against the
// server (or the Live preview backend) on load; a 401 anywhere signs the visitor out.
function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [status, setStatus] = useState(getToken() ? 'loading' : 'anon');

  const refresh = useCallback(async () => {
    try {
      const u = await api.me();
      setUser(u);
      setStatus('authed');
      return u;
    } catch {
      setUser(null);
      setStatus('anon');
      return null;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    if (getToken()) {
      api.me()
        .then((u) => { if (!cancelled) { setUser(u); setStatus('authed'); } })
        .catch(() => { if (!cancelled) setStatus('anon'); });
    }
    const onUnauthorized = () => { setUser(null); setStatus('anon'); };
    const onActionRequired = (e) => setUser((u) => (u ? { ...u, requirements: e.detail || u.requirements } : u));
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    window.addEventListener(ACTION_REQUIRED_EVENT, onActionRequired);
    return () => {
      cancelled = true;
      window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
      window.removeEventListener(ACTION_REQUIRED_EVENT, onActionRequired);
    };
  }, []);

  const signIn = useCallback((token, u) => {
    setToken(token);
    setUser(u);
    setStatus('authed');
  }, []);

  const signOut = useCallback(async () => {
    await api.logout();
    clearToken();
    setUser(null);
    setStatus('anon');
  }, []);

  const value = useMemo(() => ({ user, status, signIn, signOut, setUser, refresh }), [user, status, signIn, signOut, refresh]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export default AuthProvider;
