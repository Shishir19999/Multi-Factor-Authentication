import { useCallback, useEffect, useMemo, useState } from 'react';
import { AuthContext } from './contexts';
import { api, UNAUTHORIZED_EVENT } from '../api';
import { clearToken, getToken, setToken } from '../auth/auth';

// Holds the signed-in user. A stored token is validated against the server (or demo backend) on load.
function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [status, setStatus] = useState(getToken() ? 'loading' : 'anon');

  useEffect(() => {
    let cancelled = false;
    if (getToken()) {
      api.me()
        .then((u) => { if (!cancelled) { setUser(u); setStatus('authed'); } })
        .catch(() => { if (!cancelled) setStatus('anon'); });
    }
    const onUnauthorized = () => { setUser(null); setStatus('anon'); };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => { cancelled = true; window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized); };
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

  const value = useMemo(() => ({ user, status, signIn, signOut, setUser }), [user, status, signIn, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export default AuthProvider;
