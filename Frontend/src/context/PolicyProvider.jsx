import { useCallback, useEffect, useMemo, useState } from 'react';
import { PolicyContext } from './contexts';
import { api } from '../api';
import { defaultPolicy, normalizePolicy } from '../shared/policy';

// The active security policy (password rules, lockout numbers, ...). Falls back to the defaults while loading or offline.
function PolicyProvider({ children }) {
  const [policy, setPolicy] = useState(defaultPolicy);
  const [run, setRun] = useState(0);

  useEffect(() => {
    let cancelled = false;
    api.getPolicy()
      .then((p) => { if (!cancelled) setPolicy(normalizePolicy(p).policy); })
      .catch(() => { /* keep defaults */ });
    return () => { cancelled = true; };
  }, [run]);

  const reload = useCallback(() => setRun((n) => n + 1), []);
  const value = useMemo(() => ({ policy, reload }), [policy, reload]);
  return <PolicyContext.Provider value={value}>{children}</PolicyContext.Provider>;
}

export default PolicyProvider;
