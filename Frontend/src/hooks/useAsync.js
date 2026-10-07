import { useCallback, useEffect, useState } from 'react';

// Runs an async loader (memoise it with useCallback) and exposes { data, error, loading, reload }.
export function useAsync(loader) {
  const [run, setRun] = useState(0);
  const [result, setResult] = useState({ run: -1, data: null, error: null });

  useEffect(() => {
    let cancelled = false;
    loader()
      .then((data) => { if (!cancelled) setResult({ run, data, error: null }); })
      .catch((error) => { if (!cancelled) setResult((r) => ({ run, data: r.data, error })); });
    return () => { cancelled = true; };
  }, [loader, run]);

  const reload = useCallback(() => setRun((n) => n + 1), []);
  const loading = result.run !== run;
  // Keep the last good data while reloading; only surface an error once the request has finished.
  return { data: result.data, error: loading ? null : result.error, loading, reload, setData: (data) => setResult((r) => ({ ...r, data })) };
}
