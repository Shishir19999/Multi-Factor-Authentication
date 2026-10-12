import { useCallback, useEffect, useState } from 'react';

// Counts down once per second. Returns [secondsLeft, start(seconds)]. Used for lockouts, rate limits and resend cooldowns.
export function useCountdown(initial = 0) {
  const [left, setLeft] = useState(initial);
  useEffect(() => {
    if (left <= 0) return undefined;
    const t = setTimeout(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(t);
  }, [left]);
  const start = useCallback((seconds) => setLeft(Math.max(0, Math.ceil(seconds || 0))), []);
  return [left, start];
}
