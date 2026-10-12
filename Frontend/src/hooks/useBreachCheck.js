import { useEffect, useState } from 'react';
import { checkPwned } from '../shared/pwned';

const KEY = 'mfa_breach_pref';

export function breachPrefOn() {
  try { return localStorage.getItem(KEY) !== '0'; } catch { return true; }
}
export function setBreachPref(on) {
  try { localStorage.setItem(KEY, on ? '1' : '0'); } catch { /* ignore */ }
}

// Debounced Have I Been Pwned lookup (k-anonymity: only the first 5 characters of the SHA-1 leave the browser).
// state: idle | checking | safe | pwned | unavailable
export function useBreachCheck(password, enabled) {
  const [result, setResult] = useState({ for: '', state: 'idle', count: 0 });
  useEffect(() => {
    if (!enabled || !password || password.length < 6) return undefined;
    let cancelled = false;
    const t = setTimeout(async () => {
      const r = await checkPwned(password);
      if (!cancelled) setResult({ for: password, state: r.status, count: r.count || 0 });
    }, 700);
    return () => { cancelled = true; clearTimeout(t); };
  }, [password, enabled]);
  if (!enabled || !password || password.length < 6) return { state: 'idle', count: 0 };
  if (result.for !== password) return { state: 'checking', count: 0 };
  return { state: result.state, count: result.count };
}
