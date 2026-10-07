// Persistence for the in-browser demo backend: one JSON "database" and a demo inbox, both in localStorage
// (falling back to memory when storage is blocked). Nothing here ever leaves the visitor's browser.
const DB_KEY = 'mfa-demo-db-v1';
const INBOX_KEY = 'mfa-demo-inbox-v1';

const memory = new Map();
const storage = {
  get(k) { try { return localStorage.getItem(k); } catch { return memory.get(k) ?? null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { memory.set(k, v); } },
  remove(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } memory.delete(k); },
  keys() { try { return Object.keys(localStorage); } catch { return [...memory.keys()]; } },
};

const parse = (raw, fallback) => { try { return raw ? JSON.parse(raw) : fallback; } catch { return fallback; } };

export const loadDb = () => parse(storage.get(DB_KEY), null);
export const saveDb = (db) => storage.set(DB_KEY, JSON.stringify(db));

// ---- Demo inbox: stands in for the e-mail the real backend would send ----
const listeners = new Set();
const notify = () => listeners.forEach((fn) => fn());

export const listMail = () => parse(storage.get(INBOX_KEY), []);

export function pushMail({ to, subject, text, code }) {
  const mail = { id: crypto.randomUUID(), to, subject, text, code, at: new Date().toISOString() };
  storage.set(INBOX_KEY, JSON.stringify([mail, ...listMail()].slice(0, 20)));
  notify();
  return mail;
}

export function clearMail() {
  storage.remove(INBOX_KEY);
  notify();
}

export function subscribeMail(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// Wipes the demo database, inbox, sign-in token and trusted-device tokens, restoring the seeded sample data.
export function resetDemoData() {
  storage.remove(DB_KEY);
  storage.remove(INBOX_KEY);
  storage.keys().filter((k) => k.startsWith('mfa_')).forEach((k) => storage.remove(k));
  notify();
}
