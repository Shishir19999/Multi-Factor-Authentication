// Persistence for the Live preview's in-browser backend: one JSON "database" and a Preview inbox, both in
// localStorage (falling back to memory when storage is blocked). Nothing here ever leaves the visitor's browser.
const DB_KEY = 'mfa-preview-db-v2';
const INBOX_KEY = 'mfa-preview-inbox-v2';

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

// ---- Preview inbox: stands in for the e-mail the real backend would send ----
const listeners = new Set();
const notify = () => listeners.forEach((fn) => fn());

export const listMail = () => parse(storage.get(INBOX_KEY), []);

// kind: otp | recovery | verify-recovery-email | new-device | admin-test
export function pushMail({ kind, to, subject, text, code, link }) {
  const mail = { id: crypto.randomUUID(), kind, to, subject, text, code, link, at: new Date().toISOString() };
  storage.set(INBOX_KEY, JSON.stringify([mail, ...listMail()].slice(0, 25)));
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

// Wipes the preview database, inbox, sign-in token, trusted-device tokens and simulated passkeys, restoring the sample data.
export function resetPreviewData() {
  storage.remove(DB_KEY);
  storage.remove(INBOX_KEY);
  storage.keys().filter((k) => k.startsWith('mfa_') && k !== 'mfa_theme').forEach((k) => storage.remove(k));
  notify();
}
