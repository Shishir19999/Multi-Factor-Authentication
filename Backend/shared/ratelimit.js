// Shared rate-limit configuration and a small fixed-window counter (used by the Live preview; the API server
// applies the same numbers through express-rate-limit).
export const RATE_LIMITS = {
  login: { windowMs: 15 * 60 * 1000, limit: 10, message: 'Too many sign-in attempts.' },
  verify: { windowMs: 15 * 60 * 1000, limit: 20, message: 'Too many verification attempts.' },
  resend: { windowMs: 15 * 60 * 1000, limit: 10, message: 'Too many code requests.' },
  sensitive: { windowMs: 15 * 60 * 1000, limit: 30, message: 'Too many attempts.' },
  recover: { windowMs: 15 * 60 * 1000, limit: 10, message: 'Too many recovery requests.' },
  public: { windowMs: 15 * 60 * 1000, limit: 30, message: 'Too many requests.' },
};

// store: plain object { [key]: { count, reset } }. Returns { allowed, remaining, retryAfterSeconds }.
export function hitWindow(store, key, cfg, now = Date.now()) {
  let entry = store[key];
  if (!entry || entry.reset <= now) entry = store[key] = { count: 0, reset: now + cfg.windowMs };
  entry.count += 1;
  const allowed = entry.count <= cfg.limit;
  return { allowed, remaining: Math.max(0, cfg.limit - entry.count), retryAfterSeconds: allowed ? 0 : Math.ceil((entry.reset - now) / 1000) };
}

// Read-only check (does not count).
export function windowBlocked(store, key, cfg, now = Date.now()) {
  const entry = store[key];
  if (!entry || entry.reset <= now || entry.count < cfg.limit) return { blocked: false, retryAfterSeconds: 0 };
  return { blocked: true, retryAfterSeconds: Math.ceil((entry.reset - now) / 1000) };
}
