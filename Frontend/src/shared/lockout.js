// Sign-in lockout logic. State uses epoch milliseconds (0 = not locked) so it is storage independent.

export const emptyLockState = () => ({ failedLogins: 0, lockCount: 0, lockUntil: 0, lastFailureAt: 0 });

export function lockStatus(state, now = Date.now()) {
  const left = (state.lockUntil || 0) - now;
  return left > 0 ? { locked: true, retryAfterSeconds: Math.ceil(left / 1000) } : { locked: false, retryAfterSeconds: 0 };
}

export function lockDurationMs(policy, lockCount) {
  const base = policy.lockout.durationMinutes * 60000;
  return policy.lockout.progressive ? base * Math.min(2 ** lockCount, 8) : base;
}

const DECAY_MS = 2 * 60 * 60 * 1000; // failures older than this are forgotten

// Records one wrong password. Returns { state, locked, attemptsLeft, lockMs }.
export function registerFailure(prev, policy, now = Date.now()) {
  const state = { ...emptyLockState(), ...prev };
  if (state.lastFailureAt && now - state.lastFailureAt > DECAY_MS) state.failedLogins = 0;
  state.failedLogins += 1;
  state.lastFailureAt = now;
  const threshold = policy.lockout.threshold;
  if (state.failedLogins >= threshold) {
    const lockMs = lockDurationMs(policy, state.lockCount);
    state.lockUntil = now + lockMs;
    state.lockCount += 1;
    state.failedLogins = 0;
    return { state, locked: true, attemptsLeft: 0, lockMs };
  }
  return { state, locked: false, attemptsLeft: threshold - state.failedLogins, lockMs: 0 };
}

export const registerSuccess = () => emptyLockState();

export const formatDuration = (seconds) => {
  const s = Math.max(0, Math.round(seconds));
  if (s >= 3600) return `${Math.floor(s / 3600)}h ${String(Math.floor((s % 3600) / 60)).padStart(2, '0')}m`;
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
};
