// Every API implementation (real server or in-browser Live preview) rejects with this error type.
export class ApiError extends Error {
  constructor(message, { status = 400, data = {} } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data; // e.g. { retryAfterSeconds, rateLimited, locked, attemptsLeft, code }
  }
}

// Thrown when the visitor dismisses the "confirm it is you" dialog; callers should simply stop.
export class CancelledError extends Error {
  constructor() {
    super('Cancelled');
    this.name = 'CancelledError';
    this.cancelled = true;
  }
}

export const isCancelled = (error) => !!error?.cancelled;

export const errorMessage = (error, fallback = 'Something went wrong. Please try again.') =>
  (error instanceof ApiError && error.message) || fallback;

// Seconds to wait when the error is a rate limit or a lockout, else 0.
export const retryAfter = (error) => (error instanceof ApiError && (error.data?.rateLimited || error.data?.locked || error.status === 429) ? Number(error.data?.retryAfterSeconds) || 0 : 0);
