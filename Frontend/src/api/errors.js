// Every API implementation (real server or in-browser demo) rejects with this error type.
export class ApiError extends Error {
  constructor(message, { status = 400, data = {} } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data; // e.g. { retryAfterSeconds, locked, attemptsLeft }
  }
}

export const errorMessage = (error, fallback = 'Something went wrong. Please try again.') =>
  (error instanceof ApiError && error.message) || fallback;
