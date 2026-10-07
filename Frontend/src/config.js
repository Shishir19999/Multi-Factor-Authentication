// VITE_DEMO=true builds the browser-only demo (in-browser backend, no network calls).
export const IS_DEMO = import.meta.env.VITE_DEMO === 'true';
export const API_URL = IS_DEMO ? '' : (import.meta.env.VITE_API_URL || 'http://localhost:8080');
export const APP_NAME = 'Multi Factor Authentication';
export const REPO_URL = 'https://github.com/Shishir19999/Multi-Factor-Authentication';
