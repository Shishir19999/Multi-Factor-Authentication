// Client-side session bookkeeping.
// - Live preview: the token is the opaque session id of the in-browser backend (localStorage).
// - Real mode: the session lives in an HttpOnly cookie the page cannot read. The stored value is only a hint
//   ("probably signed in") so the app knows whether to ask the server; the CSRF token is kept in memory only.
const KEY = 'mfa_token';
const DEVICE_PREFIX = 'mfa_device:';

const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } };
const remove = (k) => { try { localStorage.removeItem(k); } catch { /* storage unavailable */ } };

export const getToken = () => read(KEY);
export const setToken = (t) => write(KEY, t);
export const clearToken = () => remove(KEY);

let csrf = null;
export const getCsrf = () => csrf;
export const setCsrf = (t) => { csrf = t || null; };

// "Trust this device" token, kept per e-mail address so it can skip the second factor on the next sign-in.
export const getDeviceToken = (email) => read(DEVICE_PREFIX + String(email).trim().toLowerCase());
export const setDeviceToken = (email, t) => write(DEVICE_PREFIX + String(email).trim().toLowerCase(), t);
