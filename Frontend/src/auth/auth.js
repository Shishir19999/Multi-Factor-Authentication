const KEY = 'mfa_token';
const DEVICE_PREFIX = 'mfa_device:';

const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } };
const remove = (k) => { try { localStorage.removeItem(k); } catch { /* storage unavailable */ } };

export const getToken = () => read(KEY);
export const setToken = (t) => write(KEY, t);
export const clearToken = () => remove(KEY);

// "Trust this device" token, kept per e-mail address so it can skip the second factor on the next sign-in.
export const getDeviceToken = (email) => read(DEVICE_PREFIX + String(email).trim().toLowerCase());
export const setDeviceToken = (email, t) => write(DEVICE_PREFIX + String(email).trim().toLowerCase(), t);
