const KEY = 'mfa_token';

export const getToken = () => {
  try { return localStorage.getItem(KEY); } catch { return null; }
};
export const setToken = (t) => {
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
};
export const clearToken = () => {
  try { localStorage.removeItem(KEY); } catch { /* ignore */ }
};
