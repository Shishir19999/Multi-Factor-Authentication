// Breached-password check against the Have I Been Pwned "range" API using k-anonymity:
// only the first 5 hex characters of the SHA-1 hash ever leave the machine; the match is done locally.
export async function sha1Hex(text) {
  const buf = await globalThis.crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Parses the "SUFFIX:COUNT" lines of a range response. Padding entries (count 0) are ignored.
export function parseRange(text) {
  const map = new Map();
  for (const line of String(text).split(/\r?\n/)) {
    const [suffix, count] = line.trim().split(':');
    const n = Number(count);
    if (suffix && /^[0-9A-F]{35}$/i.test(suffix) && n > 0) map.set(suffix.toUpperCase(), n);
  }
  return map;
}

// Resolves to { status: 'pwned', count } | { status: 'safe' } | { status: 'unavailable', reason }. Never throws:
// a network failure must not block sign-up (callers decide how to treat "unavailable").
export async function checkPwned(password, { fetchImpl = (...args) => globalThis.fetch(...args), timeoutMs = 4000, baseUrl = 'https://api.pwnedpasswords.com', padding = false } = {}) {
  try {
    if (typeof fetchImpl !== 'function') return { status: 'unavailable', reason: 'no-fetch' };
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const ctl = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), timeoutMs) : null;
    try {
      const res = await fetchImpl(`${baseUrl}/range/${prefix}`, { signal: ctl?.signal, ...(padding ? { headers: { 'Add-Padding': 'true' } } : {}) });
      if (!res.ok) return { status: 'unavailable', reason: `http-${res.status}` };
      const count = parseRange(await res.text()).get(hash.slice(5));
      return count ? { status: 'pwned', count } : { status: 'safe' };
    } finally {
      if (timer) clearTimeout(timer);
    }
  } catch (error) {
    return { status: 'unavailable', reason: error?.name === 'AbortError' ? 'timeout' : 'network' };
  }
}
