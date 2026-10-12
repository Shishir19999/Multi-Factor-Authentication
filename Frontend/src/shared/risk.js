// Device naming, approximate location and sign-in risk assessment (pure, shared by API and Live preview).

export function parseUserAgent(ua = '') {
  if (!ua || /node|axios|supertest|curl|undici|python|postman|insomnia/i.test(ua)) return { browser: 'API client', os: '', device: 'api' };
  const browser = /Edg\//.test(ua) ? 'Edge'
    : /OPR\/|Opera/.test(ua) ? 'Opera'
      : /Firefox\/|FxiOS/.test(ua) ? 'Firefox'
        : /Chrome\/|CriOS/.test(ua) ? 'Chrome'
          : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows'
    : /Android/.test(ua) ? 'Android'
      : /iPhone|iPad|iPod/.test(ua) ? 'iOS'
        : /Mac OS X|Macintosh/.test(ua) ? 'macOS'
          : /CrOS/.test(ua) ? 'ChromeOS'
            : /Linux/.test(ua) ? 'Linux' : 'unknown OS';
  const device = /iPad|Tablet/.test(ua) ? 'tablet' : /Mobi|iPhone|Android/.test(ua) ? 'mobile' : 'desktop';
  return { browser, os, device };
}

export function deviceLabel(ua = '') {
  const p = parseUserAgent(ua);
  return p.device === 'api' ? 'API client' : `${p.browser} on ${p.os}`;
}

export const deviceFamily = (ua = '') => deviceLabel(ua);

export function isPrivateIp(ip = '') {
  const v = String(ip).replace(/^::ffff:/, '');
  return !v || v === '::1' || /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|fc|fd|fe80)/i.test(v);
}

// Cities used to simulate a GeoIP lookup in the Live preview (documentation address ranges map onto these).
export const SIM_PLACES = [
  { countryCode: 'US', country: 'United States', city: 'New York' },
  { countryCode: 'GB', country: 'United Kingdom', city: 'London' },
  { countryCode: 'DE', country: 'Germany', city: 'Berlin' },
  { countryCode: 'IN', country: 'India', city: 'Mumbai' },
  { countryCode: 'JP', country: 'Japan', city: 'Tokyo' },
  { countryCode: 'BR', country: 'Brazil', city: 'Sao Paulo' },
  { countryCode: 'AU', country: 'Australia', city: 'Sydney' },
  { countryCode: 'CA', country: 'Canada', city: 'Toronto' },
  { countryCode: 'FR', country: 'France', city: 'Paris' },
  { countryCode: 'SG', country: 'Singapore', city: 'Singapore' },
  { countryCode: 'ZA', country: 'South Africa', city: 'Cape Town' },
  { countryCode: 'NL', country: 'Netherlands', city: 'Amsterdam' },
];

function fnv(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h;
}

// Deterministic fake geolocation. Always flagged simulated: this is NOT a real GeoIP lookup.
export function simulatedGeo(ip = '') {
  if (isPrivateIp(ip)) return { key: 'local', label: 'Local network', simulated: true };
  const place = SIM_PLACES[fnv(String(ip)) % SIM_PLACES.length];
  return { key: place.countryCode, label: `${place.city}, ${place.country}`, simulated: true };
}

// Real mode: no GeoIP database is bundled. Use a country header set by a trusted proxy/CDN when present.
export function geoFromHeaders(ip, headers = {}) {
  if (isPrivateIp(ip)) return { key: 'local', label: 'Local network', simulated: false };
  const cc = String(headers['cf-ipcountry'] || headers['x-vercel-ip-country'] || headers['x-country-code'] || '').toUpperCase();
  if (/^[A-Z]{2}$/.test(cc) && cc !== 'XX') return { key: cc, label: cc, simulated: false };
  return { key: 'unknown', label: 'Unknown location', simulated: false };
}

// known: { devices: [family], places: [key] }. Returns { newDevice, newLocation, level, reasons }.
export function assessLogin({ family, geo }, known) {
  const hasHistory = known.devices.length > 0;
  if (!hasHistory) return { firstLogin: true, newDevice: false, newLocation: false, level: 'low', reasons: [] };
  const newDevice = !known.devices.includes(family);
  const newLocation = !!geo && geo.key !== 'unknown' && !known.places.includes(geo.key);
  const reasons = [];
  if (newDevice) reasons.push(`New device: ${family}`);
  if (newLocation) reasons.push(`New location: ${geo.label}`);
  return { firstLogin: false, newDevice, newLocation, level: newDevice && newLocation ? 'high' : reasons.length ? 'medium' : 'low', reasons };
}
