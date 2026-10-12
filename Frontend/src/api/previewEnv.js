// The Live preview has no network, so "where the visitor connects from" is simulated. The visitor can pretend their
// browser is another device and/or in another city to see new-device and new-location alerts. Nothing is detected.
import { simulatedGeo } from '../shared/risk';

const KEY = 'mfa_preview_env';

export const DEVICES = [
  { id: 'this', label: 'This browser', ua: null },
  { id: 'firefox-win', label: 'Firefox on Windows', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0' },
  { id: 'safari-ios', label: 'Safari on iPhone', ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1' },
  { id: 'chrome-mac', label: 'Chrome on macOS', ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36' },
];

// Finds a documentation-range address that the simulated GeoIP maps to the wanted city.
export function ipForCity(city) {
  for (let n = 1; n < 255; n++) {
    const ip = `203.0.113.${n}`;
    if (simulatedGeo(ip).label.startsWith(`${city},`)) return ip;
  }
  return '203.0.113.1';
}

export const PLACES = ['New York', 'London', 'Berlin', 'Mumbai', 'Tokyo', 'Sao Paulo'].map((city) => ({ id: city, label: simulatedGeo(ipForCity(city)).label, ip: ipForCity(city) }));

const DEFAULT_ENV = { device: 'this', place: 'New York' };

export function getEnv() {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) || 'null');
    if (v && DEVICES.some((d) => d.id === v.device) && PLACES.some((p) => p.id === v.place)) return v;
  } catch { /* use default */ }
  return DEFAULT_ENV;
}

export function setEnv(env) {
  try { localStorage.setItem(KEY, JSON.stringify({ ...getEnv(), ...env })); } catch { /* ignore */ }
  window.dispatchEvent(new Event('mfa:preview-env'));
}

// What the simulated server "sees" for the current request.
export function currentRequest() {
  const env = getEnv();
  const device = DEVICES.find((d) => d.id === env.device);
  return {
    ip: PLACES.find((p) => p.id === env.place).ip,
    userAgent: device.ua || (typeof navigator === 'undefined' ? '' : navigator.userAgent),
  };
}
