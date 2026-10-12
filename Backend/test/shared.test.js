// Pure unit tests for the shared rules: policy engine, lockout logic, rate-limit windows, risk assessment, score,
// CSV export, breach check (k-anonymity) and token scopes. No DB, no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  defaultPolicy, normalizePolicy, policyDiff, passwordRules, passwordError, passwordAge, compliance, twoFactorRequired,
} from '../shared/policy.js';
import { registerFailure, registerSuccess, lockStatus, lockDurationMs, formatDuration } from '../shared/lockout.js';
import { hitWindow, windowBlocked, RATE_LIMITS } from '../shared/ratelimit.js';
import { parseUserAgent, deviceLabel, simulatedGeo, geoFromHeaders, assessLogin, isPrivateIp } from '../shared/risk.js';
import { securityScore } from '../shared/score.js';
import { toCsv, csvCell, eventLabel, EVENTS } from '../shared/audit.js';
import { sha1Hex, parseRange, checkPwned } from '../shared/pwned.js';
import { validateTokenRequest, TOKEN_SCOPES, ROUTE_SCOPES } from '../shared/scopes.js';
import { bytesToB64u, b64uToBytes } from '../shared/b64u.js';

test('policy: defaults validate, bad values are reported with their path, diffs are listed', () => {
  const base = defaultPolicy();
  assert.deepEqual(normalizePolicy({}, base).errors, []);
  const { policy, errors } = normalizePolicy({ password: { minLength: 14, requireUpper: true }, lockout: { threshold: '7' }, twoFactor: { required: 'admins' } }, base);
  assert.deepEqual(errors, []);
  assert.equal(policy.password.minLength, 14);
  assert.equal(policy.lockout.threshold, 7, 'numeric strings from forms are accepted');
  assert.deepEqual(policyDiff(base, policy).sort(), ['lockout.threshold', 'password.minLength', 'password.requireUpper', 'twoFactor.required']);
  const bad = normalizePolicy({ password: { minLength: 2, requireLetter: 'yes' }, twoFactor: { methods: [] }, breachCheck: 'maybe', session: { lifetimeMinutes: 1.5 } }, base);
  assert.deepEqual(bad.errors.map((e) => e.path).sort(), ['breachCheck', 'password.minLength', 'password.requireLetter', 'session.lifetimeMinutes', 'twoFactor.methods']);
  assert.equal(bad.policy.password.minLength, 8, 'invalid input leaves the base value');
  assert.equal(normalizePolicy('nope').errors.length, 1);
  assert.deepEqual(base, defaultPolicy(), 'the base policy is never mutated');
});

test('policy: password rules follow the policy and the e-mail name is blocked', () => {
  const p = defaultPolicy();
  assert.equal(passwordError('secret12', p), null);
  assert.match(passwordError('short1', p), /at least 8/);
  assert.match(passwordError('onlyletters', p), /a number/);
  assert.match(passwordError('a1'.repeat(40), p), /at most 72 bytes/);
  assert.match(passwordError('', p), /required/);
  const strict = normalizePolicy({ password: { minLength: 12, requireUpper: true, requireSymbol: true } }).policy;
  assert.deepEqual(passwordRules('abc', strict).map((r) => r.id), ['len', 'letter', 'upper', 'number', 'symbol']);
  assert.equal(passwordError('Correct-Horse-9', strict), null);
  assert.match(passwordError('Correct-Horse-9', strict, { email: 'horse@example.com' }), /e-mail name/);
  assert.equal(passwordError('Correct-Horse-9', strict, { email: 'ab@example.com' }), null, 'very short names are ignored');
  assert.equal(passwordRules('ab', p, { email: 'a@b.co' }).some((r) => r.id === 'email'), false);
});

test('policy: password expiry and compliance requirements', () => {
  const p = normalizePolicy({ password: { maxAgeDays: 90 } }).policy;
  const now = Date.UTC(2026, 5, 1);
  const day = 86400000;
  assert.deepEqual(passwordAge(now - 10 * day, p, now), { ageDays: 10, expires: true, expired: false, daysLeft: 80 });
  assert.equal(passwordAge(now - 91 * day, p, now).expired, true);
  assert.equal(passwordAge(now - 900 * day, defaultPolicy(), now).expired, false, 'never expires when maxAgeDays is 0');
  const u = { role: 'user', twoFactorMethod: 'email', passkeyCount: 0, passwordChangedAt: now - 5 * day };
  assert.deepEqual(compliance(u, p, now), []);
  assert.equal(compliance({ ...u, mustChangePassword: true }, p, now)[0].reason, 'forced');
  assert.equal(compliance({ ...u, passwordChangedAt: now - 120 * day }, p, now)[0].reason, 'expired');
  const adminsOnly = normalizePolicy({ twoFactor: { required: 'admins' } }).policy;
  const noFactor = { ...u, twoFactorMethod: 'none' };
  assert.equal(twoFactorRequired({ role: 'admin' }, adminsOnly), true);
  assert.deepEqual(compliance(noFactor, adminsOnly, now), []);
  assert.equal(compliance({ ...noFactor, role: 'admin' }, adminsOnly, now)[0].id, 'enroll-2fa');
  assert.deepEqual(compliance({ ...noFactor, role: 'admin', passkeyCount: 1 }, adminsOnly, now), [], 'a passkey satisfies the rule');
  assert.equal(compliance({ ...noFactor, mustEnrollTwoFactor: true }, defaultPolicy(), now)[0].id, 'enroll-2fa');
  const totpOnly = normalizePolicy({ twoFactor: { methods: ['totp'] } }).policy;
  assert.equal(compliance(u, totpOnly, now)[0].id, 'enroll-2fa', 'a method the policy no longer allows must be replaced');
});

test('lockout: counts failures, locks at the threshold, escalates, decays and resets', () => {
  const p = defaultPolicy();
  let s = registerSuccess();
  const t0 = 1_000_000;
  for (let i = 1; i < p.lockout.threshold; i++) {
    const r = registerFailure(s, p, t0 + i);
    assert.equal(r.locked, false);
    assert.equal(r.attemptsLeft, p.lockout.threshold - i);
    s = r.state;
  }
  const locked = registerFailure(s, p, t0 + 10);
  assert.equal(locked.locked, true);
  assert.equal(locked.lockMs, 15 * 60000);
  assert.equal(locked.state.failedLogins, 0);
  assert.deepEqual(lockStatus(locked.state, t0 + 10 + 60000), { locked: true, retryAfterSeconds: 840 });
  assert.equal(lockStatus(locked.state, t0 + 10 + 15 * 60000).locked, false);
  // second lockout lasts twice as long, capped at 8x
  let st = locked.state;
  let ms = 0;
  for (let round = 0; round < 5; round++) {
    for (let i = 0; i < p.lockout.threshold; i++) { const r = registerFailure(st, p, t0 + 100 + round * 10 + i); st = r.state; if (r.locked) ms = r.lockMs; }
  }
  assert.equal(ms, 15 * 60000 * 8);
  assert.equal(lockDurationMs({ lockout: { durationMinutes: 10, progressive: false } }, 5), 600000);
  // old failures are forgotten
  const old = registerFailure({ failedLogins: 4, lastFailureAt: t0 }, p, t0 + 3 * 3600000);
  assert.equal(old.locked, false);
  assert.equal(old.state.failedLogins, 1);
  assert.deepEqual(registerSuccess(), { failedLogins: 0, lockCount: 0, lockUntil: 0, lastFailureAt: 0 });
  assert.equal(formatDuration(65), '1:05');
  assert.equal(formatDuration(3725), '1h 02m');
  const custom = normalizePolicy({ lockout: { threshold: 3, durationMinutes: 1, progressive: false } }).policy;
  let c = registerSuccess();
  for (let i = 0; i < 2; i++) c = registerFailure(c, custom, 5).state;
  assert.equal(registerFailure(c, custom, 5).lockMs, 60000);
});

test('rate-limit windows: counts, blocks, reports the countdown and resets', () => {
  const store = {};
  const cfg = { windowMs: 60000, limit: 3 };
  assert.equal(hitWindow(store, 'ip', cfg, 0).allowed, true);
  hitWindow(store, 'ip', cfg, 1000);
  assert.deepEqual(hitWindow(store, 'ip', cfg, 2000), { allowed: true, remaining: 0, retryAfterSeconds: 0 });
  const blocked = hitWindow(store, 'ip', cfg, 3000);
  assert.deepEqual([blocked.allowed, blocked.retryAfterSeconds], [false, 57]);
  assert.deepEqual(windowBlocked(store, 'ip', cfg, 30000), { blocked: true, retryAfterSeconds: 30 });
  assert.equal(windowBlocked(store, 'other', cfg, 0).blocked, false);
  assert.equal(hitWindow(store, 'ip', cfg, 61000).allowed, true, 'a new window starts');
  assert.equal(RATE_LIMITS.login.limit, 10);
});

test('risk: user agents, simulated geography, new device / location assessment', () => {
  const ff = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0';
  assert.equal(deviceLabel(ff), 'Firefox on Windows');
  assert.equal(deviceLabel('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1'), 'Safari on iOS');
  assert.equal(parseUserAgent('Mozilla/5.0 (Linux; Android 14) Chrome/130 Mobile Safari/537.36').device, 'mobile');
  assert.equal(deviceLabel('node-fetch'), 'API client');
  assert.equal(isPrivateIp('::ffff:192.168.1.4'), true);
  assert.equal(isPrivateIp('203.0.113.7'), false);
  assert.equal(simulatedGeo('127.0.0.1').label, 'Local network');
  assert.deepEqual(simulatedGeo('203.0.113.7'), simulatedGeo('203.0.113.7'), 'deterministic');
  assert.equal(simulatedGeo('203.0.113.7').simulated, true);
  assert.equal(geoFromHeaders('8.8.8.8', { 'cf-ipcountry': 'de' }).key, 'DE');
  assert.equal(geoFromHeaders('8.8.8.8', {}).label, 'Unknown location');
  assert.equal(geoFromHeaders('::1', {}).key, 'local');
  const known = { devices: ['Chrome on Windows'], places: ['US'] };
  const geoUs = { key: 'US', label: 'New York, United States' };
  const geoDe = { key: 'DE', label: 'Berlin, Germany' };
  assert.equal(assessLogin({ family: 'X', geo: geoDe }, { devices: [], places: [] }).firstLogin, true);
  assert.equal(assessLogin({ family: 'Chrome on Windows', geo: geoUs }, known).level, 'low');
  assert.equal(assessLogin({ family: 'Firefox on Windows', geo: geoUs }, known).level, 'medium');
  const both = assessLogin({ family: 'Firefox on Windows', geo: geoDe }, known);
  assert.equal(both.level, 'high');
  assert.deepEqual(both.reasons, ['New device: Firefox on Windows', 'New location: Berlin, Germany']);
  assert.equal(assessLogin({ family: 'Chrome on Windows', geo: { key: 'unknown', label: 'Unknown location' } }, known).level, 'low');
});

test('score: weights add up to 100 and recommendations are ranked by gain', () => {
  const p = defaultPolicy();
  const best = { twoFactorMethod: 'totp', passkeyCount: 1, backupCodesRemaining: 8, passwordChangedAt: new Date(), breachStatus: 'clean', recoveryEmailVerified: true, trustedDevices: 0, sessionCount: 1, unreviewedAlerts: 0, riskyTokens: 0 };
  const top = securityScore(best, p);
  assert.equal(top.items.reduce((n, i) => n + i.max, 0), 100);
  assert.equal(top.score, 100);
  assert.equal(top.grade, 'A');
  assert.deepEqual(top.recommendations, []);
  const weak = securityScore({ ...best, twoFactorMethod: 'none', passkeyCount: 0, backupCodesRemaining: 0, breachStatus: 'pwned', recoveryEmailVerified: false, unreviewedAlerts: 2 }, p);
  assert.ok(weak.score < 35);
  assert.equal(weak.grade, 'F');
  assert.equal(weak.recommendations[0].id, 'factor');
  assert.ok(weak.recommendations.every((r, i, a) => i === 0 || a[i - 1].gain >= r.gain));
  assert.equal(securityScore({ ...best, passkeyCount: 0, twoFactorMethod: 'email' }, p).items.find((i) => i.id === 'factor').points, 18);
  const expired = securityScore({ ...best, passwordChangedAt: new Date(Date.now() - 200 * 86400000) }, normalizePolicy({ password: { maxAgeDays: 90 } }).policy);
  assert.equal(expired.items.find((i) => i.id === 'age').points, 0);
});

test('csv: quoting, formula protection and the audit catalogue', () => {
  assert.equal(csvCell('plain'), 'plain');
  assert.equal(csvCell('a,b'), '"a,b"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('=1+1'), "'=1+1");
  assert.equal(csvCell('+SUM(A1)'), "'+SUM(A1)");
  assert.equal(csvCell('-2'), "'-2");
  assert.equal(csvCell('@cmd'), "'@cmd");
  assert.equal(csvCell(null), '');
  assert.equal(csvCell(new Date(0)), '1970-01-01T00:00:00.000Z');
  assert.equal(toCsv([{ a: 1, b: 'x,y' }], [['A', 'a'], ['B', (r) => r.b]]), 'A,B\r\n1,"x,y"\r\n');
  assert.equal(eventLabel('login'), 'Signed in');
  assert.equal(eventLabel('mystery'), 'mystery');
  assert.ok(Object.values(EVENTS).every(([label, sev, cat]) => label && ['info', 'warn', 'critical'].includes(sev) && ['signin', 'security', 'account', 'admin'].includes(cat)));
});

test('breach check: only the 5-character hash prefix is sent; padding and failures are handled', async () => {
  assert.equal(await sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  const range = '1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0000000000000000000000000000000000A:0\r\nnot a line';
  assert.deepEqual([...parseRange(range)], [['1E4C9B93F3F0682250B6CF8331B7EE68FD8', 3861493]]);
  const calls = [];
  const fakeFetch = async (url) => { calls.push(url); return { ok: true, text: async () => range }; };
  const hit = await checkPwned('password', { fetchImpl: fakeFetch });
  assert.deepEqual(hit, { status: 'pwned', count: 3861493 });
  assert.equal(calls.length, 1);
  assert.equal(calls[0], 'https://api.pwnedpasswords.com/range/5BAA6', 'k-anonymity: the URL carries 5 characters only');
  assert.ok(calls[0].endsWith('/range/5BAA6') && !calls[0].includes('1E4C9'));
  assert.deepEqual(await checkPwned('a-very-unique-passphrase-9#', { fetchImpl: fakeFetch }), { status: 'safe' });
  assert.equal((await checkPwned('x', { fetchImpl: async () => ({ ok: false, status: 503 }) })).status, 'unavailable');
  assert.equal((await checkPwned('x', { fetchImpl: async () => { throw new TypeError('offline'); } })).reason, 'network');
  assert.equal((await checkPwned('x', { fetchImpl: undefined === 1 ? null : 'not a function' })).status, 'unavailable');
  const slow = await checkPwned('x', { timeoutMs: 20, fetchImpl: (url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })))) });
  assert.equal(slow.reason, 'timeout');
});

test('tokens: request validation, scopes and base64url helpers', () => {
  assert.ok(validateTokenRequest({ name: 'ci job', scopes: ['profile:read'], expiresInDays: 30 }).value);
  assert.match(validateTokenRequest({ name: 'a', scopes: ['profile:read'] }).error, /name/);
  assert.match(validateTokenRequest({ name: 'ok name', scopes: [] }).error, /scope/);
  assert.match(validateTokenRequest({ name: 'ok name', scopes: ['root'] }).error, /scope/);
  assert.match(validateTokenRequest({ name: 'ok name', scopes: ['profile:read'], expiresInDays: 5 }).error, /expiry/);
  assert.deepEqual(validateTokenRequest({ name: 'ok name', scopes: ['profile:read', 'profile:read'] }).value.scopes, ['profile:read']);
  assert.ok(Object.values(ROUTE_SCOPES).every((s) => s in TOKEN_SCOPES));
  const bytes = Uint8Array.from([0, 250, 251, 252, 253, 254, 255]);
  assert.equal(bytesToB64u(bytes), 'APr7_P3-_w');
  assert.deepEqual([...b64uToBytes('APr7_P3-_w')], [...bytes]);
});

test('shared modules stay identical in the Frontend copy', () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const front = path.join(here, '..', '..', 'Frontend', 'src', 'shared');
  if (!fs.existsSync(front)) return; // backend-only checkout
  for (const f of fs.readdirSync(path.join(here, '..', 'shared'))) {
    assert.equal(fs.readFileSync(path.join(front, f), 'utf8'), fs.readFileSync(path.join(here, '..', 'shared', f), 'utf8'), `${f} differs; run "npm run sync-shared" in Backend`);
  }
});
