import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../auth/auth', () => {
  let token = null;
  return {
    getToken: () => token, setToken: (t) => { token = t; }, clearToken: () => { token = null; },
    getDeviceToken: () => null, setDeviceToken: () => {}, getCsrf: () => null, setCsrf: () => {},
  };
});

const { setToken } = await import('../auth/auth');
const { previewApi: api, setBreachChecker } = await import('../api/previewApi');
const { listMail, resetPreviewData, loadDb, saveDb } = await import('../api/previewStore');
const { PREVIEW_PASSWORD: PW, PREVIEW_BACKUP_CODE, PREVIEW_TOTP_SECRET } = await import('../api/previewAccounts');
const { setEnv } = await import('../api/previewEnv');
const { totpFromSecret, base32Decode, totp } = await import('../lib/totp');
const { createPasskey, getPasskey } = await import('../lib/webauthnClient');
const { b64uToBytes, bytesToB64u } = await import('../shared/b64u');

const MEMBER = 'member@example.com';
const ADMIN = 'admin@example.com';
const NEW_PW = 'Fresh-pass-77x';

beforeEach(() => {
  vi.useRealTimers();
  resetPreviewData();
  localStorage.clear();
  setToken(null);
  setBreachChecker(async () => ({ status: 'safe' }));
});

async function signIn(email, password = PW) {
  const res = await api.login({ email, password });
  if (res.step === 'done') { setToken(res.token); return res; }
  const mail = listMail().find((m) => m.to === email && m.code);
  const done = await api.verifyCode({ email, code: mail.code });
  setToken(done.token);
  return done;
}
const expireStepUp = () => {
  const db = loadDb();
  Object.values(db.users).forEach((u) => u.sessions.forEach((s) => { s.stepUpUntil = 0; }));
  saveDb(db);
};
const rejects = async (promise) => { try { await promise; } catch (e) { return e; } throw new Error('expected a rejection'); };

describe('sign-in', () => {
  it('rejects a wrong password and a weak new password', async () => {
    await expect(api.login({ email: MEMBER, password: 'nope-nope-1A!' })).rejects.toBeTruthy();
    await expect(api.register({ email: 'new@example.com', password: 'weak' })).rejects.toBeTruthy();
  });

  it('e-mail flow: the code lands in the Preview inbox and signs in once', async () => {
    const res = await api.login({ email: MEMBER, password: PW });
    expect(res.method).toBe('email');
    const mail = listMail()[0];
    expect(mail.to).toBe(MEMBER);
    expect(mail.code).toMatch(/^\d{6}$/);
    await expect(api.verifyCode({ email: MEMBER, code: mail.code === '000000' ? '111111' : '000000' })).rejects.toBeTruthy();
    const ok = await api.verifyCode({ email: MEMBER, code: mail.code });
    expect(ok.token).toBeTruthy();
    await expect(api.verifyCode({ email: MEMBER, code: mail.code })).rejects.toBeTruthy();
  });

  it('authenticator account: live code works once, a backup code works once', async () => {
    await api.login({ email: 'alice@example.com', password: PW });
    const code = await totpFromSecret(PREVIEW_TOTP_SECRET);
    expect((await api.verifyCode({ email: 'alice@example.com', code })).token).toBeTruthy();
    await api.login({ email: 'alice@example.com', password: PW });
    await expect(api.verifyCode({ email: 'alice@example.com', code })).rejects.toBeTruthy();
    expect((await api.verifyCode({ email: 'alice@example.com', code: PREVIEW_BACKUP_CODE })).token).toBeTruthy();
    await api.login({ email: 'alice@example.com', password: PW });
    await expect(api.verifyCode({ email: 'alice@example.com', code: PREVIEW_BACKUP_CODE })).rejects.toBeTruthy();
  });

  it('locks the account after repeated wrong passwords, with a countdown, then escalates', async () => {
    let last;
    for (let i = 0; i < 5; i++) { try { await api.login({ email: 'bob@example.com', password: 'Wrong-pass-1!' }); } catch (e) { last = e; } }
    expect(last.data.locked).toBe(true);
    expect(last.data.retryAfterSeconds).toBe(900);
    const blocked = await rejects(api.login({ email: 'bob@example.com', password: PW }));
    expect(blocked.status).toBe(423);
    expect(blocked.data.retryAfterSeconds).toBeGreaterThan(800);
    const db = loadDb();
    db.users['bob@example.com'].lock.lockUntil = Date.now() - 1000;
    saveDb(db);
    for (let i = 0; i < 5; i++) { try { await api.login({ email: 'bob@example.com', password: 'Wrong-pass-1!' }); } catch (e) { last = e; } }
    expect(last.data.retryAfterSeconds).toBe(1800);
  });

  it('rate-limits failed sign-ins and reports how long to wait', async () => {
    let err;
    for (let i = 0; i < 11; i++) { err = await rejects(api.login({ email: `ghost${i}@example.com`, password: 'Wrong-pass-1!' })); }
    expect(err.status).toBe(429);
    expect(err.data.rateLimited).toBe(true);
    expect(err.data.retryAfterSeconds).toBeGreaterThan(0);
    expect(err.message).toMatch(/Try again in/);
  });

  it('trusted devices are honoured and can be switched off by policy', async () => {
    await api.login({ email: MEMBER, password: PW });
    const done = await api.verifyCode({ email: MEMBER, code: listMail()[0].code, trust: true });
    expect(done.deviceToken).toBeTruthy();
    const again = await api.login({ email: MEMBER, password: PW, deviceToken: done.deviceToken });
    expect(again.method).toBe('trusted');
  });
});

describe('step-up, password, sessions', () => {
  it('sensitive actions need a recent confirmation (password or code); wrong proofs are refused', async () => {
    await signIn(MEMBER);
    expireStepUp();
    const err = await rejects(api.createToken({ name: 'ci', scopes: ['profile:read'], expiresInDays: 30 }));
    expect(err.data.code).toBe('STEP_UP_REQUIRED');
    expect(err.data.stepUp.password).toBe(true);
    await expect(api.stepUp({ password: 'nope-nope1A' })).rejects.toBeTruthy();
    expect((await api.stepUp({ password: PW })).success).toBe(true);
    expect((await api.createToken({ name: 'ci', scopes: ['profile:read'], expiresInDays: 30 })).token).toMatch(/^mfa_pat_/);
  });

  it('authenticator codes confirm identity once only', async () => {
    await api.login({ email: 'alice@example.com', password: PW });
    const first = await totpFromSecret(PREVIEW_TOTP_SECRET);
    setToken((await api.verifyCode({ email: 'alice@example.com', code: first })).token);
    expireStepUp();
    expect((await rejects(api.removeRecoveryEmail())).data.code).toBe('STEP_UP_REQUIRED');
    await expect(api.stepUp({ code: first })).rejects.toBeTruthy(); // same step as the sign-in code
    const next = await totp(base32Decode(PREVIEW_TOTP_SECRET), Date.now() + 30000);
    expect((await api.stepUp({ code: next })).success).toBe(true);
  });

  it('change password: history, expiry and the breach check', async () => {
    await signIn(MEMBER);
    await expect(api.changePassword({ currentPassword: 'nope-nope1A', newPassword: NEW_PW })).rejects.toBeTruthy();
    expect((await api.changePassword({ currentPassword: PW, newPassword: NEW_PW })).success).toBe(true);
    const reuse = await rejects(api.changePassword({ currentPassword: NEW_PW, newPassword: PW }));
    expect(reuse.message).toMatch(/used this password before/);

    setBreachChecker(async () => ({ status: 'pwned', count: 1234 }));
    const warned = await api.changePassword({ currentPassword: NEW_PW, newPassword: 'Another-pass-88y' });
    expect(warned.warning).toMatch(/1,234/);
    expect((await api.security()).breachStatus).toBe('pwned');

    const admin = loadDb();
    admin.policy.breachCheck = 'block';
    admin.policy.password.maxAgeDays = 30;
    admin.users[MEMBER].passwordChangedAt = Date.now() - 40 * 86400000;
    saveDb(admin);
    expect((await rejects(api.changePassword({ currentPassword: 'Another-pass-88y', newPassword: 'Third-pass-99z' }))).message).toMatch(/known data breaches/);
    setBreachChecker(async () => ({ status: 'unavailable' }));
    expect((await api.changePassword({ currentPassword: 'Another-pass-88y', newPassword: 'Third-pass-99z' })).success).toBe(true);
  });

  it('sessions: name, revoke one, revoke others, sign out everywhere', async () => {
    await signIn(MEMBER);
    const list = await api.sessions();
    expect(list.length).toBe(3);
    const cur = list.find((s) => s.current);
    expect(cur.geo).toMatch(/New York/);
    await api.renameSession(cur.id, 'My laptop');
    expect((await api.sessions()).find((s) => s.current).name).toBe('My laptop');
    const other = list.find((s) => !s.current);
    expect((await api.revokeSession(other.id)).success).toBe(true);
    await expect(api.revokeSession('missing')).rejects.toBeTruthy();
    await api.revokeOtherSessions();
    expect((await api.sessions()).length).toBe(1);
    await api.revokeAllSessions();
    expect((await rejects(api.me())).status).toBe(401);
  });

  it('activity and export (CSV is formula-safe)', async () => {
    await signIn(MEMBER);
    const events = await api.activity();
    expect(events.length).toBeGreaterThan(3);
    expect(events[0].event).toBe('login');
    const security = await api.activity({ category: 'security' });
    expect(security.every((e) => e.event === 'password-changed' || e.event === '2fa-changed')).toBe(true);
    const csv = await api.exportActivity({ format: 'csv' });
    expect(csv.text.split('\r\n')[0]).toMatch(/^Time \(UTC\),Event/);
    expect((await api.exportActivity({ format: 'json' })).text).toContain(MEMBER);
  });
});

describe('passkeys (simulated server in the browser, software authenticator)', () => {
  async function addPasskey() {
    const { challengeId, options } = await api.passkeyRegisterOptions();
    const response = await createPasskey(options, { simulate: true });
    return api.passkeyRegisterVerify({ challengeId, response, name: 'Laptop' });
  }

  it('registers, signs in without a password, rejects replays, tampering and removed keys', async () => {
    await signIn(MEMBER);
    const keys = await addPasskey();
    expect(keys[0].name).toBe('Laptop');
    expect((await api.security()).passkeys).toBe(1);
    setToken(null);

    const lo = await api.passkeyOptions({ purpose: 'login' });
    const assertion = await getPasskey(lo.options, { simulate: true });
    const res = await api.passkeyVerify({ purpose: 'login', challengeId: lo.challengeId, response: assertion });
    expect(res.user.email).toBe(MEMBER);
    expect(res.token).toBeTruthy();
    await expect(api.passkeyVerify({ purpose: 'login', challengeId: lo.challengeId, response: assertion })).rejects.toBeTruthy();

    const lo2 = await api.passkeyOptions({ purpose: 'login' });
    const bad = await getPasskey(lo2.options, { simulate: true });
    bad.response.signature = bad.response.signature.slice(0, -4) + 'AAAA';
    await expect(api.passkeyVerify({ purpose: 'login', challengeId: lo2.challengeId, response: bad })).rejects.toBeTruthy();

    // second step after the password
    await api.login({ email: MEMBER, password: PW });
    const mo = await api.passkeyOptions({ purpose: 'mfa', email: MEMBER });
    expect(mo.options.allowCredentials.length).toBe(1);
    const mfa = await api.passkeyVerify({ purpose: 'mfa', email: MEMBER, challengeId: mo.challengeId, response: await getPasskey(mo.options, { simulate: true }) });
    setToken(mfa.token);

    // step-up with the passkey, rename, remove
    expireStepUp();
    expect((await rejects(api.removePasskey(keys[0].id))).data.code).toBe('STEP_UP_REQUIRED');
    const so = await api.passkeyStepUpOptions();
    expect((await api.passkeyStepUpVerify({ challengeId: so.challengeId, response: await getPasskey(so.options, { simulate: true }) })).success).toBe(true);
    await api.renamePasskey(keys[0].id, 'Work laptop');
    expect((await api.passkeys())[0].name).toBe('Work laptop');
    expect((await api.removePasskey(keys[0].id)).length).toBe(0);
  });

  it('refuses a passkey made for another origin or a stale challenge', async () => {
    await signIn(MEMBER);
    const { challengeId, options } = await api.passkeyRegisterOptions();
    const response = await createPasskey(options, { simulate: true });
    const cd = JSON.parse(new TextDecoder().decode(b64uToBytes(response.response.clientDataJSON)));
    cd.origin = 'https://evil.example';
    response.response.clientDataJSON = bytesToB64u(new TextEncoder().encode(JSON.stringify(cd)));
    expect((await rejects(api.passkeyRegisterVerify({ challengeId, response }))).message).toMatch(/origin/i);
    await expect(api.passkeyRegisterVerify({ challengeId, response })).rejects.toBeTruthy(); // challenge already used
  });
});

describe('API tokens and alerts', () => {
  it('tokens are scoped, read-only, expiring and revocable', async () => {
    await signIn(MEMBER);
    await expect(api.createToken({ name: 'x', scopes: ['profile:read'] })).rejects.toBeTruthy();
    const { token, tokenInfo } = await api.createToken({ name: 'reporting', scopes: ['profile:read'], expiresInDays: 7 });
    expect(JSON.stringify(loadDb())).not.toContain(token);
    expect((await api.callWithToken({ token, route: 'GET /auth/me' })).body.user.email).toBe(MEMBER);
    expect((await api.callWithToken({ token, route: 'GET /auth/sessions' })).status).toBe(403);
    expect((await api.callWithToken({ token: 'mfa_pat_bogus', route: 'GET /auth/me' })).status).toBe(401);
    expect((await api.callWithToken({ token, route: 'POST /auth/logout' })).status).toBe(404);
    expect((await api.tokens())[0].lastUsedAt).toBeTruthy();
    await api.revokeToken(tokenInfo.id);
    expect((await api.callWithToken({ token, route: 'GET /auth/me' })).status).toBe(401);
  });

  it('a new device or place raises an alert with a review link; "no" signs everything out and forces a new password', async () => {
    await signIn(MEMBER);
    expect(listMail().find((m) => m.kind === 'new-device')).toBeUndefined();
    setEnv({ device: 'firefox-win', place: 'Berlin' });
    const res = await signIn(MEMBER);
    expect(res.alert.level).toBe('high');
    const mail = listMail().find((m) => m.kind === 'new-device');
    expect(mail.link).toContain('#/review?t=');
    expect((await api.security()).unreviewedAlerts).toBe(1);

    const t = mail.link.split('t=')[1];
    await expect(api.alertRespondByLink({ t: `${t}x`, answer: 'yes' })).rejects.toBeTruthy();
    expect((await api.alertRespondByLink({ t, answer: 'no' })).status).toBe('denied');
    expect((await rejects(api.me())).status).toBe(401);
    const back = await signIn(MEMBER);
    expect(back.user.requirements.map((r) => r.id)).toEqual(['change-password']);
    expect((await rejects(api.sessions())).data.code).toBe('ACTION_REQUIRED');
  });

  it('in-app answer "yes" confirms the alert', async () => {
    await signIn(MEMBER);
    setEnv({ device: 'safari-ios' });
    await signIn(MEMBER);
    const [alert] = await api.alerts();
    expect(alert.status).toBe('pending');
    expect((await api.respondAlert({ id: alert.id, answer: 'yes' })).status).toBe('confirmed');
    expect((await api.security()).unreviewedAlerts).toBe(0);
  });
});

describe('recovery', () => {
  it('recovery code by e-mail (and to a verified recovery address) resets the password and signs sessions out', async () => {
    await signIn(MEMBER);
    await api.setRecoveryEmail({ email: 'backup@example.org' });
    const verifyMail = listMail().find((m) => m.kind === 'verify-recovery-email');
    await expect(api.verifyRecoveryEmail({ code: verifyMail.code === '000000' ? '111111' : '000000' })).rejects.toBeTruthy();
    expect((await api.verifyRecoveryEmail({ code: verifyMail.code })).recoveryEmail).toBe('b***@example.org');

    const generic = await api.recoverRequest({ email: MEMBER });
    expect((await api.recoverRequest({ email: 'ghost@example.com' })).message).toBe(generic.message);
    const codes = listMail().filter((m) => m.kind === 'recovery');
    expect(codes.map((m) => m.to).sort()).toEqual(['backup@example.org', MEMBER]);
    await expect(api.recoverReset({ email: MEMBER, code: '000000', newPassword: NEW_PW })).rejects.toBeTruthy();
    expect((await api.recoverReset({ email: MEMBER, code: codes[0].code, newPassword: NEW_PW })).success).toBe(true);
    expect((await rejects(api.me())).status).toBe(401);
    expect((await signIn(MEMBER, NEW_PW)).token).toBeTruthy();
  });
});

describe('admin console', () => {
  it('is for administrators only', async () => {
    await signIn(MEMBER);
    expect((await rejects(api.adminUsers())).data.code).toBe('FORBIDDEN');
  });

  it('lists, filters and manages users; every change is audited; guards protect the last admin and yourself', async () => {
    await signIn(ADMIN);
    const all = await api.adminUsers();
    expect(all.total).toBe(4);
    expect((await api.adminUsers({ q: 'ali' })).users.map((u) => u.email)).toEqual(['alice@example.com']);
    expect((await api.adminUsers({ role: 'admin' })).total).toBe(1);
    const stats = await api.adminStats();
    expect(stats.users).toBe(4);
    expect(stats.series.length).toBe(7);

    const member = all.users.find((u) => u.email === MEMBER);
    const me = all.users.find((u) => u.email === ADMIN);
    expect((await api.adminAction(member.id, 'lock', { reason: 'review' })).status).toBe('admin-locked');
    const refused = await rejects(api.login({ email: MEMBER, password: PW }));
    expect(refused.data.adminLocked).toBe(true);
    expect((await api.adminAction(member.id, 'unlock')).status).toBe('active');
    await api.adminAction(member.id, 'force-reset');
    expect((await signIn(MEMBER)).user.requirements[0].id).toBe('change-password');
    await signIn(ADMIN);

    expect((await rejects(api.adminAction(me.id, 'lock'))).message).toMatch(/own account/);
    expect((await rejects(api.adminAction(me.id, 'role', { role: 'user' }))).message).toMatch(/own role/);
    expect((await rejects(api.adminAction(member.id, 'role', { role: 'owner' }))).status).toBe(400);
    expect((await rejects(api.adminAction(member.id, 'frobnicate'))).status).toBe(404);
    expect((await api.adminAction(member.id, 'reset-2fa')).twoFactorMethod).toBe('email');

    const audit = await api.adminAudit({ event: 'admin-lock,admin-unlock' });
    expect(audit.total).toBe(2);
    expect(audit.events[0].actorEmail).toBe(ADMIN);
    expect((await api.adminAudit({ category: 'admin', severity: 'warn' })).events.every((e) => e.category === 'admin' && e.severity === 'warn')).toBe(true);
    expect((await api.adminAudit({ from: '2999-01-01' })).total).toBe(0);
    expect((await api.adminAudit({ limit: 5 })).events.length).toBe(5);
  });

  it('audit CSV export keeps spreadsheet formulas inert', async () => {
    await signIn(ADMIN);
    await rejects(api.login({ email: '=cmd|calc@example.com', password: 'x' }));
    const file = await api.adminAuditExport({ event: 'login-failed' });
    expect(file.filename).toBe('audit-log.csv');
    expect(file.text.split('\r\n')[0]).toMatch(/^Time \(UTC\),Event,Description,Severity,Result,Actor,Target,IP,Device,Location$/);
    expect(file.text).toContain('login-failed');
  });

  it('policy: validated, applied to sign-up, required factors block accounts until they enrol; test mail goes to the inbox', async () => {
    await signIn(ADMIN);
    const bad = await rejects(api.adminSetPolicy({ password: { minLength: 2 }, lockout: { threshold: 'x' } }));
    expect(bad.data.errors.length).toBe(2);
    const saved = await api.adminSetPolicy({ password: { minLength: 12, requireSymbol: true }, twoFactor: { required: 'everyone' } });
    expect(saved.changed).toEqual(expect.arrayContaining(['password.minLength', 'password.requireSymbol', 'twoFactor.required']));
    await expect(api.register({ email: 'short@example.com', password: 'Abcdef12' })).rejects.toBeTruthy();
    expect((await api.register({ email: 'long@example.com', password: 'Correct-horse-9!' })).success).toBe(true);
    expect((await api.getPolicy()).password.minLength).toBe(12);
    // bob has no second step: he is blocked from everything but enrolment
    const bob = await signIn('bob@example.com');
    expect(bob.user.requirements[0].id).toBe('enroll-2fa');
    expect((await rejects(api.sessions())).data.code).toBe('ACTION_REQUIRED');
    expect((await rejects(api.setMethod({ method: 'none' }))).message).toMatch(/required/);
    expect((await api.setMethod({ method: 'email' })).twoFactorMethod).toBe('email');
    expect((await api.sessions()).length).toBeGreaterThan(0);
    await signIn(ADMIN);
    await api.adminTestMail();
    expect(listMail()[0].kind).toBe('admin-test');
  });

  it('help requests reach the admin, who can issue a recovery code', async () => {
    const generic = await api.recoverAssist({ email: MEMBER, message: 'lost my phone' });
    expect((await api.recoverAssist({ email: 'ghost@example.com' })).message).toBe(generic.message);
    await signIn(ADMIN);
    const help = await api.adminUsers({ assist: 'true' });
    expect(help.total).toBe(1);
    expect(help.users[0].assistMessage).toBe('lost my phone');
    await api.adminAction(help.users[0].id, 'issue-recovery');
    expect(listMail()[0].kind).toBe('recovery');
    expect((await api.adminUsers({ assist: 'true' })).total).toBe(0);
  });
});
