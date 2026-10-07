import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../auth/auth', () => {
  let token = null;
  return { getToken: () => token, setToken: (t) => { token = t; }, clearToken: () => { token = null; }, getDeviceToken: () => null, setDeviceToken: () => {} };
});

const { demoApi } = await import('../api/demoApi');
const { listMail, resetDemoData } = await import('../api/demoStore');
const { DEMO_PASSWORD, DEMO_BACKUP_CODE } = await import('../api/demoAccounts');

beforeEach(() => { vi.useRealTimers(); resetDemoData(); });

describe('demo backend', () => {
  it('rejects a wrong password and a weak new password', async () => {
    await expect(demoApi.login({ email: 'demo@example.com', password: 'nope-nope-1A!' })).rejects.toBeTruthy();
    await expect(demoApi.register({ email: 'new@example.com', password: 'weak' })).rejects.toBeTruthy();
  });
  it('e-mail flow: login drops a code in the demo inbox and the code signs in', async () => {
    const res = await demoApi.login({ email: 'demo@example.com', password: DEMO_PASSWORD });
    expect(res.twoFactor || res.requires2fa || res.method || res).toBeTruthy();
    const mail = listMail()[0];
    expect(mail.to).toBe('demo@example.com');
    expect(mail.code).toMatch(/^\d{6}$/);
    await expect(demoApi.verifyCode({ email: 'demo@example.com', code: '000000' === mail.code ? '111111' : '000000' })).rejects.toBeTruthy();
    const ok = await demoApi.verifyCode({ email: 'demo@example.com', code: mail.code });
    expect(ok.token).toBeTruthy();
  });
  it('backup code works once for the authenticator account', async () => {
    await demoApi.login({ email: 'alice@example.com', password: DEMO_PASSWORD });
    const ok = await demoApi.verifyCode({ email: 'alice@example.com', code: DEMO_BACKUP_CODE });
    expect(ok.token).toBeTruthy();
    await demoApi.login({ email: 'alice@example.com', password: DEMO_PASSWORD });
    await expect(demoApi.verifyCode({ email: 'alice@example.com', code: DEMO_BACKUP_CODE })).rejects.toBeTruthy();
  });
  it('locks the account after repeated wrong passwords', async () => {
    let last;
    for (let i = 0; i < 8; i++) {
      try { await demoApi.login({ email: 'bob@example.com', password: 'Wrong-pass-1!' }); } catch (e) { last = e; }
    }
    expect(last.status).toBe(423);
  }, 30000);
});
