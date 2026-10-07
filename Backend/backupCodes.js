// One-time backup codes: format xxxxx-xxxxx (10 chars from an unambiguous alphabet), stored only as SHA-256 hashes.
import crypto from 'node:crypto';

const CHARS = 'abcdefghjkmnpqrstuvwxyz23456789';
export const BACKUP_CODE_COUNT = 10;

export function generateBackupCodes(count = BACKUP_CODE_COUNT) {
  return Array.from({ length: count }, () => {
    let s = '';
    for (const b of crypto.randomBytes(10)) s += CHARS[b % CHARS.length];
    return `${s.slice(0, 5)}-${s.slice(5)}`;
  });
}

export const normalizeBackupCode = (code) => String(code ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
export const hashBackupCode = (code) => crypto.createHash('sha256').update(normalizeBackupCode(code)).digest('hex');
export const looksLikeBackupCode = (code) => normalizeBackupCode(code).length === 10;

// Returns the remaining hashes if `code` matched one of them, otherwise null (pure: caller persists).
export function consumeBackupCode(hashes, code) {
  if (!looksLikeBackupCode(code)) return null;
  const h = hashBackupCode(code);
  const idx = hashes.indexOf(h);
  if (idx < 0) return null;
  return hashes.filter((_, i) => i !== idx);
}
