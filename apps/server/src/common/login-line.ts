import { looksEmail } from './utils';

/**
 * 账密行。有 2FA 时三段，没有时两段，不留空段。
 * 密码和 2FA 按原文输出，不用分隔符再切。
 */
export function formatLoginLine(email: string, password: string, totp?: string | null): string | null {
  const account = String(email ?? '').trim();
  const pass = typeof password === 'string' ? password : '';
  const factor = typeof totp === 'string' ? totp : '';
  if (!looksEmail(account) || !pass.trim()) return null;
  return factor.trim() ? `${account}----${pass}----${factor}` : `${account}----${pass}`;
}
