import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

function key(): Buffer {
  const secret = process.env.GPTCDK_SECRET || '';
  if (secret.length < 32) {
    throw new Error('GPTCDK_SECRET 缺失或短于 32 字符，Team 功能已停用');
  }
  return scryptSync(secret, 'gptcdk-team', 32);
}

export function teamSecretReady(): boolean {
  return (process.env.GPTCDK_SECRET || '').length >= 32;
}

export function encryptSecret(plain: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(), iv);
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return `${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${data.toString('base64')}`;
}

export function decryptSecret(payload: string): string {
  const [ivText, tagText, dataText] = String(payload || '').split('.');
  if (!ivText || !tagText || !dataText) throw new Error('秘密格式无效');
  const decipher = createDecipheriv('aes-256-gcm', key(), Buffer.from(ivText, 'base64'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(dataText, 'base64')), decipher.final()]).toString('utf8');
}
