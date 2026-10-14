import { createHash, timingSafeEqual } from 'crypto';
import { decryptSecret } from './secret-box';
import { parseTeamLines } from '../team/team-rules';

export const BUSINESS_PLAN = 'self_serve_business_prolite';
export const SELLER_TEAM_TAG = '5X Team';
export const CREDENTIAL_MISS = '找不到对应的已交付账号';
export const IMPORT_LINE_CAP = 50;

const SECRET_KEYS = new Set([
  'password',
  'proxy',
  'totp',
  'session',
  'sessionUpdate',
  'cookies',
  'passwordCipher',
  'totpCipher',
  'proxyCipher',
]);

export function isTeamSellerTag(tag: string | null | undefined): boolean {
  return String(tag || '').trim() === SELLER_TEAM_TAG;
}

export function normalizeSubscriptionTag(value: unknown): string {
  const tag = String(value ?? '').trim();
  if (!tag || tag.length > 32 || /[\\/]/.test(tag) || tag.includes('..')) return '';
  return tag;
}

export function nextExtractRetry(attempt: number, now = Date.now()): Date {
  const seconds = attempt <= 1 ? 30 : attempt === 2 ? 60 : attempt === 3 ? 120 : 300;
  return new Date(now + seconds * 1000);
}

export function secretsEqual(left: string, right: string): boolean {
  const a = createHash('sha256').update(String(left ?? ''), 'utf8').digest();
  const b = createHash('sha256').update(String(right ?? ''), 'utf8').digest();
  return timingSafeEqual(a, b);
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const part = String(token || '').split('.')[1];
  if (!part) return null;
  try {
    const parsed = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function claim(payload: Record<string, unknown> | null, key: string): string {
  if (!payload) return '';
  const direct = payload[key];
  if (typeof direct === 'string' && direct.trim()) return direct.trim();
  const auth = payload['https://api.openai.com/auth'];
  if (auth && typeof auth === 'object') {
    const nested = (auth as Record<string, unknown>)[key];
    if (typeof nested === 'string' && nested.trim()) return nested.trim();
  }
  return '';
}

export function personalPlanAllowed(payload: Record<string, unknown> | null): boolean {
  const plan = claim(payload, 'chatgpt_plan_type');
  if (!plan || plan === 'free' || plan === 'team' || plan.startsWith('self_serve_business')) return false;
  const accountId = claim(payload, 'chatgpt_account_id');
  const workspaceId = claim(payload, 'chatgpt_workspace_id') || claim(payload, 'workspace_id');
  if (accountId && workspaceId && accountId !== workspaceId) return false;
  return true;
}

function reclaimPlanAllowed(payload: Record<string, unknown> | null): boolean {
  if (claim(payload, 'chatgpt_plan_type')) return personalPlanAllowed(payload);
  const accountId = claim(payload, 'chatgpt_account_id');
  const workspaceId = claim(payload, 'chatgpt_workspace_id') || claim(payload, 'workspace_id');
  return !(accountId && workspaceId && accountId !== workspaceId);
}

export function tokenFitsStoredWorkspace(
  account: { remoteWorkspaceId?: string | null },
  accessToken: string,
): boolean {
  const expected = String(account.remoteWorkspaceId || '').trim();
  if (!expected) return true;
  const payload = decodeJwtPayload(accessToken);
  if (!payload) return false;
  return claim(payload, 'chatgpt_account_id') === expected && claim(payload, 'chatgpt_plan_type') === BUSINESS_PLAN;
}

export function teamDeliveryReady(account: { remoteWorkspaceId?: string | null; accessToken?: string | null }): boolean {
  const expected = String(account.remoteWorkspaceId || '').trim();
  const accessToken = String(account.accessToken || '').trim();
  if (!expected || !accessToken) return false;
  return tokenFitsStoredWorkspace({ remoteWorkspaceId: expected }, accessToken);
}

export function teamTokenProof(accessToken: string): { ok: true; workspaceId: string; planType: string } | { ok: false } {
  const payload = decodeJwtPayload(accessToken);
  const plan = claim(payload, 'chatgpt_plan_type');
  const workspaceId = claim(payload, 'chatgpt_account_id');
  if (plan !== BUSINESS_PLAN || !workspaceId) return { ok: false };
  return { ok: true, workspaceId, planType: plan };
}

export function sellerTokenFields(tag: string, accessToken: string): {
  ok: boolean;
  planType: string | null;
  remoteWorkspaceId: string | null;
  reason: string;
} {
  if (isTeamSellerTag(tag)) {
    const proof = teamTokenProof(accessToken);
    if (!proof.ok) {
      return { ok: false, planType: null, remoteWorkspaceId: null, reason: '5X Team 需要空间 token，不能直接入库个人文件' };
    }
    return { ok: true, planType: proof.planType, remoteWorkspaceId: proof.workspaceId, reason: '' };
  }
  if (!personalPlanAllowed(decodeJwtPayload(accessToken))) {
    return { ok: false, planType: null, remoteWorkspaceId: null, reason: '个人订阅核对失败，未入库' };
  }
  return { ok: true, planType: claim(decodeJwtPayload(accessToken), 'chatgpt_plan_type') || null, remoteWorkspaceId: null, reason: '' };
}

export function accountMatchesSellerTag(account: {
  subscriptionTag?: string | null;
  accessToken?: string | null;
  remoteWorkspaceId?: string | null;
}): boolean {
  const tag = String(account.subscriptionTag || '').trim();
  if (!tag) return true;
  const proof = sellerTokenFields(tag, String(account.accessToken || ''));
  if (!proof.ok) return false;
  if (!isTeamSellerTag(tag)) return true;
  return String(account.remoteWorkspaceId || '').trim() === proof.remoteWorkspaceId;
}

export function credentialMatchesSellerTag(
  account: { subscriptionTag?: string | null; remoteWorkspaceId?: string | null },
  accessToken: string,
): boolean {
  const tag = String(account.subscriptionTag || '').trim();
  if (!tag) return tokenFitsStoredWorkspace(account, accessToken);
  if (isTeamSellerTag(tag)) return teamDeliveryReady({ remoteWorkspaceId: account.remoteWorkspaceId, accessToken });
  const payload = decodeJwtPayload(accessToken);
  if (!payload || !reclaimPlanAllowed(payload)) return false;
  return tokenFitsStoredWorkspace(account, accessToken);
}

export function refreshedSellerFields(
  account: { subscriptionTag?: string | null; remoteWorkspaceId?: string | null },
  accessToken: string,
): { planType?: string; remoteWorkspaceId?: string } {
  if (!credentialMatchesSellerTag(account, accessToken)) return {};
  const tag = String(account.subscriptionTag || '').trim();
  if (!tag) return {};
  if (isTeamSellerTag(tag)) {
    return { planType: BUSINESS_PLAN, remoteWorkspaceId: String(account.remoteWorkspaceId || '').trim() };
  }
  const plan = claim(decodeJwtPayload(accessToken), 'chatgpt_plan_type');
  return plan ? { planType: plan } : {};
}

export function acceptExtractResult(
  tag: string,
  result: { ok?: boolean; accessToken?: string; refreshToken?: string; remoteWorkspaceId?: string | null },
  allowMissingPlan = false,
): { ok: boolean; code: string; message: string; temporary: boolean } {
  if (!result.ok || !result.accessToken || !result.refreshToken) {
    return { ok: false, code: 'REFRESH_MISSING', message: '没有拿到可用凭据', temporary: true };
  }
  if (isTeamSellerTag(tag)) {
    if (!teamDeliveryReady({ remoteWorkspaceId: result.remoteWorkspaceId, accessToken: result.accessToken })) {
      return { ok: false, code: 'PLAN_MISMATCH', message: '空间核对失败，未保存个人文件', temporary: false };
    }
    return { ok: true, code: 'OK', message: '提取完成', temporary: false };
  }
  const claims = decodeJwtPayload(result.accessToken);
  if (!(allowMissingPlan ? reclaimPlanAllowed(claims) : personalPlanAllowed(claims))) {
    return { ok: false, code: 'PLAN_MISMATCH', message: '个人订阅核对失败', temporary: false };
  }
  return { ok: true, code: 'OK', message: '提取完成', temporary: false };
}

const PERMANENT_CODES = new Set([
  'invalid_username_or_password',
  'mfa_totp_secret_required',
  'mfa_totp_factor_not_available',
  'mfa_totp_code_unavailable',
  'mfa_primary_factor_required',
  'PERSONAL_TOKEN',
  'PLAN_MISMATCH',
  'WORKSPACE_MISSING',
  'WORKSPACE_AMBIGUOUS',
  'NO_PROXY',
  'BAD_PROXY',
  'PHONE',
  'DEACTIVATED',
  'BANNED',
]);

export function classifyLoginFailure(code: string, message: string): { code: string; temporary: boolean } {
  const rawCode = String(code || '').trim();
  const text = `${rawCode} ${message || ''}`.toLowerCase();
  if (text.includes('429') || text.includes('rate_limit')) {
    return { code: rawCode || 'RETRY', temporary: true };
  }
  if (PERMANENT_CODES.has(rawCode) || /invalid_username_or_password|mfa_totp_|personal_token|plan_mismatch|workspace_missing|workspace_ambiguous/.test(text)) {
    return { code: rawCode || 'FAILED', temporary: false };
  }
  if (/密码错误|密码不正确|邮箱或密码|用户名或密码|2fa 动态码未通过|没有可用的 socks|只接受 socks|手机号|已停用|已封禁|多个 5x|没有可用的 5x|空间核对失败|个人 token|deactivated|banned/.test(text)) {
    return { code: rawCode || 'FAILED', temporary: false };
  }
  if (/email_verification|email_otp|rate_limit|429|timeout|cloudflare|worker_disabled|interrupted|aborted|refresh_missing|token 交换失败|没有拿到 refresh_token/.test(text)) {
    return { code: rawCode || 'RETRY', temporary: true };
  }
  return { code: rawCode || 'RETRY', temporary: true };
}

export function isPasswordFailure(code: string, message: string): boolean {
  const text = `${code || ''} ${message || ''}`.toLowerCase();
  return text.includes('invalid_username_or_password')
    || text.includes('密码错误')
    || text.includes('密码不正确')
    || text.includes('邮箱或密码')
    || text.includes('用户名或密码');
}

export function redactMessage(message: string, secrets: string[] = []): string {
  let text = String(message || '');
  for (const secret of secrets) {
    if (secret && secret.length >= 4) text = text.split(secret).join('***');
  }
  return text.replace(/socks5h?:\/\/\S+/gi, 'socks5://***').slice(0, 180);
}

export function stripSecrets<T extends Record<string, unknown>>(value: T): T {
  const copy = { ...value };
  for (const key of Object.keys(copy)) {
    if (SECRET_KEYS.has(key) || /password|proxy|totp|secret/i.test(key)) delete copy[key];
  }
  return copy;
}

export function countLoginLines(content: string): number {
  return String(content || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#')).length;
}

export function looksLikeLoginImport(content: string): boolean {
  return String(content || '').includes('----');
}

export function parseLoginImport(content: string): { lines: Array<{ email: string; password: string; totp: string }>; errors: string[] } {
  const parsed = parseTeamLines(content);
  return {
    lines: parsed.lines.map((line) => ({ email: line.email, password: line.password, totp: line.totp })),
    errors: parsed.errors.map((item) => item.replace(/：.+$/, '：格式不符')),
  };
}

const misses = new Map<string, number[]>();
const MISS_WINDOW_MS = 10 * 60 * 1000;
const MISS_LIMIT = 5;

export function credentialMissAllowed(ip: string | undefined, now = Date.now()): boolean {
  const key = ip || 'unknown';
  const recent = (misses.get(key) || []).filter((at) => now - at < MISS_WINDOW_MS);
  misses.set(key, recent);
  return recent.length < MISS_LIMIT;
}

export function noteCredentialMiss(ip: string | undefined, now = Date.now()): void {
  const key = ip || 'unknown';
  const recent = (misses.get(key) || []).filter((at) => now - at < MISS_WINDOW_MS);
  recent.push(now);
  misses.set(key, recent);
}

export function resetCredentialMisses(): void {
  misses.clear();
}

const LOGIN_COOLDOWN_MS = 30 * 60 * 1000;

/** 会话结束不是 invalid_grant，不能当成凭据作废。 */
export function refreshSessionEnded(code: string, description = ''): boolean {
  const text = `${code || ''} ${description || ''}`.toLowerCase();
  return text.includes('refresh_token_invalidated')
    || text.includes('session has ended')
    || text.includes('please log in again');
}

/** 只认 token 声明里的邮箱，不认协议响应回显。 */
export function emailFromToken(token: string | null | undefined): string | null {
  const payload = decodeJwtPayload(String(token || ''));
  if (!payload) return null;
  const direct = typeof payload.email === 'string' ? payload.email.trim() : '';
  if (direct.includes('@')) return direct.toLowerCase();
  for (const key of ['https://api.openai.com/profile', 'https://api.openai.com/auth']) {
    const nested = payload[key];
    if (!nested || typeof nested !== 'object' || Array.isArray(nested)) continue;
    const email = (nested as Record<string, unknown>).email;
    if (typeof email === 'string' && email.includes('@')) return email.trim().toLowerCase();
  }
  return null;
}

export function tokenEmail(accessToken?: string | null, idToken?: string | null): string | null {
  return emailFromToken(accessToken) || emailFromToken(idToken);
}

export function loginFailureCooling(createdAt: Date, now = Date.now()): boolean {
  return now - createdAt.getTime() < LOGIN_COOLDOWN_MS;
}

export function isPasswordOrTotpFailure(code: string, message: string): boolean {
  if (isPasswordFailure(code, message)) return true;
  const text = `${code || ''} ${message || ''}`.toLowerCase();
  return /mfa_totp|动态码未通过|2fa 动态码/.test(text);
}

/** 代理或出口失败才换下一个代理。密码和 2FA 失败不算。 */
export function isProxyOrEgressFailure(code: string, message: string): boolean {
  if (isPasswordOrTotpFailure(code, message)) return false;
  const text = `${code || ''} ${message || ''}`.toLowerCase();
  return /bad_proxy|no_proxy|\bproxy\b|socks|egress|出口|代理|cloudflare|econnrefused|connection refused|tunnel failed/.test(text);
}

export async function loadStoredLogin(
  prisma: { extractJob: { findFirst(args: unknown): Promise<{ passwordCipher: string; totpCipher: string; proxyCipher: string } | null> } },
  accountId: number,
): Promise<{ password: string; totp: string; proxy: string } | null> {
  const job = await prisma.extractJob.findFirst({
    where: { accountId, status: 'succeeded' },
    orderBy: { id: 'desc' },
  });
  if (!job) return null;
  try {
    return {
      password: decryptSecret(job.passwordCipher),
      totp: decryptSecret(job.totpCipher),
      proxy: decryptSecret(job.proxyCipher),
    };
  } catch {
    return null;
  }
}
