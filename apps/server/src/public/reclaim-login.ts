import type { AccountExtractClient, AccountExtractResult } from '../accounts/extract-client';
import { expiresAtFromJwt } from '../common/jwt-expiry';
import { decryptSecret, teamSecretReady } from '../common/secret-box';
import { normalizeSocks } from '../common/socks';
import {
  credentialMatchesSellerTag,
  isPasswordOrTotpFailure,
  isProxyOrEgressFailure,
  isTeamSellerTag,
  loadStoredLogin,
  loginFailureCooling,
  refreshedSellerFields,
  tokenEmail,
} from '../common/subscription';
import type { NormalizedAccount } from '../convert/convert.types';
import type { MailboxCredential } from '../mailbox/mailbox.types';
import type { PrismaService } from '../prisma/prisma.service';
import { normalizeTotpSecret } from '../team/team-rules';

export const LOGIN_TIMEOUT_MS = 360_000;
export const LOGIN_TOTAL_BUDGET_MS = 720_000;
export const GATEWAY_READ_TIMEOUT_MS = 780_000;
export const GATEWAY_WRITE_MARGIN_MS = 60_000;
const LOGIN_MIN_ATTEMPT_MS = 30_000;
/** 软超时后继续读响应。两次尝试加上这段仍低于网关 780 秒。 */
export const LOGIN_RESPONSE_GRACE_MS = 15_000;
const reclaimMailboxUntil = new Map<number, number>();

/** 登录调用邮箱回调期间才放行。没有进行中的找回时，即使持有协议令牌也不返回验证码。 */
export function allowReclaimMailbox(accountId: number, now = Date.now()): void {
  const id = Number(accountId);
  if (!Number.isInteger(id) || id <= 0) return;
  reclaimMailboxUntil.set(id, now + LOGIN_TIMEOUT_MS + 30_000);
}

export function releaseReclaimMailbox(accountId: number): void {
  reclaimMailboxUntil.delete(Number(accountId));
}

export function reclaimMailboxAllowed(accountId: number, now = Date.now()): boolean {
  const id = Number(accountId);
  const until = reclaimMailboxUntil.get(id);
  if (!until || until <= now) {
    reclaimMailboxUntil.delete(id);
    return false;
  }
  return true;
}

/** 两次登录合计不超过网关 780 秒。剩余不足一次最短尝试就不再开始。 */
export function loginAttemptBudget(startedAt: number, now = Date.now()): number {
  const remaining = LOGIN_TOTAL_BUDGET_MS - (now - startedAt);
  if (remaining < LOGIN_MIN_ATTEMPT_MS) return 0;
  return Math.min(LOGIN_TIMEOUT_MS, remaining);
}

/** 整次请求的登录窗口。网关 780 秒减去 60 秒写库，剩余不足最短尝试就不再开始。 */
export function gatewayLoginBudget(requestStartedAt: number, now = Date.now()): number {
  const remaining = GATEWAY_READ_TIMEOUT_MS - GATEWAY_WRITE_MARGIN_MS - (now - requestStartedAt);
  if (remaining < LOGIN_MIN_ATTEMPT_MS) return 0;
  return Math.min(LOGIN_TIMEOUT_MS, remaining);
}
export const LOGIN_OK_MESSAGE = '已重新登录原卡密账号';
export const HELD_LOGIN_MESSAGE = '凭据已重新登录过，本次没有再次登录';
export const LOGIN_FAILED_MESSAGE = '重新登录失败，请联系管理员';
export const LOGIN_TEMPORARY_MESSAGE = '重新登录暂时失败，请稍后重试';
export const LOGIN_INTERRUPTED_MESSAGE = '找回已中断，请稍后重试';
export const LOGIN_UNAUTHORIZED_MESSAGE = '协议服务未授权，请联系管理员';
export const LOGIN_MAILBOX_MESSAGE = '重新登录需要邮箱验证，但没有可用邮箱，请联系管理员';
export const LOGIN_PHONE_MESSAGE = '该账号需要手机验证，请联系管理员';
export const LOGIN_BANNED_MESSAGE = '该账号已停用或封禁，请联系管理员';
export const LOGIN_OTP_MESSAGE = '没有等到邮箱验证码，请稍后重试';
export const LOGIN_PROXY_MESSAGE = '代理连接失败，请稍后重试';
export const LOGIN_BUDGET_MESSAGE = '本次请求时间不足，请稍后单独找回';
export const LOGIN_MATERIALS_MESSAGE = '重新登录缺少可用密码或代理，请联系管理员';
export const MISSING_WORKSPACE_MESSAGE = '该账号缺少原空间编号，已保留原文件。请联系管理员';
export const SPACE_MISMATCH_MESSAGE = '新凭据与原空间不一致，已保留原文件。请联系管理员';

const COOLING_CODES = ['LOGIN_FAILED', 'LOGIN_MISMATCH'];

export type ReclaimCredentialWrite = {
  id: number;
  accessToken: string;
  refreshToken: string;
  previousRefreshToken: string | null;
  idToken: string | null;
  expiresAt: Date | null;
  planType?: string | null;
  remoteWorkspaceId?: string | null;
};

export type LoginAttempt =
  | { status: 'skip'; reason: 'materials' | 'worker' }
  | { status: 'failed'; code: string; message: string; logCode?: string }
  | { status: 'wrote'; write: ReclaimCredentialWrite };

type LoginAccount = {
  id: number;
  email?: string | null;
  refreshToken?: string | null;
  idToken?: string | null;
  subscriptionTag?: string | null;
  remoteWorkspaceId?: string | null;
  teamSecret?: { passwordCipher: string; totpCipher: string } | null;
};

type LoginMaterials = { password: string; totp: string; proxy: string };

export interface ReclaimLoginHost {
  prisma: PrismaService;
  convert: { readChatGptLogin(account: NormalizedAccount): { password?: string; twoFactorSecret?: string } };
  mailbox: { isComplete(credential: MailboxCredential | null): boolean };
  extractClient: AccountExtractClient;
  toNormalized(account: unknown): NormalizedAccount;
  credentialOf(account: unknown): MailboxCredential | null;
}

function failed(code: string, message: string, logCode?: string): LoginAttempt {
  return { status: 'failed', code, message, logCode };
}

function pair(password?: string | null, totp?: string | null): { password: string; totp: string } | null {
  const nextPassword = String(password || '');
  const nextTotp = String(totp || '');
  if (!nextPassword || !nextTotp) return null;
  try {
    return { password: nextPassword, totp: normalizeTotpSecret(nextTotp) };
  } catch {
    return null;
  }
}

function usableSocks(value: string | null | undefined): string {
  try {
    return value ? normalizeSocks(value) : '';
  } catch {
    return '';
  }
}

function failureText(result: AccountExtractResult): string {
  return `${result.code || ''} ${result.message || ''}`.toLowerCase();
}

/**
 * 文件找回的原账号登录。材料或 SOCKS 不齐、协议第一次未配置时返回 skip，文件找回才刷新一次。
 * 5X 没有已保存空间编号时直接失败，不交给刷新。密码、邮箱验证、未授权和空间不一致都不刷新。
 */
export class ReclaimLogin {
  now: () => number = () => Date.now();

  constructor(private readonly host: ReclaimLoginHost) {}

  async readyToLogin(account: LoginAccount): Promise<boolean> {
    if (isTeamSellerTag(account.subscriptionTag) && !String(account.remoteWorkspaceId || '').trim()) return false;
    return Boolean(await this.loginMaterials(account));
  }

  async hasLoginPair(account: LoginAccount): Promise<boolean> {
    return Boolean(await this.pairedSecret(account));
  }

  async loginOriginalAccount(account: LoginAccount, shouldStop?: () => boolean, requestStartedAt = this.now()): Promise<LoginAttempt> {
    if (shouldStop?.()) return failed('REFRESH_FAILED', LOGIN_INTERRUPTED_MESSAGE);
    const cooling = await this.coolingLogin(account.id);
    if (cooling) return cooling;
    if (isTeamSellerTag(account.subscriptionTag) && !String(account.remoteWorkspaceId || '').trim()) {
      return failed('REFRESH_FAILED', MISSING_WORKSPACE_MESSAGE);
    }
    const materials = await this.loginMaterials(account);
    if (!materials) return { status: 'skip', reason: 'materials' };
    const proxies = [materials.proxy];
    const remembered = await this.rememberedSocks();
    if (remembered && remembered !== materials.proxy) proxies.push(remembered);
    const startedAt = this.now();
    for (let index = 0; index < proxies.length; index += 1) {
      const now = this.now();
      const gatewayBudget = gatewayLoginBudget(requestStartedAt, now);
      const budget = Math.min(loginAttemptBudget(startedAt, now), gatewayBudget);
      if (budget <= 0) return failed('REQUEST_BUDGET', LOGIN_BUDGET_MESSAGE);
      const result = await this.callLogin(account, materials, proxies[index], shouldStop, budget);
      if (result.code === 'WORKER_DISABLED') {
        return index === 0 ? { status: 'skip', reason: 'worker' } : failed('REFRESH_FAILED', LOGIN_TEMPORARY_MESSAGE);
      }
      if (result.ok && result.accessToken && result.refreshToken) return this.acceptLogin(account, result);
      const outcome = this.failureFrom(result);
      if (outcome.status === 'failed' && outcome.logCode === 'LOGIN_PROXY') {
        if (index < proxies.length - 1) continue;
        return failed('REFRESH_FAILED', LOGIN_PROXY_MESSAGE);
      }
      return outcome;
    }
    return failed('REFRESH_FAILED', LOGIN_PROXY_MESSAGE);
  }

  private async coolingLogin(accountId: number): Promise<LoginAttempt | null> {
    const since = new Date(Date.now() - 30 * 60 * 1000);
    const row = await this.host.prisma.redeemLog.findFirst({
      where: {
        accountId,
        message: { in: COOLING_CODES },
        format: { startsWith: 'reclaim:' },
        createdAt: { gte: since },
      },
      orderBy: { createdAt: 'desc' },
    });
    if (!row?.createdAt || !loginFailureCooling(row.createdAt)) return null;
    if (row.message === 'LOGIN_MISMATCH') {
      return failed('REFRESH_FAILED', SPACE_MISMATCH_MESSAGE, 'LOGIN_COOLING');
    }
    return failed('LOGIN_FAILED', LOGIN_FAILED_MESSAGE, 'LOGIN_COOLING');
  }

  private async pairedSecret(account: LoginAccount): Promise<{ password: string; totp: string } | null> {
    if (isTeamSellerTag(account.subscriptionTag)) {
      const team = teamPair(account);
      if (team) return team;
    }
    const notes = this.host.convert.readChatGptLogin(this.host.toNormalized(account));
    const secret = pair(notes.password, notes.twoFactorSecret);
    if (secret) return secret;
    const job = await loadStoredLogin(this.host.prisma, account.id);
    return job ? pair(job.password, job.totp) : null;
  }

  private async loginMaterials(account: LoginAccount): Promise<LoginMaterials | null> {
    const secret = await this.pairedSecret(account);
    if (!secret) return null;
    const job = await loadStoredLogin(this.host.prisma, account.id);
    const proxy = usableSocks(job?.proxy) || (await this.rememberedSocks()) || '';
    if (!proxy) return null;
    return { ...secret, proxy };
  }

  private async rememberedSocks(): Promise<string> {
    if (!teamSecretReady()) return '';
    const row = await this.host.prisma.setting.findUnique({ where: { key: 'extractSocksProxy' } });
    if (!row?.value) return '';
    try {
      return usableSocks(decryptSecret(row.value));
    } catch {
      return '';
    }
  }

  private async callLogin(
    account: LoginAccount,
    materials: LoginMaterials,
    proxy: string,
    shouldStop?: () => boolean,
    timeoutMs: number = LOGIN_TIMEOUT_MS,
    graceMs: number = LOGIN_RESPONSE_GRACE_MS,
  ): Promise<AccountExtractResult> {
    if (shouldStop?.()) return this.aborted();
    const controller = new AbortController();
    const credential = this.host.credentialOf(account);
    const mailboxAccountId = credential && this.host.mailbox.isComplete(credential) ? account.id : undefined;
    if (mailboxAccountId) allowReclaimMailbox(mailboxAccountId);
    const pending = this.host.extractClient(
      {
        email: String(account.email || ''),
        password: materials.password,
        totp: materials.totp,
        proxy,
        subscriptionTag: String(account.subscriptionTag || ''),
        workspaceId: account.remoteWorkspaceId || undefined,
        mailboxAccountId,
        otpPolicy: 'reclaim',
      },
      controller.signal,
    ).then(
      (result) => ({ settled: true as const, result }),
      (error: unknown) => ({ settled: false as const, error }),
    );
    try {
      const early = await waitFor(pending, timeoutMs);
      if (early) return unwrapLogin(early);
      const late = await waitFor(pending, graceMs);
      if (late) return unwrapLogin(late);
      controller.abort();
      const final = await pending;
      if (final.settled && final.result.accessToken && final.result.refreshToken) return final.result;
      return unwrapLogin(final);
    } finally {
      if (mailboxAccountId) releaseReclaimMailbox(mailboxAccountId);
    }
  }

  private aborted(): AccountExtractResult {
    return abortedResult();
  }

  private acceptLogin(account: LoginAccount, result: AccountExtractResult): LoginAttempt {
    const accessToken = String(result.accessToken || '');
    const refreshToken = String(result.refreshToken || '');
    const email = tokenEmail(accessToken, result.idToken);
    if (email && email.toLowerCase() !== String(account.email || '').toLowerCase()) {
      return failed('REFRESH_FAILED', SPACE_MISMATCH_MESSAGE, 'LOGIN_MISMATCH');
    }
    if (!credentialMatchesSellerTag(account, accessToken)) {
      return failed('REFRESH_FAILED', SPACE_MISMATCH_MESSAGE, 'LOGIN_MISMATCH');
    }
    const idToken = String(result.idToken || '').trim() || account.idToken || null;
    return {
      status: 'wrote',
      write: {
        id: account.id,
        accessToken,
        refreshToken,
        previousRefreshToken: account.refreshToken ?? null,
        idToken,
        expiresAt: expiresAtFromJwt(accessToken),
        ...refreshedSellerFields(account, accessToken),
      },
    };
  }

  private failureFrom(result: AccountExtractResult): LoginAttempt {
    const text = failureText(result);
    if (result.code === 'ABORTED' || text.includes('aborted') || text.includes('提取已中断') || text.includes('找回已中断')) {
      return failed('REFRESH_FAILED', LOGIN_INTERRUPTED_MESSAGE);
    }
    if (result.code === 'UNAUTHORIZED' || text.includes('未授权')) {
      return failed('REFRESH_FAILED', LOGIN_UNAUTHORIZED_MESSAGE);
    }
    if (isPasswordOrTotpFailure(result.code, result.message)) {
      return failed('LOGIN_FAILED', LOGIN_FAILED_MESSAGE, 'LOGIN_FAILED');
    }
    if (/email_otp_rejected_|email_otp_exhausted|email_otp_verification_failed|邮箱验证码被限流/.test(text)) {
      return failed('LOGIN_FAILED', LOGIN_FAILED_MESSAGE, 'LOGIN_FAILED');
    }
    if (/email_verification_required|email_otp_provider_required|没有可用邮箱|需要邮箱验证/.test(text)) {
      return failed('REFRESH_FAILED', LOGIN_MAILBOX_MESSAGE);
    }
    if (/email_otp_not_found|没有等到邮箱验证码/.test(text)) {
      return failed('REFRESH_FAILED', LOGIN_OTP_MESSAGE);
    }
    if (/plan_mismatch|workspace_missing|workspace_ambiguous|空间核对|订阅核对|原空间不一致/.test(text)) {
      return failed('REFRESH_FAILED', SPACE_MISMATCH_MESSAGE, 'LOGIN_MISMATCH');
    }
    if (/phone|手机/.test(text)) {
      return failed('REFRESH_FAILED', LOGIN_PHONE_MESSAGE, 'LOGIN_BLOCKED');
    }
    if (/deactivated|banned|已停用|已封禁/.test(text)) {
      return failed('REFRESH_FAILED', LOGIN_BANNED_MESSAGE, 'LOGIN_BLOCKED');
    }
    if (isProxyOrEgressFailure(result.code, result.message)) {
      return failed('REFRESH_FAILED', LOGIN_PROXY_MESSAGE, 'LOGIN_PROXY');
    }
    if (result.temporary === false) {
      return failed('REFRESH_FAILED', result.message || LOGIN_FAILED_MESSAGE, 'LOGIN_BLOCKED');
    }
    return failed('REFRESH_FAILED', LOGIN_TEMPORARY_MESSAGE);
  }
}

type SettledLogin =
  | { settled: true; result: AccountExtractResult }
  | { settled: false; error: unknown };

function teamPair(account: LoginAccount): { password: string; totp: string } | null {
  if (!account.teamSecret) return null;
  try {
    return pair(decryptSecret(account.teamSecret.passwordCipher), decryptSecret(account.teamSecret.totpCipher));
  } catch {
    return null;
  }
}

function abortedResult(): AccountExtractResult {
  return { ok: false, temporary: true, code: 'ABORTED', message: LOGIN_INTERRUPTED_MESSAGE };
}

function unwrapLogin(settled: SettledLogin): AccountExtractResult {
  if ('result' in settled) return settled.result;
  const error = settled.error;
  if (error instanceof Error && error.name === 'AbortError') return abortedResult();
  return { ok: false, temporary: true, code: 'WORKER_UNREACHABLE', message: '协议服务暂时不可用' };
}

function waitFor<T>(pending: Promise<T>, ms: number): Promise<T | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), Math.max(0, ms));
    timer.unref?.();
    pending.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(null);
      },
    );
  });
}
