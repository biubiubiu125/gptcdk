import { workerPost, type WorkerResponse } from '../team/team-worker';
import { acceptExtractResult, classifyLoginFailure, stripSecrets } from '../common/subscription';

export interface AccountExtractRequest {
  email: string;
  password: string;
  totp: string;
  proxy: string;
  subscriptionTag: string;
  workspaceId?: string | null;
  mailboxAccountId?: number;
  otpPolicy?: 'reclaim';
}

export interface AccountExtractResult {
  ok: boolean;
  temporary: boolean;
  code: string;
  message: string;
  accessToken?: string;
  refreshToken?: string;
  idToken?: string;
  accountId?: string;
  userId?: string;
  planType?: string;
  remoteWorkspaceId?: string;
  email?: string;
}

export type AccountExtractClient = (input: AccountExtractRequest, signal?: AbortSignal) => Promise<AccountExtractResult>;

export function normalizeExtractResult(
  tag: string,
  parsed: WorkerResponse,
  options: { allowMissingPlan?: boolean } = {},
): AccountExtractResult {
  const cleaned = stripSecrets(parsed as unknown as Record<string, unknown>);
  const code = String(cleaned.code || (cleaned.ok ? 'OK' : 'UPSTREAM'));
  const message = String(cleaned.message || (cleaned.ok ? '提取完成' : '提取失败')).slice(0, 180);
  if (!cleaned.ok) {
    const failure = classifyLoginFailure(code, message);
    return {
      ok: false,
      temporary: typeof cleaned.temporary === 'boolean' ? cleaned.temporary : failure.temporary,
      code,
      message,
    };
  }
  const accepted = acceptExtractResult(tag, {
    ok: true,
    accessToken: typeof cleaned.accessToken === 'string' ? cleaned.accessToken : undefined,
    refreshToken: typeof cleaned.refreshToken === 'string' ? cleaned.refreshToken : undefined,
    remoteWorkspaceId: typeof cleaned.remoteWorkspaceId === 'string' ? cleaned.remoteWorkspaceId : undefined,
  }, options.allowMissingPlan === true);
  if (!accepted.ok) return { ok: false, temporary: accepted.temporary, code: accepted.code, message: accepted.message };
  return {
    ok: true,
    temporary: false,
    code: 'OK',
    message: '提取完成',
    accessToken: String(cleaned.accessToken),
    refreshToken: String(cleaned.refreshToken),
    idToken: typeof cleaned.idToken === 'string' ? cleaned.idToken : undefined,
    accountId: typeof cleaned.accountId === 'string' ? cleaned.accountId : undefined,
    userId: typeof cleaned.userId === 'string' ? cleaned.userId : undefined,
    planType: typeof cleaned.planType === 'string' ? cleaned.planType : undefined,
    remoteWorkspaceId: typeof cleaned.remoteWorkspaceId === 'string' ? cleaned.remoteWorkspaceId : undefined,
    email: typeof cleaned.email === 'string' ? cleaned.email : undefined,
  };
}

export async function postAccountExtract(input: AccountExtractRequest, signal?: AbortSignal): Promise<AccountExtractResult> {
  try {
    const parsed = await workerPost('/internal/account/extract', {
      email: input.email,
      password: input.password,
      totp: input.totp,
      proxy: input.proxy,
      subscriptionTag: input.subscriptionTag,
      workspaceId: input.workspaceId || undefined,
      ...(input.mailboxAccountId ? { mailboxAccountId: input.mailboxAccountId } : {}),
      ...(input.otpPolicy ? { otpPolicy: input.otpPolicy } : {}),
    }, signal);
    return normalizeExtractResult(input.subscriptionTag, parsed, {
      allowMissingPlan: input.otpPolicy === 'reclaim',
    });
  } catch (error) {
    const aborted = error instanceof Error && error.name === 'AbortError';
    return {
      ok: false,
      temporary: true,
      code: aborted ? 'ABORTED' : 'WORKER_UNREACHABLE',
      message: aborted ? '提取已中断' : '协议服务暂时不可用',
    };
  }
}
