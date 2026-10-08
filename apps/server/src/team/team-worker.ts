export interface WorkerResponse {
  ok: boolean;
  code?: string;
  message?: string;
  email?: string;
  workspaces?: Array<{ id: string; name?: string; role?: string; planType?: string; deactivated?: boolean }>;
  members?: Array<{ id: string; email: string; role: string; seatType?: string }>;
  invites?: Array<{ email: string }>;
  invitesTruncated?: boolean;
  total?: number | null;
  complete?: boolean;
  seatsEntitled?: number | null;
  seatsInUse?: number | null;
  successes?: string[];
  errored?: string[];
  seatFull?: boolean;
  stopped?: boolean;
  inviteSent?: boolean;
  accessToken?: string;
  refreshToken?: string;
  idToken?: string;
  accountId?: string;
  userId?: string;
  planType?: string;
  expiresAt?: string;
  raw?: Record<string, unknown>;
  pct5h?: number | null;
  pct7d?: number | null;
  reset5h?: number | null;
  reset7d?: number | null;
  limitReached?: boolean | null;
  allowed?: boolean | null;
  usageStatus?: string;
  httpStatus?: number;
  temporary?: boolean;
  rateLimited?: boolean;
  willRenew?: boolean | null;
  activeUntil?: string | null;
  subscriptionRead?: boolean;
  premiumKnown?: boolean;
  sessionUpdate?: {
    accessToken?: string;
    sessionToken?: string;
    deviceId?: string;
    cookies?: Array<{ name?: string; value?: string; domain?: string }>;
  };
}

export function workerConfigured(): boolean {
  return Boolean((process.env.PROTOCOL_WORKER_URL || '').trim() && (process.env.PROTOCOL_WORKER_TOKEN || '').trim());
}

export async function workerPost(path: string, body: unknown): Promise<WorkerResponse> {
  const base = (process.env.PROTOCOL_WORKER_URL || '').trim();
  const token = (process.env.PROTOCOL_WORKER_TOKEN || '').trim();
  if (!base || !token) {
    return { ok: false, code: 'WORKER_DISABLED', message: '协议服务未配置，Team 操作已停用' };
  }
  const response = await fetch(new URL(path, base.endsWith('/') ? base : `${base}/`), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let parsed: WorkerResponse = { ok: false, message: '协议服务没有返回 JSON' };
  try {
    parsed = text ? JSON.parse(text) as WorkerResponse : { ok: false, message: '协议服务返回空响应' };
  } catch {
    parsed = { ok: false, code: 'WORKER_BAD_RESPONSE', message: '协议服务返回的不是 JSON' };
  }
  if (!response.ok && parsed.ok !== false) {
    return { ...parsed, ok: false, message: parsed.message || '协议服务调用失败' };
  }
  return parsed;
}
