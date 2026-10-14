import { generateCardKey, bizError } from '../common/utils';
import { expiresAtFromJwt } from '../common/jwt-expiry';
import {
  IMPORT_LINE_CAP,
  acceptExtractResult,
  classifyLoginFailure,
  countLoginLines,
  nextExtractRetry,
  parseLoginImport,
  redactMessage,
} from '../common/subscription';
import { encryptSecret, teamSecretReady } from '../common/secret-box';
import { normalizeSocks } from '../common/socks';
import type { AccountExtractClient, AccountExtractResult } from './extract-client';
import { withExtractEmailLock } from '../public/reclaim-lock';

export interface ExtractHost {
  prisma: any;
  extractClient: AccountExtractClient;
  logger: { warn(message: string): void };
  extractPumping: boolean;
  extractTimer?: NodeJS.Timeout;
}

type LoginLine = { email: string; password: string; totp: string };

function lineError(index: number, reason: string) {
  return { index, name: `第${index}行`, reason };
}

async function extractBlocked(host: ExtractHost, email: string, exceptJobId?: number): Promise<string | null> {
  const account = await host.prisma.account.findFirst({
    where: { email: { equals: email, mode: 'insensitive' } },
    select: { id: true },
  });
  if (account) return '邮箱已在库或提取队列中';
  const active = await host.prisma.extractJob.findFirst({
    where: {
      email: { equals: email, mode: 'insensitive' },
      status: { in: ['queued', 'running', 'retrying', 'succeeded'] },
      ...(exceptJobId ? { NOT: { id: exceptJobId } } : {}),
    },
    select: { id: true },
  });
  if (active) return '邮箱已在库或提取队列中';
  const passwordFailure = await host.prisma.extractJob.findFirst({
    where: {
      email: { equals: email, mode: 'insensitive' },
      status: 'failed',
      ...(exceptJobId ? { NOT: { id: exceptJobId } } : {}),
      OR: passwordOrTotpJobWhere(),
    },
    select: { id: true },
  });
  if (passwordFailure) return '该邮箱密码登录已失败，不能再次提取';
  return null;
}

function passwordOrTotpJobWhere() {
  const phrases = [
    'invalid_username_or_password',
    '密码错误',
    '密码不正确',
    '邮箱或密码',
    '用户名或密码',
    'mfa_totp',
    '动态码未通过',
    '2fa 动态码',
  ];
  return phrases.flatMap((phrase) => ([
    { code: { contains: phrase, mode: 'insensitive' as const } },
    { message: { contains: phrase, mode: 'insensitive' as const } },
  ]));
}

const STOCKED_BATCH = 'stocked';
const STOCKED_CODE = 'STOCKED';

export async function ensureStockedEmail(
  prisma: { extractJob: { findFirst(args: unknown): Promise<{ id: number } | null>; create(args: unknown): Promise<unknown> } },
  email: string | null | undefined,
): Promise<void> {
  const normalized = String(email || '').trim();
  if (!normalized) return;
  const existing = await prisma.extractJob.findFirst({
    where: {
      email: { equals: normalized, mode: 'insensitive' },
      status: 'succeeded',
    },
    select: { id: true },
  });
  if (existing) return;
  await prisma.extractJob.create({
    data: {
      batchId: STOCKED_BATCH,
      email: normalized,
      subscriptionTag: '',
      passwordCipher: 'stocked',
      totpCipher: 'stocked',
      proxyCipher: 'stocked',
      status: 'succeeded',
      failureClass: 'permanent',
      code: STOCKED_CODE,
      message: 'JSON 已入库，不能再次密码登录',
      attempt: 0,
    },
  });
}

export async function enqueueLoginImport(
  host: ExtractHost,
  content: string,
  options: {
    subscriptionTag: string;
    proxy?: string;
    rememberProxy?: boolean;
    useRememberedProxy?: boolean;
    prefix: string;
    keyGroups: number;
    keyLength: number;
    source: string;
    remark?: string;
  },
) {
  const parsed = parseLoginImport(content);
  const total = countLoginLines(content);
  if (total > IMPORT_LINE_CAP) bizError('BAD_INPUT', `单次最多提交 ${IMPORT_LINE_CAP} 行账密`);
  if (!teamSecretReady()) bizError('BAD_INPUT', 'GPTCDK_SECRET 缺失或短于 32 字符，Team 功能已停用');
  const errors = parsed.errors.map((reason, index) => lineError(index + 1, reason));
  if (!parsed.lines.length) {
    return emptyImport(errors.length ? errors : [lineError(1, '没有可提取的账密行')]);
  }
  const proxy = await resolveImportProxy(host, options.proxy, options.useRememberedProxy);
  if (options.rememberProxy) await rememberExtractProxy(host, proxy);
  const seen = new Set<string>();
  const accepted: LoginLine[] = [];
  for (const line of parsed.lines) {
    const email = line.email.toLowerCase();
    if (seen.has(email)) {
      errors.push(lineError(accepted.length + errors.length + 1, '同一批里邮箱重复'));
      continue;
    }
    seen.add(email);
    const blocked = await extractBlocked(host, email);
    if (blocked) {
      errors.push(lineError(accepted.length + errors.length + 1, blocked));
      continue;
    }
    accepted.push(line);
  }
  if (!accepted.length) return emptyImport(errors);
  const batchId = `b_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  await host.prisma.batch.create({
    data: {
      batchId,
      credits: 0,
      count: 0,
      remark: options.remark?.trim() || null,
      source: options.source,
      subscriptionTag: options.subscriptionTag,
    },
  });
  const jobs = [];
  for (const line of accepted) {
    const job = await host.prisma.extractJob.create({
      data: {
        batchId,
        email: line.email,
        subscriptionTag: options.subscriptionTag,
        passwordCipher: encryptSecret(line.password),
        totpCipher: encryptSecret(line.totp),
        proxyCipher: encryptSecret(proxy),
        status: 'queued',
        keyPrefix: options.prefix,
        keyGroups: options.keyGroups,
        keyLength: options.keyLength,
      },
      select: { id: true, email: true, status: true },
    });
    jobs.push(job);
  }
  return {
    batchId,
    imported: 0,
    skipped: 0,
    failed: errors.length,
    cards: [],
    credits: 0,
    pending: 0,
    queued: jobs.length,
    jobs,
    errors,
    samples: [],
  };
}

function emptyImport(errors: Array<{ index: number; name: string; reason: string }>) {
  return {
    batchId: '',
    imported: 0,
    skipped: 0,
    failed: errors.length,
    cards: [],
    credits: 0,
    pending: 0,
    queued: 0,
    jobs: [],
    errors,
    samples: [],
  };
}

async function resolveImportProxy(host: ExtractHost, raw: string | undefined, useRemembered?: boolean): Promise<string> {
  let value = String(raw || '').trim();
  if (!value && useRemembered) value = await readRememberedProxy(host);
  if (!value) bizError('BAD_INPUT', '没有可用的 SOCKS 代理');
  try {
    return normalizeSocks(value);
  } catch (error) {
    bizError('BAD_INPUT', error instanceof Error ? error.message : '没有可用的 SOCKS 代理');
  }
}

async function readRememberedProxy(host: ExtractHost): Promise<string> {
  const row = await host.prisma.setting.findUnique({ where: { key: 'extractSocksProxy' } });
  if (!row?.value) return '';
  const { decryptSecret } = await import('../common/secret-box');
  try {
    return decryptSecret(row.value);
  } catch {
    return '';
  }
}

async function rememberExtractProxy(host: ExtractHost, proxy: string): Promise<void> {
  await host.prisma.setting.upsert({
    where: { key: 'extractSocksProxy' },
    create: { key: 'extractSocksProxy', value: encryptSecret(proxy) },
    update: { value: encryptSecret(proxy) },
  });
}

export async function rememberedProxyReady(host: ExtractHost): Promise<boolean> {
  const row = await host.prisma.setting.findUnique({ where: { key: 'extractSocksProxy' } });
  return Boolean(row?.value);
}

export async function listExtractJobs(host: ExtractHost, batchId?: string) {
  const items = await host.prisma.extractJob.findMany({
    where: {
      NOT: { code: STOCKED_CODE },
      ...(batchId ? { batchId } : {}),
    },
    orderBy: { id: 'desc' },
    take: 100,
    select: {
      id: true,
      batchId: true,
      email: true,
      subscriptionTag: true,
      status: true,
      failureClass: true,
      code: true,
      message: true,
      attempt: true,
      nextRetryAt: true,
      accountId: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  return { items };
}

export async function stopExtractJob(host: ExtractHost, id: number) {
  const job = await host.prisma.extractJob.findUnique({ where: { id } });
  if (!job) bizError('NOT_FOUND', '提取任务不存在', 404);
  if (job.status === 'succeeded') bizError('BAD_INPUT', '已完成的任务不能停止');
  await host.prisma.extractJob.update({
    where: { id },
    data: { status: 'stopped', failureClass: 'permanent', nextRetryAt: null, message: '管理员已停止' },
  });
  return { ok: true };
}

export async function recoverInterruptedExtracts(host: ExtractHost): Promise<void> {
  if (process.env.NODE_ENV === 'test') return;
  await host.prisma.extractJob.updateMany({
    where: { status: 'running' },
    data: {
      status: 'retrying',
      failureClass: 'temporary',
      code: 'INTERRUPTED',
      message: '服务重启，继续重试',
      nextRetryAt: new Date(),
    },
  });
}

export function startExtractPump(host: ExtractHost): void {
  if (process.env.NODE_ENV === 'test' || host.extractTimer) return;
  host.extractTimer = setInterval(() => {
    void pumpExtractQueue(host).catch((error) => host.logger.warn(`提取队列异常：${error instanceof Error ? error.name : 'Error'}`));
  }, 5000);
  host.extractTimer.unref?.();
}

export function stopExtractPump(host: ExtractHost): void {
  if (host.extractTimer) clearInterval(host.extractTimer);
  host.extractTimer = undefined;
}

export async function pumpExtractQueue(host: ExtractHost): Promise<void> {
  if (host.extractPumping) return;
  host.extractPumping = true;
  try {
    const running = await host.prisma.extractJob.count({ where: { status: 'running' } });
    const slots = Math.max(0, 2 - running);
    if (!slots) return;
    const due = await host.prisma.extractJob.findMany({
      where: {
        status: { in: ['queued', 'retrying'] },
        OR: [{ nextRetryAt: null }, { nextRetryAt: { lte: new Date() } }],
      },
      orderBy: { id: 'asc' },
      take: slots,
    });
    for (const job of due) {
      const claimed = await host.prisma.extractJob.updateMany({
        where: { id: job.id, status: { in: ['queued', 'retrying'] } },
        data: { status: 'running', nextRetryAt: null },
      });
      if (claimed.count !== 1) continue;
      void runExtractJob(host, job.id);
    }
  } finally {
    host.extractPumping = false;
  }
}

export async function runExtractJob(host: ExtractHost, id: number): Promise<void> {
  const job = await host.prisma.extractJob.findUnique({ where: { id } });
  if (!job || job.status === 'stopped' || job.status === 'succeeded' || job.status === 'failed') return;
  await withExtractEmailLock(host.prisma, job.email, () => runExtractJobLocked(host, job));
}

async function runExtractJobLocked(host: ExtractHost, job: any): Promise<void> {
  const current = await host.prisma.extractJob.findUnique({ where: { id: job.id }, select: { status: true } });
  if (!current || current.status === 'stopped' || current.status === 'succeeded' || current.status === 'failed') return;
  const blocked = await extractBlocked(host, job.email, job.id);
  if (blocked) {
    await host.prisma.extractJob.updateMany({
      where: { id: job.id, status: { not: 'stopped' } },
      data: { status: 'failed', failureClass: 'permanent', code: 'DUPLICATE', message: blocked, nextRetryAt: null },
    });
    return;
  }
  const id = job.id;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120000);
  const watch = setInterval(() => {
    void host.prisma.extractJob.findUnique({ where: { id }, select: { status: true } }).then((current: { status?: string } | null) => {
      if (!current || current.status === 'stopped') controller.abort();
    }).catch(() => undefined);
  }, 1000);
  let password = '';
  let totp = '';
  let proxy = '';
  try {
    const { decryptSecret } = await import('../common/secret-box');
    password = decryptSecret(job.passwordCipher);
    totp = decryptSecret(job.totpCipher);
    proxy = decryptSecret(job.proxyCipher);
    const result = await host.extractClient({
      email: job.email,
      password,
      totp,
      proxy,
      subscriptionTag: job.subscriptionTag,
    }, controller.signal);
    const latest = await host.prisma.extractJob.findUnique({ where: { id }, select: { status: true } });
    if (!latest || latest.status === 'stopped') return;
    if (!result.ok) {
      await finishFailure(host, job, result, [password, totp, proxy]);
      return;
    }
    const accepted = acceptExtractResult(job.subscriptionTag, result);
    if (!accepted.ok) {
      await finishFailure(host, job, { ...result, ok: false, ...accepted }, [password, totp, proxy]);
      return;
    }
    await saveExtractedAccount(host, job, result, password, totp);
  } catch (error) {
    host.logger.warn(`提取失败：${error instanceof Error ? error.name : 'Error'}`);
    const latest = await host.prisma.extractJob.findUnique({ where: { id }, select: { status: true } });
    if (latest && latest.status !== 'stopped') {
      await finishFailure(host, job, { ok: false, temporary: true, code: 'UPSTREAM', message: '提取暂时失败' }, [password, totp, proxy]);
    }
  } finally {
    clearTimeout(timer);
    clearInterval(watch);
  }
}

async function finishFailure(
  host: ExtractHost,
  job: { id: number; attempt: number },
  result: AccountExtractResult,
  secrets: string[],
): Promise<void> {
  const current = await host.prisma.extractJob.findUnique({ where: { id: job.id }, select: { status: true } });
  if (!current || current.status === 'stopped') return;
  const judged = classifyLoginFailure(result.code, result.message);
  const temporary = result.temporary !== false && judged.temporary;
  const message = redactMessage(result.message, secrets);
  if (!temporary) {
    await host.prisma.extractJob.update({
      where: { id: job.id },
      data: {
        status: 'failed',
        failureClass: 'permanent',
        code: result.code || 'FAILED',
        message,
        nextRetryAt: null,
        attempt: { increment: 1 },
      },
    });
    return;
  }
  const attempt = job.attempt + 1;
  await host.prisma.extractJob.update({
    where: { id: job.id },
    data: {
      status: 'retrying',
      failureClass: 'temporary',
      code: result.code || 'RETRY',
      message,
      attempt,
      nextRetryAt: nextExtractRetry(attempt),
    },
  });
}

async function saveExtractedAccount(
  host: ExtractHost,
  job: any,
  result: AccountExtractResult,
  password: string,
  totp: string,
): Promise<void> {
  const raw = {
    type: 'codex',
    email: job.email,
    access_token: result.accessToken,
    refresh_token: result.refreshToken,
    id_token: result.idToken,
    account_id: result.accountId || result.remoteWorkspaceId,
    notes: JSON.stringify({ gpt: { password }, two_factor: { secret: totp } }),
  };
  await host.prisma.$transaction(async (tx: any) => {
    const duplicate = await tx.account.findFirst({
      where: { email: { equals: job.email, mode: 'insensitive' } },
      select: { id: true },
    });
    if (duplicate) {
      await tx.extractJob.update({
        where: { id: job.id },
        data: { status: 'failed', failureClass: 'permanent', code: 'DUPLICATE', message: '邮箱已存在', nextRetryAt: null },
      });
      return;
    }
    const cardKey = await uniqueCardKey(tx, job.keyPrefix || 'CARD', job.keyGroups || 3, job.keyLength || 5);
    const batch = job.batchId
      ? await tx.batch.findUnique({ where: { batchId: job.batchId }, select: { remark: true } })
      : null;
    const created = await tx.account.create({
      data: {
        name: job.email,
        email: job.email,
        credits: 0,
        subscriptionTag: job.subscriptionTag,
        remark: batch?.remark?.trim() || null,
        remoteWorkspaceId: result.remoteWorkspaceId || null,
        planType: result.planType || null,
        accountId: result.accountId || result.remoteWorkspaceId || null,
        userId: result.userId || null,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        idToken: result.idToken || null,
        expiresAt: expiresAtFromJwt(result.accessToken || '') || null,
        rawSource: 'sub2api',
        rawJson: JSON.stringify(raw),
        cardKey,
        batchId: job.batchId,
        stockKind: 'standard',
        banStatus: 'unknown',
      },
    });
    await tx.extractJob.update({
      where: { id: job.id },
      data: { status: 'succeeded', accountId: created.id, failureClass: null, code: 'OK', message: '提取完成', nextRetryAt: null },
    });
    await tx.batch.update({ where: { batchId: job.batchId }, data: { count: { increment: 1 } } });
  });
}

async function uniqueCardKey(tx: any, prefix: string, groups: number, length: number): Promise<string> {
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const candidate = generateCardKey(prefix, groups, length);
    const exists = await tx.account.findUnique({ where: { cardKey: candidate }, select: { id: true } });
    if (!exists) return candidate;
  }
  return `${generateCardKey(prefix, groups, length)}-${Date.now().toString(36).toUpperCase()}`;
}
