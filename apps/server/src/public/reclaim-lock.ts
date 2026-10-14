import { Client } from 'pg';

/** 同时进行的找回次数。每张卡单独占一条连接，避免把数据库连接池打满。 */
const RECLAIM_SLOTS = 8;
let activeReclaims = 0;
const slotWaiters: Array<() => void> = [];

function acquireReclaimSlot(): Promise<void> {
  if (activeReclaims >= RECLAIM_SLOTS) {
    return new Promise((resolve) => {
      slotWaiters.push(resolve);
    });
  }
  activeReclaims += 1;
  return Promise.resolve();
}

function releaseReclaimSlot(): void {
  const next = slotWaiters.shift();
  if (next) {
    next();
    return;
  }
  activeReclaims -= 1;
}

/** Prisma 的 schema 参数不是 pg 的连接参数，交给独立连接前去掉。 */
export function postgresUrlForLock(databaseUrl: string): string {
  const url = new URL(databaseUrl);
  url.searchParams.delete('schema');
  return url.toString();
}

type SchemaReader = {
  $queryRaw<T = unknown>(query: TemplateStringsArray, ...values: unknown[]): Promise<T>;
};

async function currentSchema(prisma: SchemaReader): Promise<string> {
  const rows = await prisma.$queryRaw<Array<{ schema: string }>>`SELECT current_schema() AS schema`;
  const schema = rows[0]?.schema;
  if (!schema || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(schema)) {
    throw new Error('无法确认当前数据库 schema，账号刷新锁不可用');
  }
  return schema;
}

async function withNamedAdvisoryLocks<T>(databaseUrl: string, names: string[], fn: () => Promise<T>): Promise<T> {
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    for (const name of names) {
      await client.query('SELECT pg_advisory_lock(hashtextextended($1::text, 0))', [name]);
    }
    try {
      return await fn();
    } finally {
      for (const name of [...names].reverse()) {
        await client.query('SELECT pg_advisory_unlock(hashtextextended($1::text, 0))', [name]).catch(() => undefined);
      }
    }
  } finally {
    await client.end().catch(() => undefined);
  }
}

/**
 * 按账号 id 持有咨询锁，直到 fn 结束。
 * 后台刷新未售出账号和另一张卡领取附加账号必须用同一把锁：
 * 卡密锁只挡住同一张卡，挡不住附加账号被其他卡领走后仍去轮换提供商凭据。
 * 不占用找回连接槽，避免持卡锁的一方再等槽位时互相堵住。
 */
export async function withAccountRefreshLocks<T>(
  prisma: SchemaReader,
  accountIds: number[],
  fn: () => Promise<T>,
): Promise<T> {
  const ids = [...new Set(accountIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0))].sort((a, b) => a - b);
  if (!ids.length) return fn();
  const databaseUrl = process.env.DATABASE_URL || '';
  if (!databaseUrl) throw new Error('DATABASE_URL 缺失，账号刷新锁不可用');
  const schema = await currentSchema(prisma);
  const names = ids.map((id) => `gptcdk-account-refresh:${schema}:${id}`);
  return withNamedAdvisoryLocks(postgresUrlForLock(databaseUrl), names, fn);
}

/** 同一邮箱的提取任务串行。不占用找回连接槽。账号已入库后，等待中的任务不得再密码登录。 */
export async function withExtractEmailLock<T>(
  prisma: SchemaReader,
  email: string,
  fn: () => Promise<T>,
): Promise<T> {
  const databaseUrl = process.env.DATABASE_URL || '';
  if (!databaseUrl) throw new Error('DATABASE_URL 缺失，提取锁不可用');
  const schema = await currentSchema(prisma);
  const name = `gptcdk-extract-email:${schema}:${email.trim().toLowerCase()}`;
  return withNamedAdvisoryLocks(postgresUrlForLock(databaseUrl), [name], fn);
}

/**
 * 按「当前 schema + 卡密」持有会话级咨询锁，直到 fn 结束。
 * 刷新和写库重试都在锁内，另一张找回不能读到同一个旧凭据。
 * 连接断开时数据库会释放这把锁。
 */
/** 找回和后台刷新共用同一把卡锁，避免两边拿同一个旧刷新凭据去轮换。 */
export async function withReclaimLock<T>(
  prisma: { $queryRaw: Function },
  cardKey: string,
  fn: () => Promise<T>,
): Promise<T> {
  const databaseUrl = String(process.env.DATABASE_URL || '');
  if (!/^postgres(ql)?:\/\//i.test(databaseUrl)) throw new Error('DATABASE_URL 必须是 PostgreSQL');
  const rows = await prisma.$queryRaw`SELECT current_schema() AS schema`;
  const schema = String(rows[0]?.schema || 'public');
  return withReclaimCardLock(postgresUrlForLock(databaseUrl), `gptcdk-reclaim:${schema}:${cardKey}`, fn);
}

export async function withReclaimCardLock<T>(
  databaseUrl: string,
  lockName: string,
  fn: () => Promise<T>,
): Promise<T> {
  await acquireReclaimSlot();
  const client = new Client({ connectionString: databaseUrl });
  let connected = false;
  try {
    await client.connect();
    connected = true;
    await client.query('SELECT pg_advisory_lock(hashtextextended($1::text, 0))', [lockName]);
    try {
      return await fn();
    } finally {
      await client.query('SELECT pg_advisory_unlock(hashtextextended($1::text, 0))', [lockName]);
    }
  } finally {
    if (connected) await client.end().catch(() => undefined);
    releaseReclaimSlot();
  }
}
