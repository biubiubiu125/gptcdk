const assert = require('node:assert/strict');
const { test } = require('node:test');
const { randomBytes } = require('node:crypto');
const bcrypt = require('bcryptjs');

process.env.NODE_ENV = 'test';
const { Logger } = require('@nestjs/common');
const { JwtService } = require('@nestjs/jwt');
const { PrismaClient } = require('@prisma/client');
const { initializeSchema } = require('../dist/prisma/initialize-schema');
const { SCHEMA_STATEMENTS } = require('../dist/prisma/schema-statements');
const { RedeemService } = require('../dist/public/public.service');
const { AccountsService } = require('../dist/accounts/accounts.service');
const { ConvertService } = require('../dist/convert/convert.service');
const { MailboxService } = require('../dist/mailbox/mailbox.service');
const { MailAnalyzerService } = require('../dist/mailbox/mail-analyzer.service');
const { AuthService } = require('../dist/auth/auth.service');
const { JwtAuthGuard } = require('../dist/auth/jwt-auth.guard');
const { SeedService } = require('../dist/seed.service');
const { jwtSecret, initialAdminPassword } = require('../dist/auth/security-config');
const { DEFAULT_SETTINGS } = require('../dist/settings/settings.service');
const { clientAddress } = require('../dist/common/utils');

Logger.overrideLogger(false);
global.fetch = async () => { throw new Error('回归测试禁止外部网络请求'); };
const CLIENT_ID = '00000000-0000-0000-0000-000000000001';
const MS_TOKEN = 'M'.repeat(64);

function stableDeliver(content) {
  return String(content || '').replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/g, '<time>');
}

function postgresUrl() {
  const url = process.env.DATABASE_URL || '';
  if (!/^postgres(ql)?:\/\//i.test(url)) {
    throw new Error('DATABASE_URL 必须是 PostgreSQL，回归测试不再使用 SQLite');
  }
  return url;
}

function urlForSchema(base, schema) {
  const url = new URL(base);
  url.searchParams.set('schema', schema);
  return url.toString();
}

async function fixture(t, { legacy = false, limit = 1 } = {}) {
  const base = postgresUrl();
  const schema = `t_${randomBytes(4).toString('hex')}`;
  const admin = new PrismaClient({ datasources: { db: { url: base } } });
  await admin.$executeRawUnsafe(`CREATE SCHEMA "${schema}"`);
  await admin.$disconnect();
  const prisma = new PrismaClient({ datasources: { db: { url: urlForSchema(base, schema) } } });
  t.after(async () => {
    await prisma.$disconnect();
    const cleanup = new PrismaClient({ datasources: { db: { url: base } } });
    await cleanup.$executeRawUnsafe(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await cleanup.$disconnect();
  });
  if (legacy) {
    for (const statement of SCHEMA_STATEMENTS) {
      await prisma.$executeRawUnsafe(statement
        .replace('    "sessionVersion" INTEGER NOT NULL DEFAULT 0,\n', '')
        .replace('    "redeemedByCard" TEXT,\n', ''));
    }
  } else {
    await initializeSchema(prisma);
  }
  const settings = { getAll: async () => ({ ...DEFAULT_SETTINGS, redeemLimitPerCard: limit }) };
  const mailbox = new MailboxService(new MailAnalyzerService());
  const convert = new ConvertService();
  return {
    prisma, mailbox,
    redeem: new RedeemService(prisma, convert, mailbox, settings),
    accounts: new AccountsService(prisma, convert, mailbox, settings),
  };
}

async function createAccount(prisma, index = 1, extra = {}) {
  const email = `account${index}@example.com`;
  return prisma.account.create({
    data: {
      name: email, email, credits: 40, cardKey: `CARD-AAAAA-BBBBB-${String(index).padStart(5, '2')}`,
      accessToken: 'synthetic-access-token', refreshToken: 'synthetic-openai-refresh', banStatus: 'normal',
      expiresAt: new Date(Date.now() + 3600000),
      mailbox: { create: { email, password: 'placeholder-password', clientId: CLIENT_ID, refreshToken: MS_TOKEN } },
      ...extra,
    },
    include: { mailbox: true },
  });
}

function pickupResult(email, overrides = {}) {
  return { key: email, email, ok: true, error: null, banned: false, banReason: null, banKeywords: [],
    credits: null, creditsBalance: null, latestCode: null, messages: [], fetchedAt: new Date().toISOString(), ...overrides };
}

function errorText(error) {
  const body = typeof error.getResponse === 'function' ? error.getResponse() : null;
  if (body && typeof body === 'object') return String(body.message || '');
  return String(error.message || error);
}

async function rejectsPublicEmail(run) {
  await assert.rejects(run, (error) => /不支持邮箱 TXT/.test(errorText(error)));
}

test('旧库迁移保留账号与密码，回填历史主账号归属，重复执行幂等', async (t) => {
  const { prisma } = await fixture(t, { legacy: true });
  await prisma.$executeRawUnsafe(`INSERT INTO "AdminUser" ("username", "passwordHash", "updatedAt") VALUES ('legacy-admin', 'hash-kept', CURRENT_TIMESTAMP)`);
  await prisma.$executeRawUnsafe(`INSERT INTO "Account" ("name", "credits", "cardKey", "accessToken", "redeemStatus", "updatedAt") VALUES ('old', 40, 'CARD-OLD', 'token-kept', 'redeemed', CURRENT_TIMESTAMP)`);
  await initializeSchema(prisma);
  await initializeSchema(prisma);
  const admin = await prisma.adminUser.findUnique({ where: { username: 'legacy-admin' } });
  assert.equal(admin.passwordHash, 'hash-kept');
  assert.equal(admin.sessionVersion, 0);
  const account = await prisma.account.findUnique({ where: { cardKey: 'CARD-OLD' } });
  assert.equal(account.accessToken, 'token-kept');
  assert.equal(account.redeemedByCard, 'CARD-OLD');
  assert.equal(await prisma.schemaMigration.count(), 1);
});

test('仅邮箱解析、取件及导出均不能获取库存凭据', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  const resolved = await f.redeem.resolvePickup({ input: account.email });
  assert.equal(resolved.records[0].complete, false);
  assert.equal(resolved.records[0].fromCard, null);
  assert.equal(resolved.records[0].accountId, null);
  assert.equal(resolved.records[0].line, undefined);
  const fetched = await f.redeem.fetchPickup({ records: [{ key: account.email }] });
  assert.equal(fetched.results[0].ok, false);
  assert.equal(fetched.results[0].cardKey, null);
  await assert.rejects(f.redeem.exportPickup({ keys: [account.email], kind: 'line' }));
  await assert.rejects(f.redeem.exportPickup({ records: [{ key: account.email }], kind: 'line' }), /有效卡密/);
});

test('卡密可取件与导出，停用后所有公开路径拒绝继续读取', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  const resolved = await f.redeem.resolvePickup({ input: account.cardKey });
  assert.equal(resolved.records[0].complete, true);
  assert.equal(resolved.records[0].line, undefined);
  const record = { key: account.email, fromCard: account.cardKey };
  const exported = await f.redeem.exportPickup({ records: [record], kind: 'line' });
  assert(exported.content.includes(MS_TOKEN));
  f.mailbox.pickupOne = async (credential) => pickupResult(credential.email);
  assert.equal((await f.redeem.fetchPickup({ records: [record] })).results[0].ok, true);
  await f.prisma.account.update({ where: { id: account.id }, data: { cardDisabled: true } });
  assert.equal((await f.redeem.resolvePickup({ input: account.cardKey })).records.length, 0);
  await assert.rejects(f.redeem.exportPickup({ records: [record], kind: 'line' }));
});

test('自带凭据与库存隔离，伪造 key/fromCard 不能改写目标账号', async (t) => {
  const f = await fixture(t);
  const victim = await createAccount(f.prisma, 1, { banStatus: 'banned' });
  const line = `outside@example.com----placeholder----${CLIENT_ID}----${MS_TOKEN}`;
  f.mailbox.pickupOne = async (credential) => pickupResult(credential.email, { credits: 25000 });
  const response = await f.redeem.fetchPickup({ records: [{ key: victim.email, fromCard: victim.cardKey, line }] });
  assert.equal(response.results[0].email, 'outside@example.com');
  assert.equal(response.results[0].accountId, null);
  assert.equal(response.results[0].cardKey, null);
  const fresh = await f.prisma.account.findUnique({ where: { id: victim.id } });
  assert.equal(fresh.credits, 40);
  assert.equal(fresh.banStatus, 'banned');
  assert.equal(await f.prisma.pickupLog.count(), 0);
});

test('上传 JSON 自带凭据可以解析、继续取件和导出，无需存在于库存', async (t) => {
  const f = await fixture(t);
  const input = JSON.stringify({ type: 'codex', access_token: 'placeholder', email: 'external@example.com',
    notes: JSON.stringify({ mailbox: { email: 'external@example.com', client_id: CLIENT_ID, refresh_token: MS_TOKEN, password: 'placeholder' } }) });
  const resolved = await f.redeem.resolvePickup({ files: [{ content: input }] });
  assert.equal(resolved.records.length, 1);
  assert.equal(resolved.records[0].complete, true);
  assert(resolved.records[0].line.includes(MS_TOKEN));
  f.mailbox.pickupOne = async (credential) => pickupResult(credential.email);
  assert.equal((await f.redeem.fetchPickup({ records: resolved.records })).results[0].ok, true);
  assert((await f.redeem.exportPickup({ records: resolved.records, kind: 'line' })).content.includes(MS_TOKEN));
});

test('后台邮箱 TXT 保持四段或六段，前台兑换不再接受邮箱 TXT', async (t) => {
  const f = await fixture(t);
  const password = '@Demo$pa*ss!';
  const secret = 'JBSWY3DPEHPK3PXP';
  const records = [1, 2].map((index) => {
    const email = `delivery${index}@example.com`;
    const notes = { mailbox: { email, password: 'mailbox-demo', client_id: CLIENT_ID, refresh_token: MS_TOKEN } };
    if (index === 1) {
      notes.gpt = { password };
      notes.two_factor = { secret };
    }
    const accessToken = `e30.${Buffer.from(JSON.stringify({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' })).toString('base64url')}.sig`;
    return { type: 'codex', email, access_token: accessToken, notes: JSON.stringify(notes) };
  });
  const imported = await f.accounts.importAccounts({ content: JSON.stringify(records), remark: '测试批次', subscriptionTag: 'Plus' });
  assert.equal(imported.imported, 2);
  assert.equal(imported.failed, 0);
  const rows = await f.prisma.account.findMany({ orderBy: { id: 'asc' }, include: { mailbox: true } });
  assert.deepEqual(JSON.parse(rows[0].rawJson), records[0]);
  const baseLines = rows.map((row) => `${row.email}----mailbox-demo----${CLIENT_ID}----${MS_TOKEN}`);
  const expectedLines = [`${baseLines[0]}----${password}----${secret}`, baseLines[1]];
  const expected = `${expectedLines.join('\n')}\n`;
  assert.equal((await f.accounts.exportAccounts({ format: 'email', ids: rows.map((row) => row.id) })).content, expected);

  await rejectsPublicEmail(() => f.redeem.redeem({ cards: rows.map((row) => row.cardKey), format: 'email' }));
  assert.equal(await f.prisma.account.count({ where: { redeemStatus: 'redeemed' } }), 0);
  const pickup = await f.redeem.exportPickup({
    records: [{ key: rows[0].email, fromCard: rows[0].cardKey }], kind: 'line',
  });
  assert.equal(pickup.content.trim(), baseLines[0], '邮箱取件的凭据导出仍只包含邮箱四段');
});

test('历史六段取件行导出时不带出 ChatGPT 密码和 2FA', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  const gptPassword = 'chatgpt-pass';
  const totp = 'JBSWY3DPEHPK3PXP';
  const legacy = `${account.email}----placeholder-password----${CLIENT_ID}----${MS_TOKEN}----${gptPassword}----${totp}`;
  await f.prisma.mailCredential.update({ where: { accountId: account.id }, data: { line: legacy } });
  const expected = `${account.email}----placeholder-password----${CLIENT_ID}----${MS_TOKEN}`;

  const pickup = await f.redeem.exportPickup({
    records: [{ key: account.email, fromCard: account.cardKey }],
    kind: 'line',
  });
  assert.equal(pickup.content.trim(), expected);
  assert.equal(pickup.content.includes(gptPassword), false);
  assert.equal(pickup.content.includes(totp), false);

  const redeemed = await f.redeem.redeem({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(redeemed.results[0].ok, true);
  assert.equal(String(redeemed.results[0].content).includes(gptPassword), false);
  assert.equal(String(redeemed.results[0].content).includes(totp), false);
  assert.match(String(redeemed.results[0].content), /source_line/);
  assert.equal(String(redeemed.results[0].content).includes(expected), true);
});

test('服务端限制每卡数量，多账号全部占用，重试不增发且附加卡不能重复领取', async (t) => {
  const f = await fixture(t, { limit: 2 });
  const [a, b, c] = await Promise.all([1, 2, 3].map((index) => createAccount(f.prisma, index)));
  const first = await f.redeem.redeem({ cards: [a.cardKey], format: 'sub2api', limit: 20 });
  assert.equal(first.results[0].accountCount, 2);
  const owned = await f.prisma.account.findMany({ where: { redeemedByCard: a.cardKey } });
  assert.equal(owned.length, 2);
  assert(owned.every((row) => row.redeemStatus === 'redeemed'));
  const retry = await f.redeem.redeem({ cards: [a.cardKey], format: 'sub2api', limit: 1 });
  assert.equal(stableDeliver(retry.results[0].content), stableDeliver(first.results[0].content));
  assert.equal(retry.results[0].firstRedeem, false);
  const extra = owned.find((row) => row.id !== a.id);
  const duplicate = await f.redeem.redeem({ cards: [extra.cardKey], format: 'sub2api' });
  assert.equal(duplicate.results[0].code, 'CARD_ALLOCATED');
  assert.equal(await f.prisma.account.count({ where: { redeemStatus: 'unredeemed' } }), 1);
  assert.equal((await f.redeem.resolvePickup({ input: a.cardKey })).records.length, 2);
  assert.equal((await f.redeem.resolvePickup({ input: extra.cardKey })).records.length, 0);
});

test('并发重复兑换返回同一集合，另一张卡不会重复占用同一账号', async (t) => {
  const f = await fixture(t, { limit: 2 });
  const accounts = [];
  for (let index = 1; index <= 4; index++) accounts.push(await createAccount(f.prisma, index));
  const [first, retry, other] = await Promise.all([
    f.redeem.redeem({ cards: [accounts[0].cardKey], format: 'sub2api', limit: 2 }),
    f.redeem.redeem({ cards: [accounts[0].cardKey], format: 'sub2api', limit: 2 }),
    f.redeem.redeem({ cards: [accounts[3].cardKey], format: 'sub2api', limit: 2 }),
  ]);
  assert.equal(stableDeliver(first.results[0].content), stableDeliver(retry.results[0].content));
  assert.equal(other.results[0].ok, true);
  const firstIds = new Set(first.results[0].accounts.map((row) => row.id));
  assert(other.results[0].accounts.every((row) => !firstIds.has(row.id)));
});

test('转换异常回滚全部库存占用', async (t) => {
  const f = await fixture(t, { limit: 2 });
  const first = await createAccount(f.prisma);
  await createAccount(f.prisma, 2);
  f.redeem.convert.buildDeliverContent = () => { throw new Error('synthetic conversion failure'); };
  const result = await f.redeem.redeem({ cards: [first.cardKey], format: 'sub2api', limit: 2 });
  assert.equal(result.results[0].code, 'INTERNAL');
  assert.equal(result.results[0].content, null);
  assert.equal(await f.prisma.account.count({ where: { redeemStatus: 'unredeemed', redeemedByCard: null } }), 2);
});

test('失效账号拒绝兑换，已交付账号禁止重置和重新生成卡密', async (t) => {
  const f = await fixture(t);
  const invalid = await createAccount(f.prisma, 1, { banStatus: 'invalid' });
  assert.equal((await f.redeem.redeem({ cards: [invalid.cardKey] })).results[0].code, 'NO_STOCK');
  const valid = await createAccount(f.prisma, 2);
  await f.redeem.redeem({ cards: [valid.cardKey] });
  await assert.rejects(f.accounts.update(valid.id, { redeemStatus: 'unredeemed' }), /重复出售/);
  await assert.rejects(f.accounts.generateCards({ ids: [valid.id], regenerate: true }), /不能重新生成/);
});

test('未标记账号取件定档写回额度，已标记账号不写，没命中不覆盖', async (t) => {
  const f = await fixture(t);
  const plain = await createAccount(f.prisma, 1, { credits: 0, subscriptionTag: null });
  const tagged = await createAccount(f.prisma, 2, { credits: 0, subscriptionTag: 'Plus' });
  const kept = await createAccount(f.prisma, 3, { credits: 12, subscriptionTag: '', banStatus: 'unknown' });
  f.mailbox.pickupOne = async (credential) => {
    if (credential?.email === kept.email) {
      return pickupResult(kept.email, { credits: null, banned: true, banReason: 'should-not-write', banKeywords: ['banned'] });
    }
    return pickupResult(credential?.email || '', { credits: 1000, banned: true, banReason: 'should-not-write', banKeywords: ['banned'] });
  };
  const response = await f.accounts.refreshStatus({ ids: [plain.id, tagged.id, kept.id], targets: ['credits'] });
  assert.equal((await f.prisma.account.findUnique({ where: { id: plain.id } })).credits, 40);
  assert.equal((await f.prisma.account.findUnique({ where: { id: tagged.id } })).credits, 0);
  assert.equal((await f.prisma.account.findUnique({ where: { id: tagged.id } })).subscriptionTag, 'Plus');
  const keptRow = await f.prisma.account.findUnique({ where: { id: kept.id } });
  assert.equal(keptRow.credits, 12);
  assert.equal(keptRow.banStatus, 'unknown');
  assert.equal(keptRow.banReason, null);
  assert.equal(response.items.find((item) => item.id === plain.id).credits, 40);
  assert.equal(response.items.find((item) => item.id === tagged.id).credits, 0);
  assert.equal(response.items.find((item) => item.id === tagged.id).creditStatus, 'ready');
  assert.equal(response.credits.hit, 2);
});

test('仅刷新过期 OpenAI token，轮换不改变兑换状态，也不覆盖已有封禁', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { expiresAt: new Date(0), banStatus: 'banned', banReason: 'already banned' });
  f.mailbox.pickupOne = async () => pickupResult(account.email, { banned: true, banReason: 'synthetic ban', banKeywords: ['account deactivated'] });
  f.mailbox.refreshOpenAiToken = async () => ({ ok: true, accessToken: 'new-access', refreshToken: 'new-openai', expiresAt: new Date(Date.now() + 3600000) });
  const response = await f.accounts.refreshStatus({ ids: [account.id], targets: ['ban', 'redeem'] });
  const fresh = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(fresh.refreshToken, 'new-openai');
  assert.equal(fresh.banStatus, 'banned');
  assert.equal(fresh.banReason, 'already banned');
  assert.equal(fresh.redeemStatus, 'unredeemed');
  assert.equal(response.ban, undefined);
  assert.equal(response.items[0].banStatus, 'banned');
  f.mailbox.refreshOpenAiToken = async () => { throw new Error('有效 token 不应刷新'); };
  assert.equal((await f.accounts.refreshStatus({ ids: [account.id], targets: ['redeem'] })).redeem.failed, 0);
});

test('微软 refresh token 不会被送到 OpenAI', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { refreshToken: null, expiresAt: new Date(1000) });
  f.mailbox.refreshOpenAiToken = async () => { throw new Error('不应调用'); };
  const response = await f.accounts.refreshStatus({ ids: [account.id], targets: ['redeem'] });
  assert.match(response.items[0].error, /缺少 OpenAI/);
  assert.equal((await f.prisma.mailCredential.findUnique({ where: { accountId: account.id } })).refreshToken, MS_TOKEN);
});

test('刷新汇总与最终状态一致：邮箱正常但 OpenAI 凭据失效', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { expiresAt: new Date(0) });
  f.mailbox.pickupOne = async () => pickupResult(account.email);
  f.mailbox.refreshOpenAiToken = async () => ({ ok: false, invalidCredential: true, error: 'invalid_grant' });
  const response = await f.accounts.refreshStatus({ ids: [account.id], targets: ['ban', 'redeem'] });
  assert.equal(response.items[0].banStatus, 'invalid');
  assert.equal(response.ban, undefined);
  assert.equal(response.redeem.failed, 1);
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).cardDisabled, true);
});

test('修改密码撤销所有旧 JWT，旧格式 JWT 也不能绕过会话版本检查', async (t) => {
  const { prisma } = await fixture(t);
  const jwt = new JwtService({ secret: 'synthetic-test-secret-at-least-32-characters', signOptions: { expiresIn: '1h' } });
  const auth = new AuthService(prisma, jwt);
  const guard = new JwtAuthGuard(jwt, prisma);
  const admin = await prisma.adminUser.create({ data: { username: 'admin', passwordHash: await bcrypt.hash('old-test-password', 4) } });
  const context = (token) => ({ switchToHttp: () => ({ getRequest: () => ({ headers: { authorization: `Bearer ${token}` } }) }) });
  const old = await auth.login('admin', 'old-test-password');
  assert.equal(await guard.canActivate(context(old.token)), true);
  await auth.changePassword(admin.id, 'old-test-password', 'new-test-password');
  await assert.rejects(guard.canActivate(context(old.token)));
  await assert.rejects(guard.canActivate(context(jwt.sign({ sub: admin.id, role: 'admin' }))));
  const current = await auth.login('admin', 'new-test-password');
  assert.equal(await guard.canActivate(context(current.token)), true);
});

test('生产环境拒绝默认签名密钥和初始密码', () => {
  const previous = { ...process.env };
  try {
    process.env.NODE_ENV = 'production';
    for (const secret of ['', 'gptcdk-dev-secret-change-me', 'gptcdk-please-change-this-secret', 'change-me-in-production']) {
      process.env.JWT_SECRET = secret;
      assert.throws(jwtSecret);
    }
    process.env.ADMIN_PASSWORD = 'admin123';
    assert.throws(initialAdminPassword);
    process.env.JWT_SECRET = 'synthetic-independent-secret-with-32-characters';
    process.env.ADMIN_PASSWORD = 'synthetic-long-password';
    assert.equal(jwtSecret(), process.env.JWT_SECRET);
    assert.equal(initialAdminPassword(), process.env.ADMIN_PASSWORD);
  } finally {
    for (const key of ['NODE_ENV', 'JWT_SECRET', 'ADMIN_PASSWORD']) {
      if (previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    }
  }
});

function reclaimService(prisma, mailbox, refresh) {
  const settings = { getAll: async () => ({ ...DEFAULT_SETTINGS, defaultFormat: 'sub2api' }) };
  return new RedeemService(prisma, new ConvertService(), mailbox, settings, { refresh });
}

async function markRedeemed(prisma, account) {
  await prisma.account.update({
    where: { id: account.id },
    data: { redeemStatus: 'redeemed', redeemedByCard: account.cardKey, redeemedAt: new Date('2026-01-01T00:00:00Z') },
  });
}

test('未兑换、缺少刷新凭据或刷新失败时不改库存', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  let calls = 0;
  const refresh = async () => {
    calls += 1;
    return { ok: true, credentials: { accessToken: 'should-not-write', refreshToken: 'should-not-write' } };
  };
  const service = reclaimService(f.prisma, f.mailbox, refresh);
  const fresh = await service.reclaim({ cards: [account.cardKey], format: 'cockpit' });
  assert.equal(fresh.results[0].code, 'CARD_NOT_REDEEMED');
  assert.equal(calls, 0);

  await markRedeemed(f.prisma, account);
  await f.prisma.account.update({ where: { id: account.id }, data: { refreshToken: null } });
  const missing = await service.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(missing.results[0].code, 'REFRESH_MISSING');
  assert.equal(calls, 0);

  await f.prisma.account.update({ where: { id: account.id }, data: { refreshToken: 'synthetic-openai-refresh' } });
  const failing = reclaimService(f.prisma, f.mailbox, async () => {
    calls += 1;
    return { ok: false, error: 'upstream' };
  });
  const failed = await failing.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(failed.results[0].code, 'REFRESH_FAILED');
  const unchanged = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(unchanged.accessToken, 'synthetic-access-token');
  assert.equal(unchanged.refreshToken, 'synthetic-openai-refresh');
});

test('找回成功只刷新一次，写库失败也不会再次请求旧凭据', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  let calls = 0;
  const refresh = async (token) => {
    calls += 1;
    assert.equal(token, calls === 1 ? 'synthetic-openai-refresh' : 'refreshed-token');
    const rotated = calls > 1;
    return {
      ok: true,
      credentials: {
        accessToken: rotated ? 'brand-new-access' : 'refreshed-access',
        refreshToken: rotated ? 'brand-new-refresh' : 'refreshed-token',
        idToken: rotated ? 'brand-new-id' : 'refreshed-id',
        expiresAt: new Date('2030-01-01T00:00:00.000Z'),
      },
    };
  };
  const service = reclaimService(f.prisma, f.mailbox, refresh);
  const result = await service.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].firstRedeem, false);
  assert.equal(result.results[0].message, '凭据已刷新');
  assert.equal(result.mergedContent, null);
  assert.equal(calls, 1);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.accessToken, 'refreshed-access');
  assert.equal(saved.refreshToken, 'refreshed-token');
  assert.equal(saved.idToken, 'refreshed-id');
  const log = await f.prisma.redeemLog.findFirst({ where: { cardKey: account.cardKey } });
  assert.equal(log.format, 'reclaim:codex');
  assert.equal(log.message, 'OK');
  assert.equal(JSON.stringify(log).includes('refreshed-access'), false);
  await service.releaseDeliveredHolds([account.id]);

  const original = f.prisma.$transaction.bind(f.prisma);
  f.prisma.$transaction = async (fn, options) => {
    if (typeof fn !== 'function') return original(fn, options);
    return original(async (tx) => {
      tx.account.updateMany = async () => {
        throw new Error('database write failed');
      };
      return fn(tx);
    }, options);
  };
  const callsBeforeWriteFailure = calls;
  const failedWrite = await service.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(calls - callsBeforeWriteFailure, 1);
  assert.equal(failedWrite.results[0].code, 'PERSIST_FAILED');
  assert.equal(failedWrite.results[0].ok, false);
  assert.match(failedWrite.results[0].content, /brand-new-access/);
  assert.equal(JSON.stringify(await f.prisma.redeemLog.findFirst({
    where: { cardKey: account.cardKey, message: 'PERSIST_FAILED' },
    orderBy: { id: 'desc' },
  })).includes('brand-new-access'), false);
  f.prisma.$transaction = original;
  const still = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(still.refreshToken, 'refreshed-token');
});


test('文件找回只刷新原卡密账号，不带附加账号', async (t) => {
  const f = await fixture(t);
  const primary = await createAccount(f.prisma, 1, { refreshToken: 'primary-refresh' });
  const extra = await createAccount(f.prisma, 2, { refreshToken: 'extra-refresh' });
  await markRedeemed(f.prisma, primary);
  await f.prisma.account.update({
    where: { id: extra.id },
    data: { redeemStatus: 'redeemed', redeemedByCard: primary.cardKey, redeemedAt: new Date() },
  });
  const calls = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    calls.push(token);
    return { ok: true, credentials: { accessToken: `access-${token}`, refreshToken: `new-${token}` } };
  });
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [primary.cardKey], format: 'sub2api' });
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '凭据已刷新');
  assert.match(result.results[0].content, /access-primary-refresh/);
  assert.equal(result.results[0].content.includes(extra.email), false);
  assert.equal(result.results[0].content.includes('extra-refresh'), false);
  assert.deepEqual(calls, ['primary-refresh']);
  const savedPrimary = await f.prisma.account.findUnique({ where: { id: primary.id } });
  const savedExtra = await f.prisma.account.findUnique({ where: { id: extra.id } });
  assert.equal(savedPrimary.refreshToken, 'new-primary-refresh');
  assert.equal(savedExtra.refreshToken, 'extra-refresh');
  assert.equal(savedExtra.refreshHeld, false);
});

test('写库失败只影响当前卡，同一次找回里其他卡仍返回', async (t) => {
  const f = await fixture(t);
  const first = await createAccount(f.prisma, 1);
  const second = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, first);
  await markRedeemed(f.prisma, second);
  const original = f.prisma.$transaction.bind(f.prisma);
  let transactions = 0;
  f.prisma.$transaction = async (fn, options) => {
    transactions += 1;
    if (transactions >= 2) throw new Error('database write failed');
    return original(fn, options);
  };
  const service = reclaimService(f.prisma, f.mailbox, async () => ({
    ok: true,
    credentials: { accessToken: 'batch-access', refreshToken: 'batch-refresh' },
  }));
  const result = await service.reclaim({ cards: [first.cardKey, second.cardKey], format: 'codex' });
  assert.equal(result.results.length, 2);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[1].ok, false);
  assert.equal(result.results[1].code, 'PERSIST_FAILED');
  assert.match(result.results[1].content, /batch-access/);
  assert.match(result.results[1].content, /batch-refresh/);
  const savedFirst = await f.prisma.account.findUnique({ where: { id: first.id } });
  const savedSecond = await f.prisma.account.findUnique({ where: { id: second.id } });
  assert.equal(savedFirst.refreshToken, 'batch-refresh');
  assert.equal(savedSecond.refreshToken, 'synthetic-openai-refresh');
});

test('邮箱格式写库失败时，结果文件仍包含新的 OpenAI 凭据', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  const original = f.prisma.$transaction.bind(f.prisma);
  f.prisma.$transaction = async (fn, options) => {
    if (typeof fn !== 'function') return original(fn, options);
    return original(async (tx) => {
      tx.account.updateMany = async () => {
        throw new Error('database write failed');
      };
      return fn(tx);
    }, options);
  };
  const service = reclaimService(f.prisma, f.mailbox, async () => ({
    ok: true,
    credentials: { accessToken: 'brand-new-access', refreshToken: 'brand-new-refresh' },
  }));
  const failed = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(failed.results[0].code, 'PERSIST_FAILED');
  assert.match(failed.results[0].content, /brand-new-access/);
  assert.match(failed.results[0].content, /brand-new-refresh/);
  assert.match(failed.mergedContent, /brand-new-access/);
  assert.match(failed.mergedContent, /brand-new-refresh/);
  assert.equal(JSON.stringify(await f.prisma.redeemLog.findFirst({
    where: { cardKey: account.cardKey },
    orderBy: { id: 'desc' },
  })).includes('brand-new-access'), false);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
});

test('刷新进行时不占着账号行锁，返回后仍写回新凭据', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  const original = f.prisma.$transaction.bind(f.prisma);
  let inTransaction = false;
  let refreshInsideTransaction = false;
  f.prisma.$transaction = async (fn, options) => {
    if (typeof fn !== 'function') return original(fn, options);
    inTransaction = true;
    try {
      return await original(fn, options);
    } finally {
      inTransaction = false;
    }
  };
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    refreshInsideTransaction = inTransaction;
    return { ok: true, credentials: { accessToken: 'held-access', refreshToken: 'held-refresh' } };
  });
  const result = await service.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(result.results[0].ok, true);
  assert.equal(refreshInsideTransaction, false);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'held-refresh');
  assert.equal(saved.accessToken, 'held-access');
});

test('写库失败重试期间，另一次找回不会用同一个旧凭据再刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  const original = f.prisma.$transaction.bind(f.prisma);
  let transactions = 0;
  let releaseWrite = () => {};
  const writeGate = new Promise((resolve) => {
    releaseWrite = resolve;
  });
  f.prisma.$transaction = async (fn, options) => {
    transactions += 1;
    if (transactions === 1 && typeof fn === 'function') {
      return original(async (tx) => {
        tx.account.updateMany = async () => {
          throw new Error('database write failed');
        };
        return fn(tx);
      }, options);
    }
    if (transactions === 2) await writeGate;
    return original(fn, options);
  };
  const seen = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    seen.push(token);
    return {
      ok: true,
      credentials: { accessToken: `access-${seen.length}`, refreshToken: `refresh-${seen.length}` },
    };
  });
  const first = service.reclaim({ cards: [account.cardKey], format: 'codex' });
  try {
    const started = Date.now();
    while (transactions < 1 && Date.now() - started < 3000) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const second = service.reclaim({ cards: [account.cardKey], format: 'codex' });
    const overlap = Date.now();
    while (seen.length < 2 && Date.now() - overlap < 400) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(seen.length, 1);
    releaseWrite();
    const [firstResult, secondResult] = await Promise.all([first, second]);
    assert.equal(firstResult.results[0].ok, true);
    assert.equal(secondResult.results[0].ok, true);
    assert.deepEqual(seen, ['synthetic-openai-refresh']);
    assert.match(secondResult.results[0].content, /access-1/);
    const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
    assert.equal(saved.refreshToken, 'refresh-1');
    assert.equal(saved.refreshHeld, true);
    return second;
  } finally {
    releaseWrite();
    await Promise.allSettled([first]);
  }
});

test('批量兑换某一张失败时，已经兑换的卡仍返回', async (t) => {
  const f = await fixture(t);
  const first = await createAccount(f.prisma, 1);
  const second = await createAccount(f.prisma, 2);
  const original = f.prisma.$transaction.bind(f.prisma);
  let transactions = 0;
  f.prisma.$transaction = async (fn, options) => {
    transactions += 1;
    if (transactions >= 2) throw new Error('database write failed');
    return original(fn, options);
  };
  const result = await f.redeem.redeem({ cards: [first.cardKey, second.cardKey], format: 'sub2api' });
  assert.equal(result.results.length, 2);
  assert.equal(result.results[0].ok, true);
  assert.match(result.results[0].content, /synthetic-access-token/);
  assert.equal(result.results[1].ok, false);
  assert.equal(result.results[1].code, 'INTERNAL');
  const savedFirst = await f.prisma.account.findUnique({ where: { id: first.id } });
  const savedSecond = await f.prisma.account.findUnique({ where: { id: second.id } });
  assert.equal(savedFirst.redeemStatus, 'redeemed');
  assert.equal(savedSecond.redeemStatus, 'unredeemed');
});

test('并发找回等待前一次写回，不会用同一个旧凭据刷新两次', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  let release = () => {};
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  t.after(() => release());
  const seen = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    seen.push(token);
    if (seen.length === 1) await gate;
    const refreshToken = `next-${seen.length}`;
    return { ok: true, credentials: { accessToken: `access-${refreshToken}`, refreshToken } };
  });
  const first = service.reclaim({ cards: [account.cardKey], format: 'codex' });
  const secondPromise = (async () => {
    const started = Date.now();
    while (seen.length < 1 && Date.now() - started < 3000) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const second = service.reclaim({ cards: [account.cardKey], format: 'codex' });
    const overlap = Date.now();
    while (seen.length < 2 && Date.now() - overlap < 1000) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(seen.length, 1);
    release();
    return second;
  })();
  try {
    const second = await secondPromise;
    const [firstResult, secondResult] = await Promise.all([first, second]);
    assert.equal(firstResult.results[0].ok, true);
    assert.equal(secondResult.results[0].ok, true);
    assert.deepEqual(seen, ['synthetic-openai-refresh']);
    assert.match(secondResult.results[0].content, /access-next-1/);
    const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
    assert.equal(saved.refreshToken, 'next-1');
    assert.equal(saved.refreshHeld, true);
  } finally {
    release();
    await Promise.allSettled([first, secondPromise.then((second) => second)]);
  }
});

test('只标记已兑换但没有归属时，找回会补归属并刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await f.accounts.update(account.id, { redeemStatus: 'redeemed' });
  const marked = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(marked.redeemStatus, 'redeemed');
  assert.equal(marked.redeemedByCard, account.cardKey);

  const legacy = await createAccount(f.prisma, 2);
  await f.prisma.account.update({
    where: { id: legacy.id },
    data: { redeemStatus: 'redeemed', redeemedByCard: null, redeemedAt: new Date('2026-01-01T00:00:00Z') },
  });
  const service = reclaimService(f.prisma, f.mailbox, async () => ({
    ok: true,
    credentials: { accessToken: 'legacy-access', refreshToken: 'legacy-refresh' },
  }));
  const result = await service.reclaim({ cards: [legacy.cardKey], format: 'codex' });
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].code, 'OK');
  const saved = await f.prisma.account.findUnique({ where: { id: legacy.id } });
  assert.equal(saved.redeemedByCard, legacy.cardKey);
  assert.equal(saved.refreshToken, 'legacy-refresh');
});

function jwtWithExp(exp) {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
  return `${header}.${payload}.sig`;
}

test('刷新没有带回过期时间时不沿用旧值，idToken 仍保留', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  const previousExpiry = new Date('2020-01-01T00:00:00Z');
  await f.prisma.account.update({
    where: { id: account.id },
    data: { idToken: 'stale-id-token', expiresAt: previousExpiry },
  });
  const service = reclaimService(f.prisma, f.mailbox, async () => ({
    ok: true,
    credentials: { accessToken: 'fresh-access', refreshToken: 'fresh-refresh' },
  }));
  const result = await service.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(result.results[0].ok, true);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.accessToken, 'fresh-access');
  assert.equal(saved.refreshToken, 'fresh-refresh');
  assert.equal(saved.idToken, 'stale-id-token');
  assert.equal(saved.expiresAt, null);

  const exp = Math.trunc(Date.now() / 1000) + 7200;
  const jwtAccount = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, jwtAccount);
  await f.prisma.account.update({
    where: { id: jwtAccount.id },
    data: { expiresAt: previousExpiry },
  });
  const jwtService = reclaimService(f.prisma, f.mailbox, async () => ({
    ok: true,
    credentials: { accessToken: jwtWithExp(exp), refreshToken: 'jwt-refresh' },
  }));
  const jwtResult = await jwtService.reclaim({ cards: [jwtAccount.cardKey], format: 'codex' });
  assert.equal(jwtResult.results[0].ok, true);
  const jwtSaved = await f.prisma.account.findUnique({ where: { id: jwtAccount.id } });
  assert.equal(jwtSaved.expiresAt.toISOString(), new Date(exp * 1000).toISOString());
});

test('写库失败后再次找回和重导出都使用暂存凭据，不再刷新旧凭据', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  const original = f.prisma.$transaction.bind(f.prisma);
  f.prisma.$transaction = async (fn, options) => {
    if (typeof fn !== 'function') return original(fn, options);
    return original(async (tx) => {
      tx.account.updateMany = async () => {
        throw new Error('database write failed');
      };
      return fn(tx);
    }, options);
  };
  const seen = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    seen.push(token);
    return { ok: true, credentials: { accessToken: 'staged-access', refreshToken: 'staged-refresh', idToken: 'staged-id' } };
  });
  const failed = await service.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(failed.results[0].code, 'PERSIST_FAILED');
  assert.match(failed.results[0].content, /staged-refresh/);
  const stored = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(stored.refreshToken, 'synthetic-openai-refresh');
  assert.match(stored.stagedCredential, /staged-refresh/);
  const again = await service.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(again.results[0].code, 'PERSIST_FAILED');
  assert.match(again.results[0].content, /staged-refresh/);
  assert.deepEqual(seen, ['synthetic-openai-refresh']);
  f.prisma.$transaction = original;
  const exported = await service.redeem({ cards: [account.cardKey], format: 'codex' });
  assert.equal(exported.results[0].ok, true);
  assert.match(exported.results[0].content, /staged-refresh/);
  assert.equal(exported.results[0].content.includes('synthetic-openai-refresh'), false);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'staged-refresh');
  assert.equal(saved.stagedCredential, null);
  assert.deepEqual(seen, ['synthetic-openai-refresh']);
});

test('再次找回不轮换已经落库的原卡密账号，也不动附加账号', async (t) => {
  const f = await fixture(t);
  const primary = await createAccount(f.prisma, 1);
  const extra = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, primary);
  await f.prisma.account.update({
    where: { id: extra.id },
    data: { redeemStatus: 'redeemed', redeemedByCard: primary.cardKey, redeemedAt: new Date('2026-01-01T00:00:00Z') },
  });
  const calls = [];
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    calls.push('refresh');
    return { ok: true, credentials: { accessToken: 'access-1', refreshToken: 'refresh-1' } };
  });
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const first = await service.reclaim({ cards: [primary.cardKey], format: 'codex' });
  assert.equal(first.results[0].ok, true);
  assert.equal(calls.length, 1);
  assert.equal(String(first.results[0].content || '').includes(extra.email), false);
  const second = await service.reclaim({ cards: [primary.cardKey], format: 'codex' });
  assert.equal(second.results[0].ok, true);
  assert.equal(calls.length, 1);
  assert.equal(second.results[0].message, '凭据已刷新过，本次没有再次轮换');
  const savedPrimary = await f.prisma.account.findUnique({ where: { id: primary.id } });
  const savedExtra = await f.prisma.account.findUnique({ where: { id: extra.id } });
  assert.equal(savedPrimary.refreshToken, 'refresh-1');
  assert.equal(savedExtra.refreshToken, 'synthetic-openai-refresh');
});

test('前台邮箱格式兑换和找回直接拒绝，不会刷新凭据', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  await rejectsPublicEmail(() => service.reclaim({ cards: [account.cardKey], format: 'email' }));
  await rejectsPublicEmail(() => service.redeem({ cards: [account.cardKey], format: 'email' }));
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.redeemStatus, 'redeemed');
});

test('后台刷新写不进去时不算成功，有暂存时不再用旧凭据刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { expiresAt: new Date(0) });
  await f.prisma.account.update({
    where: { id: account.id },
    data: {
      stagedCredential: JSON.stringify({
        accessToken: 'staged-access',
        refreshToken: 'staged-refresh',
        idToken: 'staged-id',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        previousRefreshToken: 'synthetic-openai-refresh',
      }),
    },
  });
  f.mailbox.refreshOpenAiToken = async () => {
    throw new Error('不应再用旧凭据刷新');
  };
  const applied = await f.accounts.refreshStatus({ ids: [account.id], targets: ['redeem'] });
  assert.equal(applied.redeem.failed, 0);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'staged-refresh');
  assert.equal(saved.stagedCredential, null);

  await f.prisma.account.update({
    where: { id: account.id },
    data: { expiresAt: new Date(0), refreshToken: 'current-refresh', accessToken: 'current-access' },
  });
  const originalUpdate = f.prisma.account.updateMany.bind(f.prisma.account);
  f.prisma.account.updateMany = async (args) => {
    if (args?.data?.accessToken === 'admin-access') return { count: 0 };
    return originalUpdate(args);
  };
  f.mailbox.refreshOpenAiToken = async (token) => {
    assert.equal(token, 'current-refresh');
    return { ok: true, accessToken: 'admin-access', refreshToken: 'admin-refresh', expiresAt: new Date(Date.now() + 3600000) };
  };
  const missed = await f.accounts.refreshStatus({ ids: [account.id], targets: ['redeem'] });
  assert.equal(missed.redeem.failed, 1);
  assert.match(missed.items[0].error, /暂存/);
  const still = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(still.refreshToken, 'current-refresh');
  assert.match(still.stagedCredential, /admin-refresh/);
  f.prisma.account.updateMany = originalUpdate;
  f.mailbox.refreshOpenAiToken = async () => {
    throw new Error('暂存凭据不应再次刷新');
  };
  const committed = await f.accounts.refreshStatus({ ids: [account.id], targets: ['redeem'] });
  assert.equal(committed.redeem.failed, 0);
  const finalAccount = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(finalAccount.refreshToken, 'admin-refresh');
  assert.equal(finalAccount.stagedCredential, null);
});

test('部分找回后兑换重导出仍提交附加暂存，下一轮文件找回不带附加账号', async (t) => {
  const f = await fixture(t);
  const primary = await createAccount(f.prisma, 1);
  const extra = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, primary);
  await f.prisma.account.update({
    where: { id: extra.id },
    data: {
      redeemStatus: 'redeemed',
      redeemedByCard: primary.cardKey,
      redeemedAt: new Date('2026-01-01T00:00:00Z'),
      accessToken: 'old-extra-access',
      refreshToken: 'old-extra-refresh',
      stagedCredential: JSON.stringify({
        accessToken: 'staged-extra-access',
        refreshToken: 'staged-extra-refresh',
        idToken: 'staged-extra-id',
        expiresAt: null,
        previousRefreshToken: 'old-extra-refresh',
      }),
    },
  });
  await f.prisma.account.update({
    where: { id: primary.id },
    data: { refreshHeld: true, accessToken: 'live-access-1', refreshToken: 'live-refresh-1' },
  });
  const calls = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    calls.push(token);
    return { ok: true, credentials: { accessToken: `access-${token}`, refreshToken: `rotated-${token}` } };
  });
  const exported = await service.redeem({ cards: [primary.cardKey], format: 'sub2api' });
  assert.equal(exported.results[0].ok, true);
  assert.match(exported.results[0].content, /staged-extra-refresh/);
  assert.equal(exported.results[0].content.includes('old-extra-refresh'), false);
  const savedExtra = await f.prisma.account.findUnique({ where: { id: extra.id } });
  const savedPrimary = await f.prisma.account.findUnique({ where: { id: primary.id } });
  assert.equal(savedExtra.refreshToken, 'staged-extra-refresh');
  assert.equal(savedExtra.stagedCredential, null);
  assert.equal(savedExtra.refreshHeld, true);
  assert.equal(savedPrimary.refreshHeld, true);
  const again = await service.reclaim({ cards: [primary.cardKey], format: 'sub2api' });
  assert.equal(again.results[0].ok, true);
  assert.deepEqual(calls, []);
  assert.equal(String(again.results[0].content || '').includes('staged-extra-refresh'), false);
  assert.equal(String(again.results[0].content || '').includes(extra.email), false);
  assert.match(again.results[0].content, /live-refresh-1/);
  const finalExtra = await f.prisma.account.findUnique({ where: { id: extra.id } });
  const finalPrimary = await f.prisma.account.findUnique({ where: { id: primary.id } });
  assert.equal(finalExtra.refreshToken, 'staged-extra-refresh');
  assert.equal(finalPrimary.refreshToken, 'live-refresh-1');
});

test('已兑换账号的后台检查和原卡找回都不提交附加账号暂存', async (t) => {
  const f = await fixture(t);
  const primary = await createAccount(f.prisma, 1);
  const extra = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, primary);
  await f.prisma.account.update({
    where: { id: primary.id },
    data: { refreshHeld: true, accessToken: 'live-access-1', refreshToken: 'live-refresh-1' },
  });
  await f.prisma.account.update({
    where: { id: extra.id },
    data: {
      redeemStatus: 'redeemed',
      redeemedByCard: primary.cardKey,
      redeemedAt: new Date('2026-01-01T00:00:00Z'),
      accessToken: 'old-extra-access',
      refreshToken: 'old-extra-refresh',
      expiresAt: new Date(Date.now() + 3600000),
      stagedCredential: JSON.stringify({
        accessToken: 'admin-staged-access',
        refreshToken: 'admin-staged-refresh',
        idToken: 'admin-staged-id',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        previousRefreshToken: 'old-extra-refresh',
      }),
    },
  });
  f.mailbox.refreshOpenAiToken = async () => {
    throw new Error('不应再用旧凭据刷新');
  };
  const applied = await f.accounts.refreshStatus({ ids: [extra.id], targets: ['redeem'] });
  assert.equal(applied.redeem.failed, 0);
  assert.equal(applied.items[0].error, null);
  const savedExtra = await f.prisma.account.findUnique({ where: { id: extra.id } });
  assert.equal(savedExtra.refreshToken, 'old-extra-refresh');
  assert.equal(savedExtra.stagedCredential == null, false);
  assert.notEqual(savedExtra.refreshHeld, true);
  const calls = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    calls.push(token);
    return { ok: true, credentials: { accessToken: `access-${token}`, refreshToken: `rotated-${token}` } };
  });
  const again = await service.reclaim({ cards: [primary.cardKey], format: 'codex' });
  assert.equal(again.results[0].ok, true);
  assert.equal(JSON.stringify(again.results[0]).includes('admin-staged-refresh'), false);
  assert.equal(JSON.stringify(again.results[0]).includes(extra.email), false);
  assert.deepEqual(calls, []);
  const finalExtra = await f.prisma.account.findUnique({ where: { id: extra.id } });
  assert.equal(finalExtra.refreshToken, 'old-extra-refresh');
  assert.equal(finalExtra.stagedCredential == null, false);
});

test('兑换重导出先提交暂存凭据，再按文件格式交付', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  await f.prisma.account.update({
    where: { id: account.id },
    data: {
      stagedCredential: JSON.stringify({
        accessToken: 'mail-new-access',
        refreshToken: 'mail-new-refresh',
        idToken: 'mail-new-id',
        expiresAt: null,
        previousRefreshToken: 'synthetic-openai-refresh',
      }),
    },
  });
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应再刷新');
  });
  const exported = await service.redeem({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(exported.results[0].ok, true);
  assert.match(exported.results[0].content, /mail-new-refresh/);
  assert.match(exported.results[0].content, /mail-new-access/);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'mail-new-refresh');
  assert.equal(saved.stagedCredential, null);
});

test('找回刷新期间兑换会等待，不会下载即将失效的旧凭据', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  let entered;
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    entered();
    await gate;
    return { ok: true, credentials: { accessToken: 'race-new-access', refreshToken: 'race-new-refresh' } };
  });
  const reclaiming = service.reclaim({ cards: [account.cardKey], format: 'codex' });
  await started;
  let redeemFinished = false;
  const redeeming = service.redeem({ cards: [account.cardKey], format: 'codex' }).then((result) => {
    redeemFinished = true;
    return result;
  });
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(redeemFinished, false);
  release();
  const [reclaimed, redeemed] = await Promise.all([reclaiming, redeeming]);
  assert.equal(reclaimed.results[0].ok, true);
  assert.equal(redeemed.results[0].ok, true);
  assert.match(redeemed.results[0].content, /race-new-refresh/);
  assert.equal(redeemed.results[0].content.includes('synthetic-openai-refresh'), false);
  assert.match(reclaimed.results[0].content, /race-new-refresh/);
});

test('后台导出使用暂存凭据，不用已经作废的旧凭据', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  await f.prisma.account.update({
    where: { id: account.id },
    data: {
      stagedCredential: JSON.stringify({
        accessToken: 'export-staged-access',
        refreshToken: 'export-staged-refresh',
        idToken: 'export-staged-id',
        expiresAt: null,
        previousRefreshToken: 'synthetic-openai-refresh',
      }),
    },
  });
  const exported = await f.accounts.exportAccounts({ ids: [account.id], format: 'codex' });
  assert.match(exported.content, /export-staged-refresh/);
  assert.equal(exported.content.includes('synthetic-openai-refresh'), false);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'export-staged-refresh');
  assert.equal(saved.stagedCredential, null);
});

test('数据库密码里的特殊字符会在连接串里被转义', () => {
  const { postgresDatabaseUrl } = require('../dist/common/database-url');
  const url = postgresDatabaseUrl({
    user: 'card',
    password: 'p@ss:word/a#b?c',
    host: 'postgres',
    database: 'gptcdk',
  });
  const parsed = new URL(url);
  assert.equal(parsed.username, 'card');
  assert.equal(decodeURIComponent(parsed.password), 'p@ss:word/a#b?c');
  assert.equal(parsed.hostname, 'postgres');
  assert.equal(parsed.pathname, '/gptcdk');
  assert.equal(parsed.searchParams.get('schema'), 'public');
});

test('兑换日志只记录转发链最后一跳', () => {
  assert.equal(clientAddress({ 'x-forwarded-for': '1.1.1.1, 203.0.113.8' }, '10.0.0.1'), '203.0.113.8');
  assert.equal(clientAddress({ 'x-forwarded-for': ['1.1.1.1', '203.0.113.9'] }, '10.0.0.1'), '203.0.113.9');
  assert.equal(clientAddress({}, '10.0.0.1'), '10.0.0.1');
});

test('暂存连续失败后仍会在锁内再写一次，不会拿旧凭据重刷', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  const original = f.prisma.account.updateMany.bind(f.prisma.account);
  let failures = 0;
  f.prisma.account.updateMany = async (...args) => {
    failures += 1;
    if (failures <= 2) throw new Error('stage failed');
    return original(...args);
  };
  const calls = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    calls.push(token);
    return { ok: true, credentials: { accessToken: 'retry-access', refreshToken: 'retry-refresh' } };
  });
  const result = await service.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(result.results[0].ok, true);
  assert.deepEqual(calls, ['synthetic-openai-refresh']);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'retry-refresh');
  assert.equal(saved.accessToken, 'retry-access');
  f.prisma.account.updateMany = original;
  await service.releaseDeliveredHolds([account.id]);
  const again = await service.reclaim({ cards: [account.cardKey], format: 'codex' });
  assert.equal(again.results[0].ok, true);
  assert.equal(calls[1], 'retry-refresh');
  assert.equal(calls.filter((token) => token === 'synthetic-openai-refresh').length, 1);
});

test('一张卡多个账号时，codex 按账号拆成独立文件，CPA 仍是数组', async (t) => {
  const f = await fixture(t, { limit: 2 });
  const primary = await createAccount(f.prisma, 1);
  await createAccount(f.prisma, 2);
  const codex = await f.redeem.redeem({ cards: [primary.cardKey], format: 'codex', limit: 2 });
  assert.equal(codex.results[0].ok, true);
  assert.equal(codex.results[0].accountCount, 2);
  assert.equal(codex.results[0].content, null);
  assert.equal(codex.results[0].files.length, 2);
  for (const file of codex.results[0].files) {
    const parsed = JSON.parse(file.content);
    assert.equal(Array.isArray(parsed), false);
    assert.equal(parsed.auth_mode, 'chatgpt');
  }
  const cpa = await f.redeem.redeem({ cards: [primary.cardKey], format: 'cpa' });
  assert.equal(Array.isArray(JSON.parse(cpa.results[0].content)), true);
});

test('后台导出多个 codex 账号时打包，邮箱导出不附带 OpenAI JSON', async (t) => {
  const f = await fixture(t);
  const first = await createAccount(f.prisma, 1);
  const second = await createAccount(f.prisma, 2);
  const exported = await f.accounts.exportAccounts({ format: 'codex', ids: [first.id, second.id] });
  assert.equal(exported.contentType, 'application/zip');
  assert.match(exported.filename, /\.zip$/);
  assert.equal(Buffer.isBuffer(exported.content), true);
  assert.equal(exported.content.subarray(0, 2).toString(), 'PK');
  const text = exported.content.toString('utf8');
  assert.match(text, /account1@example.com/);
  assert.match(text, /account2@example.com/);
  const single = await f.accounts.exportAccounts({ format: 'codex', ids: [first.id] });
  assert.equal(single.contentType, 'application/json; charset=utf-8');
  assert.equal(Array.isArray(JSON.parse(single.content)), false);

  await f.prisma.account.update({
    where: { id: first.id },
    data: {
      stagedCredential: JSON.stringify({
        accessToken: 'admin-mail-access',
        refreshToken: 'admin-mail-refresh',
        idToken: null,
        expiresAt: null,
        previousRefreshToken: 'synthetic-openai-refresh',
      }),
    },
  });
  const email = await f.accounts.exportAccounts({ format: 'email', ids: [first.id] });
  assert.match(email.content, new RegExp(first.email));
  assert.equal(String(email.content).includes('admin-mail-access'), false);
  assert.equal(String(email.content).includes('admin-mail-refresh'), false);
  const saved = await f.prisma.account.findUnique({ where: { id: first.id } });
  assert.equal(saved.refreshToken, 'admin-mail-refresh');
});

test('后台刷新没有过期时间时不沿用旧的 expiresAt', async (t) => {
  const f = await fixture(t);
  const stale = new Date('2020-01-01T00:00:00Z');
  const plain = await createAccount(f.prisma, 1, { expiresAt: stale });
  f.mailbox.refreshOpenAiToken = async () => ({
    ok: true,
    accessToken: 'not-a-jwt',
    refreshToken: 'plain-refresh',
  });
  const missed = await f.accounts.refreshStatus({ ids: [plain.id], targets: ['redeem'] });
  assert.equal(missed.redeem.failed, 0);
  const plainSaved = await f.prisma.account.findUnique({ where: { id: plain.id } });
  assert.equal(plainSaved.refreshToken, 'plain-refresh');
  assert.equal(plainSaved.expiresAt, null);

  const exp = Math.trunc(Date.now() / 1000) + 7200;
  const jwtAccount = await createAccount(f.prisma, 2, { expiresAt: stale });
  f.mailbox.refreshOpenAiToken = async () => ({
    ok: true,
    accessToken: jwtWithExp(exp),
    refreshToken: 'jwt-refresh',
  });
  const refreshed = await f.accounts.refreshStatus({ ids: [jwtAccount.id], targets: ['redeem'] });
  assert.equal(refreshed.redeem.failed, 0);
  const jwtSaved = await f.prisma.account.findUnique({ where: { id: jwtAccount.id } });
  assert.equal(jwtSaved.expiresAt.toISOString(), new Date(exp * 1000).toISOString());
});

test('前台批量邮箱找回整次拒绝，不会刷新任何卡', async (t) => {
  const f = await fixture(t);
  const okCard = await createAccount(f.prisma, 1);
  const lostCard = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, okCard);
  await markRedeemed(f.prisma, lostCard);
  await f.prisma.account.update({ where: { id: okCard.id }, data: { refreshToken: 'ok-old' } });
  await f.prisma.account.update({ where: { id: lostCard.id }, data: { refreshToken: 'lost-old' } });
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  await rejectsPublicEmail(() => service.reclaim({ cards: [okCard.cardKey, lostCard.cardKey], format: 'email' }));
  assert.equal((await f.prisma.account.findUnique({ where: { id: okCard.id } })).refreshToken, 'ok-old');
  assert.equal((await f.prisma.account.findUnique({ where: { id: lostCard.id } })).refreshToken, 'lost-old');
});

test('后台刷新写库抛错时先暂存，下次不再用旧凭据刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { expiresAt: new Date(0) });
  await f.prisma.account.update({
    where: { id: account.id },
    data: { refreshToken: 'current-refresh', accessToken: 'current-access' },
  });
  const originalUpdate = f.prisma.account.updateMany.bind(f.prisma.account);
  f.prisma.account.updateMany = async (args) => {
    if (args?.data?.accessToken === 'thrown-access') throw new Error('database write failed');
    return originalUpdate(args);
  };
  let calls = 0;
  f.mailbox.refreshOpenAiToken = async (token) => {
    calls += 1;
    assert.equal(token, 'current-refresh');
    return {
      ok: true,
      accessToken: 'thrown-access',
      refreshToken: 'thrown-refresh',
      expiresAt: new Date(Date.now() + 3600000),
    };
  };
  const missed = await f.accounts.refreshStatus({ ids: [account.id], targets: ['redeem'] });
  assert.equal(missed.redeem.failed, 1);
  assert.match(missed.items[0].error, /暂存/);
  const still = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(still.refreshToken, 'current-refresh');
  assert.equal(still.banStatus, 'normal');
  assert.match(still.stagedCredential, /thrown-refresh/);
  f.prisma.account.updateMany = originalUpdate;
  f.mailbox.refreshOpenAiToken = async () => {
    throw new Error('暂存凭据不应再次刷新');
  };
  const committed = await f.accounts.refreshStatus({ ids: [account.id], targets: ['redeem'] });
  assert.equal(committed.redeem.failed, 0);
  assert.equal(calls, 1);
  const finalAccount = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(finalAccount.refreshToken, 'thrown-refresh');
  assert.equal(finalAccount.accessToken, 'thrown-access');
  assert.equal(finalAccount.stagedCredential, null);
  assert.equal(finalAccount.banStatus, 'normal');
});

test('导出暂存没有过期时间时不退回旧的 expiresAt', async (t) => {
  const f = await fixture(t);
  const stale = new Date('2020-01-01T00:00:00Z');
  const account = await createAccount(f.prisma, 1, { expiresAt: stale });
  await f.prisma.account.update({
    where: { id: account.id },
    data: {
      stagedCredential: JSON.stringify({
        accessToken: 'staged-export-access',
        refreshToken: 'staged-export-refresh',
        idToken: null,
        expiresAt: null,
        previousRefreshToken: 'synthetic-openai-refresh',
      }),
    },
  });
  const originalUpdate = f.prisma.account.updateMany.bind(f.prisma.account);
  f.prisma.account.updateMany = async (args) => {
    if (args?.data?.accessToken === 'staged-export-access') throw new Error('persist failed');
    return originalUpdate(args);
  };
  const exported = await f.accounts.exportAccounts({ format: 'sub2api', ids: [account.id] });
  assert.match(exported.content, /staged-export-access/);
  assert.match(exported.content, /staged-export-refresh/);
  assert.equal(String(exported.content).includes('1577836800'), false);
  assert.equal(String(exported.content).includes('2020-01-01'), false);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.expiresAt.toISOString(), stale.toISOString());
  assert.match(saved.stagedCredential, /staged-export-refresh/);
});

test('超过 500 张卡密直接拒绝，不静默截断', async (t) => {
  const f = await fixture(t);
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  const cards = Array.from({ length: 501 }, (_, index) => `CARD-${index}`);
  await assert.rejects(service.reclaim({ cards }), (error) => {
    assert.equal(error.getResponse().code, 'BAD_INPUT');
    assert.match(error.getResponse().message, /500/);
    return true;
  });
  await assert.rejects(service.redeem({ cards }), (error) => {
    assert.equal(error.getResponse().code, 'BAD_INPUT');
    return true;
  });
});

test('OpenAI 返回 400、401 或客户端错误时不把账号标成凭据失效', async (t) => {
  const f = await fixture(t);
  const request = await createAccount(f.prisma, 1, { expiresAt: new Date(0), refreshToken: 'request-refresh' });
  const client = await createAccount(f.prisma, 2, { expiresAt: new Date(0), refreshToken: 'client-refresh' });
  const geo = await createAccount(f.prisma, 3, { expiresAt: new Date(0), refreshToken: 'geo-refresh' });
  const dead = await createAccount(f.prisma, 4, { expiresAt: new Date(0), refreshToken: 'dead-refresh' });
  const real = f.mailbox.refreshOpenAiToken.bind(f.mailbox);
  f.mailbox.refreshOpenAiToken = async (token) => {
    const previous = global.fetch;
    global.fetch = async () => {
      if (token === 'dead-refresh') {
        return new Response(JSON.stringify({ error: { code: 'invalid_grant', message: 'expired' } }), { status: 400 });
      }
      if (token === 'client-refresh') {
        return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'bad client' }), { status: 401 });
      }
      if (token === 'geo-refresh') {
        return new Response(JSON.stringify({
          error: { code: 'unsupported_country_region_territory', message: 'Country, region, or territory not supported' },
        }), { status: 403 });
      }
      return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'bad scope' }), { status: 400 });
    };
    try {
      return await real(token);
    } finally {
      global.fetch = previous;
    }
  };
  const response = await f.accounts.refreshStatus({
    ids: [request.id, client.id, geo.id, dead.id],
    targets: ['redeem'],
  });
  const byId = new Map(response.items.map((item) => [item.id, item]));
  assert.match(byId.get(request.id).error, /invalid_request/);
  assert.match(byId.get(client.id).error, /invalid_client/);
  assert.match(byId.get(geo.id).error, /unsupported_country_region_territory/);
  assert.match(byId.get(dead.id).error, /invalid_grant/);
  assert.equal((await f.prisma.account.findUnique({ where: { id: request.id } })).banStatus, 'normal');
  assert.equal((await f.prisma.account.findUnique({ where: { id: client.id } })).banStatus, 'normal');
  assert.equal((await f.prisma.account.findUnique({ where: { id: client.id } })).cardDisabled, false);
  assert.equal((await f.prisma.account.findUnique({ where: { id: geo.id } })).banStatus, 'normal');
  assert.equal((await f.prisma.account.findUnique({ where: { id: geo.id } })).cardDisabled, false);
  assert.equal((await f.prisma.account.findUnique({ where: { id: dead.id } })).banStatus, 'invalid');
  assert.equal((await f.prisma.account.findUnique({ where: { id: dead.id } })).cardDisabled, true);
});

test('已兑换账号不在后台轮换凭据，未兑换仍可刷新', async (t) => {
  const f = await fixture(t);
  const redeemed = await createAccount(f.prisma, 1, { expiresAt: new Date(0), refreshToken: 'customer-rt' });
  await f.prisma.account.update({
    where: { id: redeemed.id },
    data: {
      redeemStatus: 'redeemed',
      redeemedByCard: redeemed.cardKey,
      stagedCredential: JSON.stringify({ refreshToken: 'staged-rt', accessToken: 'staged-at' }),
    },
  });
  const open = await createAccount(f.prisma, 2, { expiresAt: new Date(0), refreshToken: 'open-rt' });
  f.mailbox.refreshOpenAiToken = async (token) => {
    if (token === 'customer-rt') throw new Error('已兑换账号不应请求 OpenAI');
    return { ok: true, accessToken: 'open-access', refreshToken: 'open-new', expiresAt: new Date(Date.now() + 3600000) };
  };
  const blocked = await f.accounts.refreshStatus({ ids: [redeemed.id], targets: ['redeem'] });
  assert.equal(blocked.items[0].error, '已兑换账号不在后台轮换凭据');
  const kept = await f.prisma.account.findUnique({ where: { id: redeemed.id } });
  assert.equal(kept.refreshToken, 'customer-rt');
  assert.match(kept.stagedCredential, /staged-rt/);
  const rotated = await f.accounts.refreshStatus({ ids: [open.id], targets: ['redeem'] });
  assert.equal(rotated.redeem.failed, 0);
  assert.equal((await f.prisma.account.findUnique({ where: { id: open.id } })).refreshToken, 'open-new');
});

test('检查过程中已兑换时不覆盖当前凭据也不停用', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, {
    expiresAt: new Date(0),
    refreshToken: 'old-refresh',
    accessToken: 'old-access',
  });
  f.mailbox.refreshOpenAiToken = async () => {
    await f.prisma.account.update({
      where: { id: account.id },
      data: { redeemStatus: 'redeemed', redeemedByCard: account.cardKey, redeemedAt: new Date() },
    });
    return {
      ok: true,
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      expiresAt: new Date(Date.now() + 3600000),
    };
  };
  const rotated = await f.accounts.refreshStatus({ ids: [account.id], targets: ['redeem'] });
  assert.equal(rotated.items[0].error, '已兑换账号不在后台轮换凭据');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'old-refresh');
  assert.equal(saved.accessToken, 'old-access');
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.stagedCredential, null);
  assert.equal(rotated.items[0].unsavedCredential ?? null, null);

  const dead = await createAccount(f.prisma, 2, {
    expiresAt: new Date(0),
    refreshToken: 'dead-refresh',
    accessToken: 'dead-access',
    banStatus: 'normal',
  });
  f.mailbox.refreshOpenAiToken = async () => {
    await f.prisma.account.update({
      where: { id: dead.id },
      data: { redeemStatus: 'redeemed', redeemedByCard: dead.cardKey, redeemedAt: new Date() },
    });
    return { ok: false, invalidCredential: true, error: 'invalid_grant' };
  };
  const blocked = await f.accounts.refreshStatus({ ids: [dead.id], targets: ['redeem'] });
  assert.equal(blocked.items[0].error, '已兑换账号不在后台轮换凭据');
  const kept = await f.prisma.account.findUnique({ where: { id: dead.id } });
  assert.equal(kept.refreshToken, 'dead-refresh');
  assert.equal(kept.cardDisabled, false);
  assert.equal(kept.banStatus, 'normal');
  assert.equal(kept.stagedCredential, null);
});

test('检查其他卡的过期库存时，不会把正在轮换的旧凭据交给正在兑换的卡', { timeout: 20000 }, async (t) => {
  const f = await fixture(t, { limit: 2 });
  const buyer = await createAccount(f.prisma, 1, {
    cardKey: 'CARD-BUYER',
    refreshToken: 'rt-buyer',
    accessToken: 'at-buyer',
    expiresAt: new Date(Date.now() + 3600000),
  });
  const stock = await createAccount(f.prisma, 2, {
    cardKey: 'CARD-STOCK',
    refreshToken: 'rt-old-stock',
    accessToken: 'at-old-stock',
    expiresAt: new Date(0),
  });
  let releaseOpenAi = () => {};
  let entered;
  const opened = new Promise((resolve) => { entered = resolve; });
  f.mailbox.refreshOpenAiToken = async (token) => {
    assert.equal(token, 'rt-old-stock');
    entered();
    await new Promise((done) => { releaseOpenAi = done; });
    return {
      ok: true,
      accessToken: 'at-new-stock',
      refreshToken: 'rt-new-stock',
      expiresAt: new Date(Date.now() + 3600000),
    };
  };
  const admin = f.accounts.refreshStatus({ ids: [stock.id], targets: ['redeem'] });
  await opened;
  const redeemPromise = f.redeem.redeem({ cards: [buyer.cardKey], format: 'sub2api' });
  let adminResult;
  let redeemResult;
  try {
    const early = await Promise.race([
      redeemPromise.then(() => 'done'),
      new Promise((resolve) => setTimeout(() => resolve('waiting'), 800)),
    ]);
    assert.equal(early, 'waiting');
  } finally {
    releaseOpenAi();
    [adminResult, redeemResult] = await Promise.all([admin, redeemPromise]);
  }
  const text = String(redeemResult.results[0].content || '');
  assert.equal(redeemResult.results[0].ok, true);
  assert.equal(redeemResult.results[0].accountCount, 2);
  assert.equal(text.includes('rt-old-stock'), false);
  assert.equal(text.includes('rt-new-stock'), true);
  assert.equal(text.includes('rt-buyer'), true);
  const saved = await f.prisma.account.findUnique({ where: { id: stock.id } });
  assert.equal(saved.refreshToken, 'rt-new-stock');
  assert.equal(saved.redeemedByCard, buyer.cardKey);
  assert.equal(saved.stagedCredential, null);
  assert.equal(saved.cardDisabled, false);
  assert.equal(adminResult.items[0].error, null);
});

test('改标记过程中已兑换的账号不会被改标记', async (t) => {
  const f = await fixture(t);
  const plus = `e30.${Buffer.from(JSON.stringify({ chatgpt_plan_type: 'plus' })).toString('base64url')}.sig`;
  const account = await createAccount(f.prisma, 1, { accessToken: plus, subscriptionTag: null });
  const original = f.prisma.account.findMany.bind(f.prisma.account);
  f.prisma.account.findMany = async (args) => {
    const rows = await original(args);
    const ids = args?.where?.id?.in;
    if (Array.isArray(ids) && ids.includes(account.id) && args?.where?.stockKind) {
      await f.prisma.account.update({
        where: { id: account.id },
        data: { redeemStatus: 'redeemed', redeemedByCard: account.cardKey, redeemedAt: new Date() },
      });
    }
    return rows;
  };
  try {
    const response = await f.accounts.retag({ ids: [account.id], subscriptionTag: 'Plus' });
    assert.equal(response.updated, 0);
    assert.equal(response.rejected.length, 1);
    assert.equal(response.rejected[0].reason, '已兑换账号不能改标记');
  } finally {
    f.prisma.account.findMany = original;
  }
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.subscriptionTag, null);
  assert.equal(saved.planType, null);
  assert.equal(saved.redeemStatus, 'redeemed');
});

test('附加账号凭据作废时继续交付仍可用账号，卡主作废仍整卡停用', async (t) => {
  const f = await fixture(t, { limit: 2 });
  const extra = await createAccount(f.prisma, 1, {
    cardKey: 'CARD-EXTRA',
    refreshToken: 'rt-extra',
    accessToken: 'at-extra',
    expiresAt: new Date(0),
  });
  const owner = await createAccount(f.prisma, 2, {
    cardKey: 'CARD-OWNER',
    refreshToken: 'rt-owner',
    accessToken: 'at-owner',
    expiresAt: new Date(0),
  });
  const first = await f.redeem.redeem({ cards: [owner.cardKey], format: 'sub2api' });
  assert.equal(first.results[0].ok, true);
  assert.equal(first.results[0].accountCount, 2);
  const calls = [];
  f.mailbox.refreshOpenAiToken = async (token) => {
    calls.push(token);
    if (token === 'rt-extra') return { ok: false, invalidCredential: true, error: 'invalid_grant' };
    if (token === 'rt-owner') {
      return {
        ok: true,
        accessToken: 'at-owner-new',
        refreshToken: 'rt-owner-new',
        expiresAt: new Date(Date.now() + 3600000),
      };
    }
    throw new Error(`不应刷新 ${token}`);
  };
  const reclaimed = await f.redeem.reclaim({ cards: [owner.cardKey], format: 'sub2api' });
  assert.equal(reclaimed.results[0].ok, true);
  assert.equal(reclaimed.results[0].message, '凭据已刷新');
  const text = JSON.stringify(reclaimed.results[0]);
  assert.equal(text.includes('rt-owner-new'), true);
  assert.equal(text.includes('rt-extra'), false);
  assert.equal(text.includes(extra.email), false);
  assert.deepEqual(calls, ['rt-owner']);
  const extraRow = await f.prisma.account.findUnique({ where: { id: extra.id } });
  assert.equal(extraRow.cardDisabled, false);
  assert.equal(extraRow.banStatus, 'normal');
  assert.equal(extraRow.refreshToken, 'rt-extra');
  const ownerRow = await f.prisma.account.findUnique({ where: { id: owner.id } });
  assert.equal(ownerRow.cardDisabled, false);
  assert.equal(ownerRow.refreshToken, 'rt-owner-new');

  const ownerFirst = await createAccount(f.prisma, 3, {
    cardKey: 'CARD-OWNER-FIRST',
    refreshToken: 'rt-owner-first',
    accessToken: 'at-owner-first',
    expiresAt: new Date(0),
  });
  const laterExtra = await createAccount(f.prisma, 4, {
    cardKey: 'CARD-LATER-EXTRA',
    refreshToken: 'rt-later-extra',
    accessToken: 'at-later-extra',
    expiresAt: new Date(0),
  });
  const sold = await f.redeem.redeem({ cards: [ownerFirst.cardKey], format: 'sub2api' });
  assert.equal(sold.results[0].accountCount, 2);
  f.mailbox.refreshOpenAiToken = async (token) => {
    if (token === 'rt-owner-first') return { ok: false, invalidCredential: true, error: 'invalid_grant' };
    if (token === 'rt-later-extra') throw new Error('卡主作废后不应继续刷新附加账号');
    throw new Error(`不应刷新 ${token}`);
  };
  const stopped = await f.redeem.reclaim({ cards: [ownerFirst.cardKey], format: 'sub2api' });
  assert.equal(stopped.results[0].ok, false);
  assert.equal(stopped.results[0].content, null);
  assert.equal(stopped.results[0].message, '凭据已作废，请联系管理员');
  const stoppedOwner = await f.prisma.account.findUnique({ where: { id: ownerFirst.id } });
  assert.equal(stoppedOwner.cardDisabled, true);
  assert.equal(stoppedOwner.refreshToken, 'rt-owner-first');
  const stoppedExtra = await f.prisma.account.findUnique({ where: { id: laterExtra.id } });
  assert.equal(stoppedExtra.cardDisabled, false);
  assert.equal(stoppedExtra.refreshToken, 'rt-later-extra');
  const again = await f.redeem.reclaim({ cards: [ownerFirst.cardKey], format: 'sub2api' });
  assert.equal(again.results[0].code, 'CARD_DISABLED');
  assert.equal(again.results[0].content, null);
});

test('导入日期按服务器本地日筛选，关键词能搜到批次备注', async (t) => {
  const f = await fixture(t);
  const start = new Date(2026, 2, 21, 0, 0, 0, 0);
  const end = new Date(2026, 2, 21, 23, 59, 59, 999);
  await createAccount(f.prisma, 1, { cardKey: 'CARD-DATE-IN', createdAt: new Date(2026, 2, 21, 2, 30, 0, 0) });
  await createAccount(f.prisma, 2, { cardKey: 'CARD-DATE-BEFORE', createdAt: new Date(start.getTime() - 60_000) });
  await createAccount(f.prisma, 3, { cardKey: 'CARD-DATE-AFTER', createdAt: new Date(end.getTime() + 60_000) });
  const keysOf = (response) => response.items.map((item) => item.cardKey);
  const listed = await f.accounts.list({ createdFrom: '2026-03-21', createdTo: '2026-03-21', pageSize: 50 });
  assert.equal(keysOf(listed).includes('CARD-DATE-IN'), true);
  assert.equal(keysOf(listed).includes('CARD-DATE-BEFORE'), false);
  assert.equal(keysOf(listed).includes('CARD-DATE-AFTER'), false);
  const offset = -new Date().getTimezoneOffset();
  const sign = offset >= 0 ? '+' : '-';
  const hours = String(Math.floor(Math.abs(offset) / 60)).padStart(2, '0');
  const minutes = String(Math.abs(offset) % 60).padStart(2, '0');
  const zone = `${sign}${hours}:${minutes}`;
  const iso = await f.accounts.list({
    createdFrom: `2026-03-21T00:00:00.000${zone}`,
    createdTo: `2026-03-21T23:59:59.999${zone}`,
    pageSize: 50,
  });
  assert.deepEqual(keysOf(iso), keysOf(listed));

  const batch = await f.prisma.batch.create({
    data: { batchId: 'b_extract_remark', credits: 0, count: 1, remark: '提取批次备注' },
  });
  const extracted = await createAccount(f.prisma, 4, {
    cardKey: 'CARD-EXTRACT-REMARK',
    remark: null,
    batchId: batch.batchId,
  });
  const keyword = await f.accounts.list({ keyword: '提取批次备注', pageSize: 50 });
  assert.equal(keyword.items.some((item) => item.cardKey === 'CARD-EXTRACT-REMARK'), true);
  await f.accounts.update(extracted.id, { remark: '改成单行备注' });
  const edited = await f.accounts.list({ cardKey: 'CARD-EXTRACT-REMARK', pageSize: 20 });
  assert.equal(edited.items[0].batchRemark, '提取批次备注');
  assert.equal(edited.items[0].remark, '改成单行备注');
  await f.prisma.batch.delete({ where: { batchId: batch.batchId } });
  const orphan = await f.accounts.list({ cardKey: 'CARD-EXTRACT-REMARK', pageSize: 20 });
  assert.equal(orphan.items[0].batchRemark, '改成单行备注');
  assert.equal(orphan.items[0].batchId, null);
  assert.equal('banStatus' in edited.items[0], false);
});

test('未确认删除不会删掉检查后才兑换的账号', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  const original = f.prisma.account.findMany.bind(f.prisma.account);
  f.prisma.account.findMany = async (args) => {
    const rows = await original(args);
    const ids = args?.where?.id?.in;
    if (Array.isArray(ids) && ids.includes(account.id) && !args?.where?.redeemStatus) {
      await f.prisma.account.update({
        where: { id: account.id },
        data: { redeemStatus: 'redeemed', redeemedByCard: account.cardKey, redeemedAt: new Date() },
      });
    }
    return rows;
  };
  try {
    const response = await f.accounts.batchDelete([account.id], false);
    assert.equal(response.deleted, 0);
    assert.equal(response.kept, 1);
    assert.equal(JSON.stringify(response).includes('已兑换'), false);
  } finally {
    f.prisma.account.findMany = original;
  }
  const kept = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(kept.redeemStatus, 'redeemed');
  assert.equal(kept.refreshToken, 'synthetic-openai-refresh');
});

test('失效附加账号不挡住仍可用账号的找回', async (t) => {
  const f = await fixture(t);
  const primary = await createAccount(f.prisma, 1, {
    refreshToken: 'primary-refresh',
    accessToken: 'primary-access',
    rawJson: JSON.stringify({ notes: { gpt: { password: 'primary-pass' } } }),
  });
  await f.prisma.account.update({
    where: { id: primary.id },
    data: { redeemStatus: 'redeemed', redeemedByCard: primary.cardKey, redeemedAt: new Date() },
  });
  const extra = await createAccount(f.prisma, 2, {
    refreshToken: 'extra-refresh',
    accessToken: 'extra-access',
    banStatus: 'invalid',
    cardDisabled: true,
    rawJson: JSON.stringify({ notes: { gpt: { password: 'extra-pass' } } }),
  });
  await f.prisma.account.update({
    where: { id: extra.id },
    data: { redeemStatus: 'redeemed', redeemedByCard: primary.cardKey },
  });
  const calls = [];
  f.mailbox.refreshOpenAiToken = async (token) => {
    calls.push(token);
    if (token !== 'primary-refresh') throw new Error('不应刷新附加账号');
    return {
      ok: true,
      accessToken: 'primary-new',
      refreshToken: 'primary-new-rt',
      expiresAt: new Date(Date.now() + 3600000),
    };
  };
  const file = await f.redeem.reclaim({ cards: [primary.cardKey], format: 'sub2api' });
  assert.equal(file.results[0].ok, true);
  assert.equal(file.results[0].message, '凭据已刷新');
  assert.deepEqual(calls, ['primary-refresh']);
  const text = JSON.stringify(file);
  assert.equal(text.includes('primary-new'), true);
  assert.equal(text.includes('extra-access'), false);
  assert.equal(text.includes('extra-pass'), false);
  const login = await f.redeem.reclaim({ cards: [primary.cardKey], format: 'login' });
  assert.equal(login.results[0].ok, true);
  assert.equal(login.results[0].content.includes('primary-pass'), true);
  assert.equal(login.results[0].content.includes('extra-pass'), false);
  const dead = await createAccount(f.prisma, 3, { banStatus: 'invalid', cardDisabled: true });
  await f.prisma.account.update({
    where: { id: dead.id },
    data: { redeemStatus: 'redeemed', redeemedByCard: dead.cardKey, redeemedAt: new Date() },
  });
  const none = await f.redeem.reclaim({ cards: [dead.cardKey], format: 'sub2api' });
  assert.equal(none.results[0].ok, false);
  assert.equal(none.results[0].content, null);
  assert.equal(none.results[0].code, 'CARD_DISABLED');
});

test('只请求封禁刷新时不取件也不报错', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  f.mailbox.pickupOne = async () => { throw new Error('不应取件'); };
  const response = await f.accounts.refreshStatus({ ids: [account.id], targets: ['ban'] });
  assert.deepEqual(response, { requested: 0, processed: 0, nextCursor: null, items: [] });
});

test('空批次备注不能导入，已兑换不能改标记，删除已兑换需要确认', async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    () => f.accounts.importAccounts({ content: 'seller@example.com----secret-pass----JBSWY3DPEHPK3PXP', subscriptionTag: 'Plus' }),
    (error) => errorText(error) === '请填写批次备注',
  );
  const redeemed = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await f.prisma.account.update({
    where: { id: redeemed.id },
    data: { redeemStatus: 'redeemed', redeemedByCard: redeemed.cardKey },
  });
  const open = await createAccount(f.prisma, 2, { subscriptionTag: 'Plus' });
  await assert.rejects(
    () => f.accounts.retag({ ids: [redeemed.id], subscriptionTag: 'Pro' }),
    (error) => errorText(error) === '已兑换账号不能改标记',
  );
  assert.equal((await f.prisma.account.findUnique({ where: { id: redeemed.id } })).subscriptionTag, 'Plus');
  await assert.rejects(
    () => f.accounts.batchDelete([redeemed.id, open.id]),
    (error) => /已兑换/.test(errorText(error)),
  );
  assert.equal(await f.prisma.account.count(), 2);
  const deleted = await f.accounts.batchDelete([redeemed.id, open.id], true);
  assert.equal(deleted.deleted, 2);
  assert.equal(deleted.redeemed, 1);
});

test('启动时把历史封禁和失效账号停用', async (t) => {
  const f = await fixture(t);
  const banned = await createAccount(f.prisma, 1, { banStatus: 'banned', cardDisabled: false });
  const invalid = await createAccount(f.prisma, 2, { banStatus: 'invalid', cardDisabled: false });
  const normal = await createAccount(f.prisma, 3, { banStatus: 'normal', cardDisabled: false });
  await initializeSchema(f.prisma);
  assert.equal((await f.prisma.account.findUnique({ where: { id: banned.id } })).cardDisabled, true);
  assert.equal((await f.prisma.account.findUnique({ where: { id: invalid.id } })).cardDisabled, true);
  assert.equal((await f.prisma.account.findUnique({ where: { id: normal.id } })).cardDisabled, false);
});

test('后台刷新写库和暂存都失败时，响应带上未落库凭据', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { expiresAt: new Date(0) });
  await f.prisma.account.update({
    where: { id: account.id },
    data: { refreshToken: 'current-refresh', accessToken: 'current-access' },
  });
  f.prisma.account.updateMany = async () => {
    throw new Error('database write failed');
  };
  f.mailbox.refreshOpenAiToken = async (token) => {
    assert.equal(token, 'current-refresh');
    return {
      ok: true,
      accessToken: 'unsaved-access',
      refreshToken: 'unsaved-refresh',
      idToken: 'unsaved-id',
      expiresAt: new Date('2030-01-01T00:00:00Z'),
    };
  };
  const missed = await f.accounts.refreshStatus({ ids: [account.id], targets: ['redeem'] });
  assert.equal(missed.redeem.failed, 1);
  assert.match(missed.items[0].error, /请立即保存/);
  assert.equal(missed.items[0].unsavedCredential.accessToken, 'unsaved-access');
  assert.equal(missed.items[0].unsavedCredential.refreshToken, 'unsaved-refresh');
  assert.equal(missed.items[0].unsavedCredential.idToken, 'unsaved-id');
  assert.equal(missed.items[0].unsavedCredential.expiresAt, '2030-01-01T00:00:00.000Z');
  const still = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(still.refreshToken, 'current-refresh');
  assert.equal(still.accessToken, 'current-access');
  assert.equal(still.stagedCredential, null);
  assert.equal(still.banStatus, 'normal');
});

test('找回回读失败时响应带上已落库凭据，再次找回不再刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  await f.prisma.account.update({
    where: { id: account.id },
    data: { refreshToken: 'old-refresh', accessToken: 'old-access' },
  });
  let calls = 0;
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    calls += 1;
    assert.equal(token, 'old-refresh');
    return { ok: true, credentials: { accessToken: 'saved-access', refreshToken: 'saved-refresh' } };
  });
  const originalFind = f.prisma.account.findMany.bind(f.prisma.account);
  let blocked = false;
  f.prisma.account.findMany = async (args) => {
    const rows = await originalFind(args);
    if (!blocked && args?.where?.redeemedByCard && rows.some((row) => row.accessToken === 'saved-access')) {
      blocked = true;
      throw new Error('read failed');
    }
    return rows;
  };
  const first = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(calls, 1);
  assert.match(first.results[0].content, /saved-access/);
  assert.match(first.results[0].content, /saved-refresh/);
  assert.match(first.results[0].message, /不会重新刷新/);
  const stored = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(stored.refreshToken, 'saved-refresh');
  assert.equal(stored.refreshHeld, true);
  f.prisma.account.findMany = originalFind;
  const second = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(calls, 1);
  assert.equal(second.results[0].ok, true);
  assert.match(second.results[0].content, /saved-access/);
});

test('找回文件生成失败时保留已落库凭据，恢复后不再刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  await f.prisma.account.update({
    where: { id: account.id },
    data: { refreshToken: 'old-refresh', accessToken: 'old-access' },
  });
  let calls = 0;
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    calls += 1;
    return { ok: true, credentials: { accessToken: 'kept-access', refreshToken: 'kept-refresh' } };
  });
  const original = service.convert.buildDeliverContent.bind(service.convert);
  service.convert.buildDeliverContent = () => {
    throw new Error('pack failed');
  };
  const failed = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(failed.results[0].code, 'INTERNAL');
  assert.equal(failed.results[0].content, null);
  assert.equal(calls, 1);
  const stored = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(stored.accessToken, 'kept-access');
  assert.equal(stored.refreshToken, 'kept-refresh');
  assert.equal(stored.refreshHeld, true);
  service.convert.buildDeliverContent = original;
  const again = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(calls, 1);
  assert.equal(again.results[0].ok, true);
  assert.match(again.results[0].content, /kept-access/);
  assert.match(again.results[0].content, /kept-refresh/);
});

test('管理员初始化日志不包含密码', async (t) => {
  const { prisma } = await fixture(t);
  const seed = new SeedService(prisma);
  const messages = [];
  seed.logger = { log: (message) => messages.push(message) };
  const previous = process.env.ADMIN_PASSWORD;
  process.env.ADMIN_PASSWORD = 'synthetic-never-log-this-password';
  try {
    await seed.onModuleInit();
    assert.equal(await prisma.adminUser.count(), 1);
    assert(!messages.join(' ').includes(process.env.ADMIN_PASSWORD));
  } finally {
    if (previous === undefined) delete process.env.ADMIN_PASSWORD;
    else process.env.ADMIN_PASSWORD = previous;
  }
});

test('成功找回在响应送达前保持持有，未送达时再次找回不再刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  await markRedeemed(f.prisma, account);
  const calls = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    calls.push(token);
    return {
      ok: true,
      credentials: {
        accessToken: calls.length === 1 ? 'delivered-access' : 'second-access',
        refreshToken: calls.length === 1 ? 'delivered-refresh' : 'second-refresh',
      },
    };
  });
  const first = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(first.results[0].ok, true);
  assert.match(first.results[0].content, /delivered-access/);
  const stored = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(stored.refreshToken, 'delivered-refresh');
  assert.equal(stored.refreshHeld, true);
  const second = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.deepEqual(calls, ['synthetic-openai-refresh']);
  assert.equal(second.results[0].ok, true);
  assert.match(second.results[0].content, /delivered-access/);
  assert.equal(second.results[0].content.includes('second-access'), false);
  await service.releaseDeliveredHolds([account.id]);
  const released = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(released.refreshHeld, false);
  const third = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(third.results[0].ok, true);
  assert.deepEqual(calls, ['synthetic-openai-refresh', 'delivered-refresh']);
  assert.match(third.results[0].content, /second-access/);
});

test('客户端断开后不再继续刷新后续卡，也不解除已写入卡的持有', async (t) => {
  const f = await fixture(t);
  const first = await createAccount(f.prisma, 1);
  const second = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, first);
  await markRedeemed(f.prisma, second);
  let stop = false;
  const calls = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    calls.push(token);
    stop = true;
    return { ok: true, credentials: { accessToken: 'stopped-access', refreshToken: 'stopped-refresh' } };
  });
  const result = await service.reclaim({
    cards: [first.cardKey, second.cardKey],
    format: 'sub2api',
    shouldStop: () => stop,
  });
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].card, first.cardKey);
  assert.deepEqual(calls, ['synthetic-openai-refresh']);
  const savedFirst = await f.prisma.account.findUnique({ where: { id: first.id } });
  const savedSecond = await f.prisma.account.findUnique({ where: { id: second.id } });
  assert.equal(savedFirst.refreshToken, 'stopped-refresh');
  assert.equal(savedFirst.refreshHeld, true);
  assert.equal(savedSecond.refreshToken, 'synthetic-openai-refresh');
  assert.equal(savedSecond.refreshHeld, false);
});

test('组包失败重试后只返回原卡密账号，不带已持有的附加账号', async (t) => {
  const f = await fixture(t);
  const primary = await createAccount(f.prisma, 1);
  const held = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, primary);
  await f.prisma.account.update({
    where: { id: primary.id },
    data: { refreshToken: 'old-refresh', accessToken: 'old-access' },
  });
  await f.prisma.account.update({
    where: { id: held.id },
    data: {
      redeemStatus: 'redeemed',
      redeemedByCard: primary.cardKey,
      redeemedAt: new Date('2026-01-01T00:00:00Z'),
      refreshHeld: true,
      accessToken: 'held-access',
      refreshToken: 'held-refresh',
    },
  });
  const calls = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    calls.push(token);
    return { ok: true, credentials: { accessToken: 'new-access', refreshToken: 'new-refresh' } };
  });
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const originalPack = service.convert.buildDeliverContent.bind(service.convert);
  let packs = 0;
  service.convert.buildDeliverContent = (...args) => {
    packs += 1;
    if (packs === 1) throw new Error('pack failed');
    return originalPack(...args);
  };
  const failed = await service.reclaim({ cards: [primary.cardKey], format: 'sub2api' });
  const text = typeof failed.results[0].content === 'string' ? failed.results[0].content : JSON.stringify(failed.results[0].content);
  assert.equal(calls.length, 1);
  assert.equal(calls[0], 'old-refresh');
  assert.equal(failed.results[0].ok, true);
  assert.equal(failed.results[0].message, '凭据已刷新');
  assert.match(text, /new-access/);
  assert.match(text, /new-refresh/);
  assert.equal(text.includes('held-access'), false);
  assert.equal(text.includes('held-refresh'), false);
  assert.equal(text.includes(held.email), false);
  const storedHeld = await f.prisma.account.findUnique({ where: { id: held.id } });
  assert.equal(storedHeld.refreshToken, 'held-refresh');
  assert.equal(storedHeld.refreshHeld, true);
});

test('找回响应写完才解除持有，连接提前关闭不解除', async () => {
  const { EventEmitter } = require('node:events');
  const { PublicController } = require('../dist/public/public.controller');
  function response() {
    const emitter = new EventEmitter();
    emitter.writableFinished = false;
    emitter.writableEnded = false;
    emitter.headersSent = false;
    return emitter;
  }
  function request() {
    return { headers: {}, ip: '127.0.0.1', socket: new EventEmitter() };
  }

  const released = [];
  const delivered = response();
  const deliveredRequest = request();
  const deliveredService = {
    reclaim: async () => ({ results: [{ ok: true, card: 'CARD-OK', accounts: [{ id: 11 }] }, { ok: false, card: 'CARD-BAD', accounts: [{ id: 12 }] }] }),
    releaseDeliveredHolds: async (cards) => { released.push(...cards); },
  };
  const deliveredController = new PublicController(deliveredService);
  await deliveredController.reclaim({ cards: ['CARD-OK'], format: 'sub2api' }, deliveredRequest, delivered);
  delivered.writableFinished = true;
  delivered.emit('finish');
  delivered.emit('close');
  assert.deepEqual(released, [11]);

  const dropped = [];
  const closed = response();
  const closedRequest = request();
  let sawStop = false;
  const closedService = {
    reclaim: async (payload) => {
      closedRequest.socket.emit('close');
      sawStop = typeof payload.shouldStop === 'function' && payload.shouldStop() === true;
      return { results: [{ ok: true, card: 'CARD-DROPPED', accounts: [{ id: 22 }] }] };
    },
    releaseDeliveredHolds: async (cards) => { dropped.push(...cards); },
  };
  const closedController = new PublicController(closedService);
  await closedController.reclaim({ cards: ['CARD-DROPPED'], format: 'sub2api' }, closedRequest, closed);
  closed.writableFinished = true;
  closed.emit('finish');
  assert.equal(sawStop, true);
  assert.deepEqual(dropped, []);
});

test('同一条长连接上连续找回不会堆积 close 监听', async () => {
  const { EventEmitter } = require('node:events');
  const { PublicController } = require('../dist/public/public.controller');
  const socket = new EventEmitter();
  const released = [];
  const service = {
    reclaim: async () => ({ results: [{ ok: true, card: 'CARD-OK', accounts: [{ id: 11 }] }] }),
    releaseDeliveredHolds: async (cards) => { released.push(...cards); },
  };
  const controller = new PublicController(service);

  for (let index = 0; index < 2; index += 1) {
    const response = new EventEmitter();
    response.writableFinished = false;
    const request = { headers: {}, ip: '127.0.0.1', socket };
    await controller.reclaim({ cards: ['CARD-OK'], format: 'sub2api' }, request, response);
    assert.equal(socket.listenerCount('close'), 0);
    assert.equal(response.listenerCount('close'), 0);
    response.writableFinished = true;
    response.emit('finish');
  }
  assert.deepEqual(released, [11, 11]);

  const dropped = [];
  service.releaseDeliveredHolds = async (cards) => { dropped.push(...cards); };
  service.reclaim = async () => {
    socket.emit('close');
    return { results: [{ ok: true, card: 'CARD-DROPPED', accounts: [{ id: 22 }] }] };
  };
  const closed = new EventEmitter();
  closed.writableFinished = false;
  await controller.reclaim({ cards: ['CARD-DROPPED'], format: 'sub2api' }, { headers: {}, ip: '127.0.0.1', socket }, closed);
  assert.equal(socket.listenerCount('close'), 0);
  closed.writableFinished = true;
  closed.emit('finish');
  assert.deepEqual(dropped, []);

  service.reclaim = async () => {
    throw new Error('reclaim failed');
  };
  const failed = new EventEmitter();
  failed.writableFinished = false;
  await assert.rejects(
    () => controller.reclaim({ cards: ['CARD-OK'], format: 'sub2api' }, { headers: {}, ip: '127.0.0.1', socket }, failed),
    /reclaim failed/,
  );
  assert.equal(socket.listenerCount('close'), 0);
  assert.equal(failed.listenerCount('close'), 0);
});

test('公开 meta 不含邮箱 TXT，默认 email 会改成 sub2api', async (t) => {
  const f = await fixture(t);
  const meta = await f.redeem.publicMeta();
  assert.equal(meta.formats.some((item) => item.value === 'email'), false);
  assert.equal(meta.formats.some((item) => item.value === 'login'), true);
  const emailDefault = new RedeemService(
    f.prisma,
    new ConvertService(),
    f.mailbox,
    { getAll: async () => ({ ...DEFAULT_SETTINGS, defaultFormat: 'email' }) },
  );
  assert.equal((await emailDefault.publicMeta()).defaultFormat, 'sub2api');
});

test('账密兑换按实际内容输出两段或三段，不用邮箱地址和邮箱密码', async (t) => {
  const f = await fixture(t);
  const withFactor = await createAccount(f.prisma, 1, {
    email: 'chatgpt-user@example.com',
    rawJson: JSON.stringify({
      email: 'chatgpt-user@example.com',
      notes: { gpt: { password: 'pass with  ----  tail ' }, two_factor: { secret: 'JBSWY3DPEHPK3PXP' } },
    }),
  });
  const plain = await createAccount(f.prisma, 2, {
    email: 'plain-user@example.com',
    rawJson: JSON.stringify({ email: 'plain-user@example.com', notes: { gpt: { password: 'only-pass' } } }),
  });
  const delivered = await f.redeem.redeem({ cards: [withFactor.cardKey, plain.cardKey], format: 'login' });
  assert.equal(delivered.results[0].content, 'chatgpt-user@example.com----pass with  ----  tail ----JBSWY3DPEHPK3PXP\n');
  assert.equal(delivered.results[1].content, 'plain-user@example.com----only-pass\n');
  assert.equal(
    delivered.mergedContent,
    'chatgpt-user@example.com----pass with  ----  tail ----JBSWY3DPEHPK3PXP\nplain-user@example.com----only-pass\n',
  );
  assert.equal(JSON.stringify(delivered).includes('placeholder-password'), false);
  assert.equal(JSON.stringify(delivered).includes(MS_TOKEN), false);
  assert.equal(JSON.stringify(delivered).includes('synthetic-access-token'), false);
});

test('没有 ChatGPT 密码或只有 2FA 时不占库存', async (t) => {
  const f = await fixture(t);
  const missing = await createAccount(f.prisma, 1, { rawJson: JSON.stringify({ email: 'account1@example.com' }) });
  const factorOnly = await createAccount(f.prisma, 2, {
    rawJson: JSON.stringify({ notes: { two_factor: { secret: 'ONLY2FA' } } }),
  });
  assert.equal((await f.redeem.redeem({ cards: [missing.cardKey], format: 'login' })).results[0].message, '该卡密没有账密交付');
  assert.equal((await f.redeem.redeem({ cards: [factorOnly.cardKey], format: 'login' })).results[0].message, '该卡密没有账密交付');
  assert.equal(await f.prisma.account.count({ where: { redeemStatus: 'redeemed' } }), 0);
});

test('额度待定的账密兑换不占库存', async (t) => {
  const f = await fixture(t);
  const pending = await createAccount(f.prisma, 1, {
    credits: 0,
    rawJson: JSON.stringify({ notes: { gpt: { password: 'pending-pass' } } }),
  });
  const result = await f.redeem.redeem({ cards: [pending.cardKey], format: 'login' });
  assert.equal(result.results[0].code, 'CREDITS_PENDING');
  assert.equal((await f.prisma.account.findUnique({ where: { id: pending.id } })).redeemStatus, 'unredeemed');
});

test('首次账密兑换忽略 limit，重新导出要求每张账号都有账密', async (t) => {
  const f = await fixture(t);
  const primary = await createAccount(f.prisma, 1, {
    rawJson: JSON.stringify({ notes: { gpt: { password: 'primary-pass' } } }),
  });
  const extra = await createAccount(f.prisma, 2);
  const first = await f.redeem.redeem({ cards: [primary.cardKey], format: 'login', limit: 5 });
  assert.equal(first.results[0].ok, true);
  assert.equal(first.results[0].accountCount, 1);
  assert.equal((await f.prisma.account.findUnique({ where: { id: extra.id } })).redeemStatus, 'unredeemed');
  await f.prisma.account.update({
    where: { id: extra.id },
    data: { redeemStatus: 'redeemed', redeemedByCard: primary.cardKey, redeemedAt: new Date() },
  });
  const again = await f.redeem.redeem({ cards: [primary.cardKey], format: 'login' });
  assert.equal(again.results[0].ok, false);
  assert.equal(again.results[0].message, '该卡密没有账密交付');
  assert.equal((await f.prisma.account.findUnique({ where: { id: primary.id } })).redeemStatus, 'redeemed');
  assert.equal((await f.prisma.account.findUnique({ where: { id: extra.id } })).redeemStatus, 'redeemed');
});

test('账密找回不刷新，空 refresh token 也能导出', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, {
    refreshToken: '',
    rawJson: JSON.stringify({ notes: { gpt: { password: 'kept-pass' } } }),
  });
  await markRedeemed(f.prisma, account);
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  const result = await service.reclaim({ cards: [account.cardKey], format: 'login' });
  assert.equal(result.results[0].content, 'account1@example.com----kept-pass\n');
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).refreshToken, '');
});

test('未传格式且默认是邮箱时按 sub2api 兑换', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma);
  const service = new RedeemService(
    f.prisma,
    new ConvertService(),
    f.mailbox,
    { getAll: async () => ({ ...DEFAULT_SETTINGS, defaultFormat: 'email' }) },
  );
  const result = await service.redeem({ cards: [account.cardKey] });
  assert.equal(result.results[0].ok, true);
  assert.match(result.results[0].filename, /\.sub2api\.json$/);
  assert.match(result.results[0].content, /synthetic-access-token/);
});

test('账密找回写完也不解除持有', async () => {
  const { EventEmitter } = require('node:events');
  const { PublicController } = require('../dist/public/public.controller');
  const released = [];
  const service = {
    reclaim: async () => ({ format: 'login', results: [{ ok: true, card: 'CARD-LOGIN' }] }),
    releaseDeliveredHolds: async (cards) => { released.push(...cards); },
  };
  const controller = new PublicController(service);
  const response = new EventEmitter();
  response.writableFinished = false;
  await controller.reclaim(
    { cards: ['CARD-LOGIN'], format: 'login' },
    { headers: {}, ip: '127.0.0.1', socket: new EventEmitter() },
    response,
  );
  response.writableFinished = true;
  response.emit('finish');
  assert.deepEqual(released, []);

  const omitted = new EventEmitter();
  omitted.writableFinished = false;
  await controller.reclaim(
    { cards: ['CARD-LOGIN'] },
    { headers: {}, ip: '127.0.0.1', socket: new EventEmitter() },
    omitted,
  );
  omitted.writableFinished = true;
  omitted.emit('finish');
  assert.deepEqual(released, []);

  service.reclaim = async () => ({ format: 'sub2api', results: [{ ok: true, accounts: [{ id: 7 }] }] });
  const credential = new EventEmitter();
  credential.writableFinished = false;
  await controller.reclaim(
    { lines: ['buyer@example.com----stored-pass----JBSWY3DPEHPK3PXP'], format: 'sub2api' },
    { headers: {}, ip: '127.0.0.1', socket: new EventEmitter() },
    credential,
  );
  credential.writableFinished = true;
  credential.emit('finish');
  assert.deepEqual(released, []);

  const cardFile = new EventEmitter();
  cardFile.writableFinished = false;
  await controller.reclaim(
    { cards: ['CARD-FILE'], format: 'sub2api' },
    { headers: {}, ip: '127.0.0.1', socket: new EventEmitter() },
    cardFile,
  );
  cardFile.writableFinished = true;
  cardFile.emit('finish');
  assert.deepEqual(released, [7]);
});

test('账密找回成功后仍保留文件找回留下的持有', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, {
    refreshHeld: true,
    rawJson: JSON.stringify({ notes: { gpt: { password: 'held-pass' } } }),
  });
  await markRedeemed(f.prisma, account);
  const { EventEmitter } = require('node:events');
  const { PublicController } = require('../dist/public/public.controller');
  const controller = new PublicController(f.redeem);
  const response = new EventEmitter();
  response.writableFinished = false;
  const result = await controller.reclaim(
    { cards: [account.cardKey], format: 'login' },
    { headers: {}, ip: '127.0.0.1', socket: new EventEmitter() },
    response,
  );
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].content, 'account1@example.com----held-pass\n');
  response.writableFinished = true;
  response.emit('finish');
  await new Promise((resolve) => setTimeout(resolve, 300));
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshHeld, true);
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
});

test('账密重导跳过停用、封禁或失效的附加账号，仍返回可用账号', async (t) => {
  const f = await fixture(t, { limit: 2 });
  const cases = [
    { index: 1, patch: { banStatus: 'banned' } },
    { index: 2, patch: { cardDisabled: true } },
    { index: 3, patch: { banStatus: 'invalid' } },
  ];
  for (const item of cases) {
    const primary = await createAccount(f.prisma, item.index, {
      rawJson: JSON.stringify({ notes: { gpt: { password: `primary-${item.index}` } } }),
    });
    const extra = await createAccount(f.prisma, item.index + 10, {
      rawJson: JSON.stringify({ notes: { gpt: { password: `extra-${item.index}` } } }),
    });
    const claimed = await f.redeem.redeem({ cards: [primary.cardKey], format: 'sub2api', limit: 2 });
    assert.equal(claimed.results[0].ok, true);
    await f.prisma.account.update({ where: { id: extra.id }, data: item.patch });
    const before = await f.prisma.account.findUnique({ where: { id: primary.id } });
    const again = await f.redeem.redeem({ cards: [primary.cardKey], format: 'login' });
    assert.equal(again.results[0].ok, true);
    assert.equal(again.results[0].message, '部分账号已停用，本次只返回仍可用的凭据');
    assert.equal(again.results[0].content.includes(`primary-${item.index}`), true);
    assert.equal(again.results[0].content.includes(`extra-${item.index}`), false);
    const savedPrimary = await f.prisma.account.findUnique({ where: { id: primary.id } });
    const savedExtra = await f.prisma.account.findUnique({ where: { id: extra.id } });
    assert.equal(savedPrimary.redeemStatus, 'redeemed');
    assert.equal(savedPrimary.redeemedByCard, primary.cardKey);
    assert.equal(savedPrimary.redeemCount, before.redeemCount + 1);
    assert.equal(savedExtra.redeemedByCard, primary.cardKey);
    assert.equal(savedExtra.cardDisabled || savedExtra.banStatus === 'banned' || savedExtra.banStatus === 'invalid', true);
  }
});

test('后台账密导出跳过没有密码的账号，空结果是空文本', async (t) => {
  const f = await fixture(t);
  const ready = await createAccount(f.prisma, 1, {
    rawJson: JSON.stringify({ notes: { gpt: { password: 'export-pass' } } }),
  });
  const skipped = await createAccount(f.prisma, 2);
  const exported = await f.accounts.exportAccounts({ format: 'login', ids: [ready.id, skipped.id] });
  assert.equal(exported.content, 'account1@example.com----export-pass\n');
  assert.equal(exported.filename.endsWith('.txt'), true);
  const empty = await f.accounts.exportAccounts({ format: 'login', ids: [skipped.id] });
  assert.equal(empty.content, '');
});

function claimsJwt(claims) {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${header}.${payload}.sig`;
}

function plusAccess(email, extra = {}) {
  return claimsJwt({
    email,
    chatgpt_plan_type: 'plus',
    'https://api.openai.com/profile': { email },
    ...extra,
  });
}

function loginOk(email, refresh = 'login-refresh', extra = {}) {
  return {
    ok: true,
    temporary: false,
    code: 'OK',
    message: '提取完成',
    accessToken: plusAccess(email),
    refreshToken: refresh,
    idToken: plusAccess(email),
    email: 'echo-not-proof@example.com',
    ...extra,
  };
}

async function giveLoginMaterials(prisma, account, options = {}) {
  const { encryptSecret } = require('../dist/common/secret-box');
  process.env.GPTCDK_SECRET = process.env.GPTCDK_SECRET && process.env.GPTCDK_SECRET.length >= 32
    ? process.env.GPTCDK_SECRET
    : 'gptcdk-team-test-secret-32chars-min';
  const password = options.password === undefined ? 'stored-pass' : options.password;
  const totp = options.totp === undefined ? 'JBSWY3DPEHPK3PXP' : options.totp;
  const proxy = options.proxy || 'socks5://127.0.0.1:1080';
  if (options.notes !== false) {
    const notesPassword = options.notesPassword === undefined ? password : options.notesPassword;
    const notesTotp = options.notesTotp === undefined ? totp : options.notesTotp;
    await prisma.account.update({
      where: { id: account.id },
      data: {
        rawJson: JSON.stringify({
          notes: {
            gpt: { password: notesPassword },
            two_factor: { secret: notesTotp },
          },
        }),
      },
    });
  }
  await prisma.extractJob.create({
    data: {
      batchId: `login-${account.id}-${Date.now()}-${Math.random()}`,
      email: account.email,
      subscriptionTag: options.tag || 'Plus',
      passwordCipher: encryptSecret(options.jobPassword === undefined ? password : options.jobPassword),
      totpCipher: encryptSecret(options.jobTotp === undefined ? totp : options.jobTotp),
      proxyCipher: encryptSecret(proxy),
      status: 'succeeded',
      accountId: account.id,
    },
  });
}

test('会话结束和邮箱声明按 token 判断，不认协议回显', () => {
  const { refreshSessionEnded, emailFromToken, tokenEmail, isPasswordOrTotpFailure, isProxyOrEgressFailure } = require('../dist/common/subscription');
  assert.equal(refreshSessionEnded('refresh_token_invalidated', ''), true);
  assert.equal(refreshSessionEnded('401', 'Your session has ended. Please log in again.'), true);
  assert.equal(refreshSessionEnded('invalid_grant', 'grant invalid'), false);
  assert.equal(refreshSessionEnded('401', 'unauthorized'), false);
  assert.equal(emailFromToken(claimsJwt({ 'https://api.openai.com/profile': { email: 'profile@example.com' } })), 'profile@example.com');
  assert.equal(emailFromToken(claimsJwt({ 'https://api.openai.com/auth': { email: 'auth@example.com' } })), 'auth@example.com');
  assert.equal(tokenEmail(plusAccess('access@example.com'), plusAccess('id@example.com')), 'access@example.com');
  assert.equal(isPasswordOrTotpFailure('mfa_totp', '动态码未通过'), true);
  assert.equal(isProxyOrEgressFailure('invalid_username_or_password', 'bad proxy'), false);
  assert.equal(isProxyOrEgressFailure('BAD_PROXY', 'tunnel failed'), true);
});


test('材料齐全时登录一次，不刷新且不停用', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const logins = [];
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'refreshed-access', refreshToken: 'refreshed-token' } };
  });
  service.extractClient = async (input) => {
    logins.push(input);
    return loginOk(account.email, 'login-refresh');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins.length, 1);
  assert.equal(logins[0].otpPolicy, 'reclaim');
  assert.equal(logins[0].password, 'stored-pass');
  assert.equal(logins[0].mailboxAccountId, account.id);
  assert.equal(JSON.stringify(logins[0]).includes(MS_TOKEN), false);
  assert.deepEqual(refreshes, []);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '已重新登录原卡密账号');
  const content = typeof result.results[0].content === 'string'
    ? result.results[0].content
    : JSON.stringify(result.results[0].content);
  assert.match(content, /login-refresh/);
  assert.equal(content.includes('stored-pass'), false);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'login-refresh');
  assert.equal(saved.email, account.email);
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.refreshHeld, true);
  await service.releaseDeliveredHolds(result.results[0].accounts.map((item) => item.id));
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).refreshHeld, false);
});

test('顾客提交的新密码只用于匹配，对上后用库存密码登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const logins = [];
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'refreshed-access', refreshToken: 'refreshed-token' } };
  });
  service.extractClient = async (input) => {
    logins.push(input);
    return loginOk(account.email, 'login-refresh');
  };
  const missed = await service.reclaim({
    lines: ['account1@example.com----customer-new-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
  });
  assert.equal(missed.results[0].ok, false);
  assert.equal(logins.length, 0);
  assert.deepEqual(refreshes, []);
  const matched = await service.reclaim({
    lines: ['account1@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
  });
  assert.equal(logins.length, 1);
  assert.equal(logins[0].password, 'stored-pass');
  assert.equal(logins[0].otpPolicy, 'reclaim');
  assert.deepEqual(refreshes, []);
  assert.equal(matched.results[0].ok, true);
  assert.equal(matched.results[0].accounts[0].id, account.id);
  assert.equal(matched.results[0].message, '已重新登录原卡密账号');
  assert.equal(JSON.stringify(matched).includes('customer-new-pass'), false);
  assert.equal(JSON.stringify(matched).includes('login-refresh'), true);
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).refreshHeld, true);
});

test('卡主停用时，对上的附加账号文件格式登录，账密格式不登录', async (t) => {
  const f = await fixture(t);
  const owner = await createAccount(f.prisma, 1);
  const extra = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, owner);
  await f.prisma.account.update({
    where: { id: owner.id },
    data: { cardDisabled: true, banStatus: 'invalid' },
  });
  await f.prisma.account.update({
    where: { id: extra.id },
    data: {
      cardKey: 'CARD-EXTRA-LIVE',
      redeemStatus: 'redeemed',
      redeemedByCard: owner.cardKey,
      redeemedAt: new Date(),
      refreshToken: 'rt-extra',
      accessToken: 'access-extra',
    },
  });
  await giveLoginMaterials(f.prisma, extra, { password: 'stored-pass' });
  const calls = [];
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'access-extra-new', refreshToken: 'rt-extra-new' } };
  });
  service.extractClient = async (input) => {
    calls.push(input.email);
    return loginOk(extra.email, 'rt-extra-login');
  };
  const exported = await service.reclaim({
    lines: [`${extra.email}----stored-pass----JBSWY3DPEHPK3PXP`],
    format: 'login',
  });
  assert.equal(exported.results[0].ok, true);
  assert.equal(exported.results[0].content.includes('stored-pass'), true);
  assert.equal(calls.length, 0);
  assert.deepEqual(refreshes, []);
  const matched = await service.reclaim({
    lines: [`${extra.email}----stored-pass----JBSWY3DPEHPK3PXP`],
    format: 'sub2api',
  });
  assert.equal(matched.results[0].ok, true);
  assert.equal(matched.results[0].code, 'OK');
  assert.equal(matched.results[0].message, '已重新登录原卡密账号');
  assert.deepEqual(calls, [extra.email]);
  assert.deepEqual(refreshes, []);
  const saved = await f.prisma.account.findUnique({ where: { id: extra.id } });
  assert.equal(saved.refreshToken, 'rt-extra-login');
  assert.equal(saved.refreshHeld, true);
  const ownerSaved = await f.prisma.account.findUnique({ where: { id: owner.id } });
  assert.equal(ownerSaved.refreshToken, 'synthetic-openai-refresh');
  const content = typeof matched.results[0].content === 'string'
    ? matched.results[0].content
    : JSON.stringify(matched.results[0].content);
  assert.equal(content.includes('rt-extra-login'), true);
  assert.equal(content.includes(owner.email), false);
});

test('文件找回只登录原卡密账号，不登录附加账号', async (t) => {
  const f = await fixture(t);
  const primary = await createAccount(f.prisma, 1, { refreshToken: 'primary-refresh' });
  const extra = await createAccount(f.prisma, 2, { refreshToken: 'extra-refresh' });
  await markRedeemed(f.prisma, primary);
  await f.prisma.account.update({
    where: { id: extra.id },
    data: {
      redeemStatus: 'redeemed',
      redeemedByCard: primary.cardKey,
      redeemedAt: new Date(),
      refreshHeld: true,
    },
  });
  await giveLoginMaterials(f.prisma, primary);
  await giveLoginMaterials(f.prisma, extra, { password: 'extra-pass', proxy: 'socks5://10.0.0.8:1080' });
  const logins = [];
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'primary-access-new', refreshToken: 'primary-refresh-new' } };
  });
  service.extractClient = async (input) => {
    logins.push(input.email);
    return loginOk(input.email, 'primary-login-refresh');
  };
  const result = await service.reclaim({ cards: [primary.cardKey], format: 'sub2api' });
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '已重新登录原卡密账号');
  assert.deepEqual(logins, [primary.email]);
  assert.deepEqual(refreshes, []);
  const content = typeof result.results[0].content === 'string'
    ? result.results[0].content
    : JSON.stringify(result.results[0].content);
  assert.equal(content.includes(extra.email), false);
  assert.match(content, /primary-login-refresh/);
  await service.releaseDeliveredHolds(result.results[0].accounts.map((item) => item.id));
  const savedPrimary = await f.prisma.account.findUnique({ where: { id: primary.id } });
  const savedExtra = await f.prisma.account.findUnique({ where: { id: extra.id } });
  assert.equal(savedPrimary.refreshHeld, false);
  assert.equal(savedPrimary.refreshToken, 'primary-login-refresh');
  assert.equal(savedExtra.refreshHeld, true);
  assert.equal(savedExtra.refreshToken, 'extra-refresh');
});

test('已经持有的原账号不再登录或刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await f.prisma.account.update({ where: { id: account.id }, data: { refreshHeld: true } });
  await giveLoginMaterials(f.prisma, account);
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  let logins = 0;
  service.extractClient = async () => {
    logins += 1;
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 0);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '凭据已重新登录过，本次没有再次登录');
});

test('材料齐全时密码失败不刷新、不停用，冷却不滑动', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'refreshed-access', refreshToken: 'refreshed-token' } };
  });
  service.extractClient = async () => {
    logins += 1;
    return { ok: false, temporary: false, code: 'invalid_username_or_password', message: '密码错误' };
  };
  const first = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(first.results[0].ok, false);
  assert.equal(first.results[0].code, 'LOGIN_FAILED');
  assert.equal(first.results[0].message, '重新登录失败，请联系管理员');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  const second = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(second.results[0].message, '重新登录失败，请联系管理员');
  const failed = await f.prisma.redeemLog.findMany({ where: { accountId: account.id, message: 'LOGIN_FAILED' } });
  const cooling = await f.prisma.redeemLog.findMany({ where: { accountId: account.id, message: 'LOGIN_COOLING' } });
  assert.equal(failed.length, 1);
  assert.equal(cooling.length, 1);
  await f.prisma.redeemLog.update({
    where: { id: failed[0].id },
    data: { createdAt: new Date(Date.now() - 31 * 60 * 1000) },
  });
  const third = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 2);
  assert.equal(third.results[0].code, 'LOGIN_FAILED');
  assert.equal((await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_FAILED' } })), 2);
});

test('任务代理失败后改用记住的 SOCKS 登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account, { proxy: 'socks5://127.0.0.1:1080' });
  const { encryptSecret } = require('../dist/common/secret-box');
  process.env.GPTCDK_SECRET = process.env.GPTCDK_SECRET && process.env.GPTCDK_SECRET.length >= 32
    ? process.env.GPTCDK_SECRET
    : 'gptcdk-team-test-secret-32chars-min';
  await f.prisma.setting.create({
    data: { key: 'extractSocksProxy', value: encryptSecret('socks5://10.0.0.2:1080') },
  });
  const proxies = [];
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    throw new Error('不应刷新');
  });
  service.extractClient = async (input) => {
    proxies.push(input.proxy);
    if (proxies.length === 1) return { ok: false, temporary: true, code: 'BAD_PROXY', message: 'tunnel failed' };
    return loginOk(account.email, 'remembered-refresh');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.deepEqual(proxies, ['socks5://127.0.0.1:1080', 'socks5://10.0.0.2:1080']);
  assert.deepEqual(refreshes, []);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '已重新登录原卡密账号');
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).refreshToken, 'remembered-refresh');
});

test('刷新结果和标记不一致时不写入也不标失效', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return {
      ok: true,
      credentials: {
        accessToken: claimsJwt({ chatgpt_plan_type: 'free', email: account.email }),
        refreshToken: 'free-refresh',
        idToken: claimsJwt({ chatgpt_plan_type: 'free', email: account.email }),
      },
    };
  });
  service.extractClient = async () => {
    logins += 1;
    return loginOk(account.email, 'free-refresh', {
      accessToken: claimsJwt({ chatgpt_plan_type: 'free', email: account.email }),
      idToken: claimsJwt({ chatgpt_plan_type: 'free', email: account.email }),
    });
  };
  const mismatch = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(mismatch.results[0].ok, false);
  assert.equal(mismatch.results[0].message, '新凭据与原空间不一致，已保留原文件。请联系管理员');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.cardDisabled, false);
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_MISMATCH' } }), 1);
  const again = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.equal(again.results[0].message, '新凭据与原空间不一致，已保留原文件。请联系管理员');
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_COOLING' } }), 1);
});

test('5X Team 没有原空间编号时不登录也不刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: '5X Team' });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return {
      ok: true,
      credentials: { accessToken: plusAccess(account.email), refreshToken: 'rotated-workspace-refresh' },
    };
  });
  service.extractClient = async () => {
    logins += 1;
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 0);
  assert.deepEqual(refreshes, []);
  assert.equal(result.results[0].ok, false);
  assert.equal(result.results[0].message, '该账号缺少原空间编号，已保留原文件。请联系管理员');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.cardDisabled, false);
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: { in: ['LOGIN_FAILED', 'LOGIN_MISMATCH'] } } }), 0);
});

test('找回中断不写库，也不记登录失败', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  let stop = false;
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  const originalFind = f.prisma.account.findMany.bind(f.prisma.account);
  f.prisma.account.findMany = async (args) => {
    const rows = await originalFind(args);
    if (args?.where?.redeemedByCard) stop = true;
    return rows;
  };
  service.extractClient = async () => {
    logins += 1;
    return loginOk(account.email, 'aborted-refresh');
  };
  const stopped = await service.reclaim({
    cards: [account.cardKey],
    format: 'sub2api',
    shouldStop: () => stop,
  });
  assert.equal(stopped.results[0].message, '找回已中断，请稍后重试');
  assert.equal(logins, 0);
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).refreshToken, 'synthetic-openai-refresh');
  const logs = await f.prisma.redeemLog.findMany({ where: { accountId: account.id, message: 'LOGIN_FAILED' } });
  assert.equal(logs.length, 0);
});

test('刷新已经返回时仍写入新凭据，不登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  let stop = false;
  let logins = 0;
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    stop = true;
    return { ok: true, credentials: { accessToken: 'rotated-access', refreshToken: 'rotated-refresh' } };
  });
  service.extractClient = async () => {
    logins += 1;
    throw new Error('不应登录');
  };
  const stopped = await service.reclaim({
    cards: [account.cardKey],
    format: 'sub2api',
    shouldStop: () => stop,
  });
  assert.equal(logins, 0);
  assert.equal(stopped.results[0].ok, true);
  assert.equal(stopped.results[0].message, '凭据已刷新');
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).refreshToken, 'rotated-refresh');
  const logs = await f.prisma.redeemLog.findMany({ where: { accountId: account.id, message: 'LOGIN_FAILED' } });
  assert.equal(logs.length, 0);
});

test('没有 refresh token 但材料齐全时仍然登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { refreshToken: null });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  let refreshes = 0;
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    refreshes += 1;
    throw new Error('没有刷新凭据不应刷新');
  });
  service.extractClient = async () => {
    logins += 1;
    return loginOk(account.email, 'login-refresh');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.equal(refreshes, 0);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '已重新登录原卡密账号');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'login-refresh');
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.banStatus, 'normal');
});

test('材料不全时会话结束不停用，invalid_grant 仍停用且不登录', async (t) => {
  const f = await fixture(t);
  const ended = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, ended);
  const service = reclaimService(f.prisma, f.mailbox, async () => ({
    ok: false,
    invalidCredential: false,
    sessionEnded: true,
    error: 'Your session has ended. Please log in again.',
  }));
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const first = await service.reclaim({ cards: [ended.cardKey], format: 'cpa' });
  assert.equal(first.results[0].message, '会话已结束，无法重新登录，请联系管理员');
  const endedRow = await f.prisma.account.findUnique({ where: { id: ended.id } });
  assert.equal(endedRow.cardDisabled, false);
  assert.equal(endedRow.banStatus, 'normal');

  const dead = await createAccount(f.prisma, 2);
  await markRedeemed(f.prisma, dead);
  service.refresher = {
    refresh: async () => ({ ok: false, invalidCredential: true, error: 'invalid_grant' }),
  };
  const second = await service.reclaim({ cards: [dead.cardKey], format: 'cpa' });
  assert.equal(second.results[0].message, '凭据已作废，请联系管理员');
  const deadRow = await f.prisma.account.findUnique({ where: { id: dead.id } });
  assert.equal(deadRow.cardDisabled, true);
  assert.equal(deadRow.banStatus, 'invalid');
});

test('材料齐全时先登录，不进入 invalid_grant 停用', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  const service = reclaimService(f.prisma, f.mailbox, async () => ({
    ok: false,
    invalidCredential: true,
    sessionEnded: false,
    error: 'invalid_grant',
  }));
  service.extractClient = async () => {
    logins += 1;
    return loginOk(account.email, 'login-refresh');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '已重新登录原卡密账号');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.refreshToken, 'login-refresh');
});

test('凭证文件对上但没有可用代理时不刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, {
    rawJson: JSON.stringify({
      notes: { gpt: { password: 'stored-pass' }, two_factor: { secret: 'JBSWY3DPEHPK3PXP' } },
    }),
  });
  await markRedeemed(f.prisma, account);
  let logins = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: plusAccess(account.email), refreshToken: 'rotated-by-credential-match' } };
  });
  service.extractClient = async () => {
    logins += 1;
    throw new Error('不应登录');
  };
  const result = await service.reclaim({
    lines: ['account1@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
  });
  assert.equal(logins, 0);
  assert.deepEqual(refreshes, []);
  assert.equal(result.results[0].ok, false);
  assert.equal(result.results[0].message, '重新登录缺少可用密码或代理，请联系管理员');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.refreshHeld, false);
});

test('凭证文件对上后协议未配置也不刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: plusAccess(account.email), refreshToken: 'rotated-by-worker-skip' } };
  });
  service.extractClient = async () => {
    logins += 1;
    return { ok: false, temporary: true, code: 'WORKER_DISABLED', message: '协议服务未配置' };
  };
  const result = await service.reclaim({
    lines: ['account1@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
  });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(result.results[0].ok, false);
  assert.equal(result.results[0].message, '重新登录暂时失败，请稍后重试');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.refreshHeld, false);
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: { in: ['LOGIN_FAILED', 'LOGIN_MISMATCH'] } } }), 0);
});

test('暂存令牌没有套餐声明但标记一致时仍然写入', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const access = claimsJwt({ email: account.email });
  await f.prisma.account.update({
    where: { id: account.id },
    data: {
      stagedCredential: JSON.stringify({
        accessToken: access,
        refreshToken: 'staged-no-plan-refresh',
        idToken: null,
        expiresAt: null,
        previousRefreshToken: 'synthetic-openai-refresh',
      }),
    },
  });
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '凭据已刷新');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'staged-no-plan-refresh');
  assert.equal(saved.stagedCredential, null);
  assert.equal(saved.banStatus, 'normal');
});

test('暂存凭据和原空间不一致时不登录也不标失效', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  await f.prisma.account.update({
    where: { id: account.id },
    data: {
      stagedCredential: JSON.stringify({
        accessToken: 'plain-staged-access',
        refreshToken: 'plain-staged-refresh',
        idToken: null,
        expiresAt: null,
        previousRefreshToken: 'synthetic-openai-refresh',
      }),
    },
  });
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(result.results[0].message, '新凭据与原空间不一致，已保留原文件。请联系管理员');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.stagedCredential, null);
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.cardDisabled, false);
});

test('文件找回刷新换到新票但标记不一致时交出新票且不落库', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await markRedeemed(f.prisma, account);
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return {
      ok: true,
      credentials: {
        accessToken: claimsJwt({ chatgpt_plan_type: 'free', email: account.email }),
        refreshToken: 'rotated-free-refresh',
        idToken: claimsJwt({ chatgpt_plan_type: 'free', email: account.email }),
      },
    };
  });
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.deepEqual(refreshes, ['synthetic-openai-refresh']);
  assert.equal(result.results[0].ok, false);
  assert.equal(result.results[0].message, '新凭据与原空间不一致，未写入库存。请立即保存本次结果，旧刷新凭据可能已经失效');
  assert.match(String(result.results[0].content || ''), /rotated-free-refresh/);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.accessToken, 'synthetic-access-token');
  assert.equal(saved.stagedCredential, null);
  assert.equal(saved.refreshHeld, false);
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.cardDisabled, false);
});

test('文件找回刷新没有换新票且标记不一致时保留原文件', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await markRedeemed(f.prisma, account);
  const service = reclaimService(f.prisma, f.mailbox, async () => ({
    ok: true,
    credentials: {
      accessToken: claimsJwt({ chatgpt_plan_type: 'free', email: account.email }),
      refreshToken: 'synthetic-openai-refresh',
      idToken: claimsJwt({ chatgpt_plan_type: 'free', email: account.email }),
    },
  }));
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(result.results[0].ok, false);
  assert.equal(result.results[0].message, '新凭据与原空间不一致，已保留原文件。请联系管理员');
  assert.equal(result.results[0].content, null);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.cardDisabled, false);
});

test('导入库存没有提取任务时只刷新，不登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, {
    rawJson: JSON.stringify({
      notes: { gpt: { password: 'imported-pass' }, two_factor: { secret: 'JBSWY3DPEHPK3PXP' } },
    }),
  });
  await markRedeemed(f.prisma, account);
  const logins = [];
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'refreshed-access', refreshToken: 'refreshed-token' } };
  });
  service.extractClient = async (input) => {
    logins.push(input);
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'cpa' });
  assert.equal(logins.length, 0);
  assert.deepEqual(refreshes, ['synthetic-openai-refresh']);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '凭据已刷新');
  assert.match(result.results[0].content, /refreshed-token/);
});

test('导入库存没有可用代理时不登录，会话结束仍只刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, {
    rawJson: JSON.stringify({
      notes: { gpt: { password: 'imported-pass' }, two_factor: { secret: 'JBSWY3DPEHPK3PXP' } },
    }),
  });
  await markRedeemed(f.prisma, account);
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return {
      ok: false,
      invalidCredential: false,
      sessionEnded: true,
      error: 'Your session has ended. Please log in again.',
    };
  });
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'cpa' });
  assert.deepEqual(refreshes, ['synthetic-openai-refresh']);
  assert.equal(result.results[0].message, '会话已结束，无法重新登录，请联系管理员');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.banStatus, 'normal');
});

test('协议服务未配置时调用一次后刷新，会话结束不停用', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const refreshes = [];
  let calls = 0;
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return {
      ok: false,
      invalidCredential: false,
      sessionEnded: true,
      error: 'Your session has ended. Please log in again.',
    };
  });
  service.extractClient = async () => {
    calls += 1;
    return { ok: false, temporary: true, code: 'WORKER_DISABLED', message: '协议服务未配置，Team 操作已停用' };
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'cpa' });
  assert.equal(calls, 1);
  assert.deepEqual(refreshes, ['synthetic-openai-refresh']);
  assert.equal(result.results[0].message, '会话已结束，无法重新登录，请联系管理员');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.banStatus, 'normal');
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
});

test('协议客户端抛错时不刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let calls = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'refreshed-access', refreshToken: 'refreshed-token' } };
  });
  service.extractClient = async () => {
    calls += 1;
    throw new Error('协议挂了');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(calls, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(result.results[0].ok, false);
  assert.equal(result.results[0].message, '重新登录暂时失败，请稍后重试');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.banStatus, 'normal');
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_FAILED' } }), 0);
});

test('账密格式找回材料齐全也不登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, {
    rawJson: JSON.stringify({ notes: { gpt: { password: 'export-pass' }, two_factor: { secret: 'JBSWY3DPEHPK3PXP' } } }),
  });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account, { password: 'export-pass' });
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'login' });
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].content.includes('export-pass'), true);
});

test('notes 不完整时用完整任务对，不拼接半套', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account, {
    notesPassword: 'notes-pass',
    notesTotp: '',
    jobPassword: 'job-pass',
    jobTotp: 'JBSWY3DPEHPK3PXP',
  });
  const logins = [];
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async (input) => {
    logins.push(input);
    return loginOk(account.email);
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(result.results[0].ok, true);
  assert.equal(logins.length, 1);
  assert.equal(logins[0].password, 'job-pass');
  assert.equal(logins[0].totp, 'JBSWY3DPEHPK3PXP');
});

test('notes 完整对优先于任务密码', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account, {
    notesPassword: 'notes-pass',
    notesTotp: 'JBSWY3DPEHPK3PXP',
    jobPassword: 'job-pass',
  });
  const logins = [];
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async (input) => {
    logins.push(input.password);
    return loginOk(account.email);
  };
  await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.deepEqual(logins, ['notes-pass']);
});

test('协议未授权、邮箱验证和永久失败都不刷新', async (t) => {
  const f = await fixture(t);
  const cases = [
    [{ ok: false, code: 'UNAUTHORIZED', message: '协议服务未授权' }, '协议服务未授权，请联系管理员', null],
    [{ ok: false, code: 'email_verification_required', message: '需要邮箱验证' }, '重新登录需要邮箱验证，但没有可用邮箱，请联系管理员', null],
    [{ ok: false, temporary: false, code: 'phone_required', message: '需要手机验证' }, '该账号需要手机验证，请联系管理员', 'LOGIN_BLOCKED'],
    [{ ok: false, temporary: false, code: 'DEACTIVATED', message: '账号已停用' }, '该账号已停用或封禁，请联系管理员', 'LOGIN_BLOCKED'],
  ];
  for (const [index, [payload, message, logCode]] of cases.entries()) {
    const account = await createAccount(f.prisma, index + 1);
    await markRedeemed(f.prisma, account);
    await giveLoginMaterials(f.prisma, account);
    let refreshes = 0;
    const service = reclaimService(f.prisma, f.mailbox, async () => {
      refreshes += 1;
      throw new Error('不应刷新');
    });
    service.extractClient = async () => payload;
    const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
    assert.equal(refreshes, 0);
    assert.equal(result.results[0].message, message);
    assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_FAILED' } }), 0);
    if (logCode) {
      assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: logCode } }), 1);
    }
    const again = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
    assert.equal(again.results[0].message, message);
    assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_COOLING' } }), 0);
  }
});

test('第二次代理返回未配置时不刷新', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account, { proxy: 'socks5://127.0.0.1:1080' });
  const { encryptSecret } = require('../dist/common/secret-box');
  await f.prisma.setting.create({
    data: { key: 'extractSocksProxy', value: encryptSecret('socks5://10.0.0.2:1080') },
  });
  const codes = [];
  let refreshes = 0;
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    refreshes += 1;
    throw new Error('不应刷新');
  });
  service.extractClient = async () => {
    codes.push(codes.length === 0 ? 'BAD_PROXY' : 'WORKER_DISABLED');
    return { ok: false, temporary: true, code: codes[codes.length - 1], message: '代理或未配置' };
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.deepEqual(codes, ['BAD_PROXY', 'WORKER_DISABLED']);
  assert.equal(refreshes, 0);
  assert.equal(result.results[0].message, '重新登录暂时失败，请稍后重试');
});

test('邮箱不完整时登录请求不带邮箱账号', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  await f.prisma.account.update({
    where: { id: account.id },
    data: { mailbox: { update: { refreshToken: 'short' } } },
  });
  const logins = [];
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async (input) => {
    logins.push(input);
    return loginOk(account.email);
  };
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(result.results[0].ok, true);
  assert.equal(logins[0].mailboxAccountId, undefined);
  assert.equal(logins[0].otpPolicy, 'reclaim');
});

test('内部邮箱回调缺令牌拒绝，成功也不回放邮箱密文', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  const { InternalMailboxController } = require('../dist/public/internal-mailbox.controller');
  const { allowReclaimMailbox, releaseReclaimMailbox } = require('../dist/public/reclaim-login');
  const controller = new InternalMailboxController(reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  }));
  const previous = process.env.PROTOCOL_WORKER_TOKEN;
  process.env.PROTOCOL_WORKER_TOKEN = '';
  await assert.rejects(async () => controller.otp({ accountId: account.id, email: account.email }, 'Bearer x'));
  process.env.PROTOCOL_WORKER_TOKEN = 'worker-token-test';
  await assert.rejects(async () => controller.otp({ accountId: account.id, email: account.email }, 'Bearer wrong'));
  allowReclaimMailbox(account.id);
  const result = await controller.otp({ accountId: account.id, email: account.email, excludeIds: [] }, 'Bearer worker-token-test');
  releaseReclaimMailbox(account.id);
  assert.equal(JSON.stringify(result).includes(MS_TOKEN), false);
  assert.equal(JSON.stringify(result).includes('placeholder-password'), false);
  process.env.PROTOCOL_WORKER_TOKEN = previous;
});

test('登录已经返回后客户端断开仍写入，再次找回不再登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let stop = false;
  let calls = 0;
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async () => {
    calls += 1;
    stop = true;
    return loginOk(account.email, 'saved-after-return');
  };
  const first = await service.reclaim({
    cards: [account.cardKey],
    format: 'sub2api',
    shouldStop: () => stop,
  });
  assert.equal(first.results[0].ok, true);
  assert.equal(first.results[0].message, '已重新登录原卡密账号');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'saved-after-return');
  assert.equal(saved.refreshHeld, true);
  const second = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(calls, 1);
  assert.equal(second.results[0].ok, true);
  assert.equal(second.results[0].message, '凭据已重新登录过，本次没有再次登录');
});

test('登录进行中客户端断开不中止协议请求，成功后仍落库', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let stop = false;
  let calls = 0;
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async (_input, signal) => {
    calls += 1;
    stop = true;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, 500);
      signal?.addEventListener('abort', () => {
        clearTimeout(timer);
        const error = new Error('The operation was aborted');
        error.name = 'AbortError';
        reject(error);
      });
    });
    return loginOk(account.email, 'saved-after-inflight');
  };
  const first = await service.reclaim({
    cards: [account.cardKey],
    format: 'sub2api',
    shouldStop: () => stop,
  });
  assert.equal(first.results[0].ok, true);
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.refreshToken, 'saved-after-inflight');
  assert.equal(saved.refreshHeld, true);
  assert.equal(calls, 1);
});

test('密码失败日志在卡锁释放前写入，并发找回不再登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let calls = 0;
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async () => {
    calls += 1;
    return { ok: false, temporary: false, code: 'invalid_username_or_password', message: '密码错误' };
  };
  let releaseLog;
  const gate = new Promise((resolve) => {
    releaseLog = resolve;
  });
  let logStarted;
  const started = new Promise((resolve) => {
    logStarted = resolve;
  });
  const original = service.log.bind(service);
  service.log = async (...args) => {
    logStarted();
    await gate;
    return original(...args);
  };
  const first = service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  try {
    await started;
    const second = service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
    const deadline = Date.now() + 1000;
    while (Date.now() < deadline && calls === 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(calls, 1);
    releaseLog();
    const [firstResult, secondResult] = await Promise.all([first, second]);
    assert.equal(calls, 1);
    assert.equal(firstResult.results[0].code, 'LOGIN_FAILED');
    assert.equal(secondResult.results[0].code, 'LOGIN_FAILED');
    assert.equal(secondResult.results[0].message, '重新登录失败，请联系管理员');
  } finally {
    releaseLog();
  }
});

test('邮箱回调可以先拿当前邮件基线，不回验证码和密文', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  f.mailbox.pickupOne = async () => ({
    ok: true,
    messages: [
      { id: 'old-1', code: '111111', receivedDateTime: '2026-01-01T00:00:00.000Z' },
      { id: 'old-2', code: '222222', receivedDateTime: '2026-01-02T00:00:00.000Z' },
    ],
  });
  const { InternalMailboxController } = require('../dist/public/internal-mailbox.controller');
  const { allowReclaimMailbox, releaseReclaimMailbox } = require('../dist/public/reclaim-login');
  const controller = new InternalMailboxController(reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  }));
  const previous = process.env.PROTOCOL_WORKER_TOKEN;
  process.env.PROTOCOL_WORKER_TOKEN = 'worker-token-test';
  allowReclaimMailbox(account.id);
  try {
    const baseline = await controller.otp({
      accountId: account.id,
      email: account.email,
      baseline: true,
    }, 'Bearer worker-token-test');
    assert.deepEqual([...(baseline.ids || [])].sort(), ['old-1', 'old-2']);
    assert.equal(baseline.code, undefined);
    assert.equal(JSON.stringify(baseline).includes('111111'), false);
    assert.equal(JSON.stringify(baseline).includes(MS_TOKEN), false);
    assert.equal(JSON.stringify(baseline).includes('placeholder-password'), false);
  } finally {
    releaseReclaimMailbox(account.id);
    process.env.PROTOCOL_WORKER_TOKEN = previous;
  }
});

test('两次登录总时间不超过网关', () => {
  const { readFileSync } = require('fs');
  const { join } = require('path');
  const { loginAttemptBudget, LOGIN_TIMEOUT_MS, LOGIN_TOTAL_BUDGET_MS } = require('../dist/public/reclaim-login');
  const nginx = readFileSync(join(__dirname, '../../../docker/nginx.conf.template'), 'utf8');
  const match = nginx.match(/location \/api\/[\s\S]*?proxy_read_timeout (\d+)s/);
  assert.ok(match);
  const gatewayMs = Number(match[1]) * 1000;
  assert.equal(LOGIN_TIMEOUT_MS, 360000);
  assert.equal(LOGIN_TOTAL_BUDGET_MS, 720000);
  assert.ok(LOGIN_TOTAL_BUDGET_MS + 60000 <= gatewayMs);
  assert.equal(loginAttemptBudget(0, 0), 360000);
  assert.equal(loginAttemptBudget(0, 360000), 360000);
  assert.equal(loginAttemptBudget(0, 700000), 0);
  const { gatewayLoginBudget } = require('../dist/public/reclaim-login');
  assert.equal(gatewayLoginBudget(0, 0), 360000);
  assert.equal(gatewayLoginBudget(0, 200000), 360000);
  assert.equal(gatewayLoginBudget(0, 400000), 320000);
  assert.equal(gatewayLoginBudget(0, 700000), 0);
  const internal = nginx.match(/location \/api\/internal\/\s*\{([^}]*)\}/);
  assert.ok(internal);
  assert.match(internal[1], /return 404;/);
  assert.equal(internal[1].includes('proxy_pass'), false);
});

test('找回验证码只收 OpenAI 或 ChatGPT 邮件里的验证码句', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  const seen = [];
  let messages = [];
  f.mailbox.pickupOne = async (_credential, options) => {
    seen.push(options);
    return { ok: true, messages };
  };
  const { InternalMailboxController } = require('../dist/public/internal-mailbox.controller');
  const { allowReclaimMailbox, releaseReclaimMailbox } = require('../dist/public/reclaim-login');
  const controller = new InternalMailboxController(reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  }));
  const previous = process.env.PROTOCOL_WORKER_TOKEN;
  process.env.PROTOCOL_WORKER_TOKEN = 'worker-token-test';
  allowReclaimMailbox(account.id);
  const ask = () => controller.otp({
    accountId: account.id,
    email: account.email,
  }, 'Bearer worker-token-test');
  try {
    messages = [
      {
        id: 'shop',
        from: 'Shop <orders@shop.example>',
        subject: '订单 654321',
        bodyPreview: '您的订单号 654321',
        code: '654321',
        receivedDateTime: '2026-04-02T00:00:00.000Z',
      },
      {
        id: 'openai',
        from: 'OpenAI <noreply@tm.openai.com>',
        subject: 'Your ChatGPT code',
        bodyPreview: 'Your ChatGPT verification code is 111111',
        code: '654321',
        receivedDateTime: '2026-04-01T00:00:00.000Z',
      },
    ];
    const selected = await ask();
    assert.equal(selected.code, '111111');
    assert.equal(selected.id, 'openai');
    assert.equal(seen[0].maxMessages, 200);

    messages = [messages[0]];
    const foreign = await ask();
    assert.equal(foreign.ok, false);
    assert.equal(foreign.code, 'MAILBOX_EMPTY');

    messages = [{
      id: 'receipt',
      from: 'OpenAI <noreply@tm.openai.com>',
      subject: 'Receipt',
      bodyPreview: 'order 123456',
      code: '123456',
      receivedDateTime: '2026-04-03T00:00:00.000Z',
    }];
    const receipt = await ask();
    assert.equal(receipt.ok, false);
    assert.equal(receipt.code, 'MAILBOX_EMPTY');

    messages = [{
      id: 'unknown',
      from: '未知发件人',
      subject: 'code',
      bodyPreview: 'verification code is 333333',
      code: '333333',
      receivedDateTime: '2026-04-04T00:00:00.000Z',
    }];
    const unknown = await ask();
    assert.equal(unknown.ok, false);
    assert.equal(unknown.code, 'MAILBOX_EMPTY');

    messages = [{
      id: 'chatgpt',
      from: 'ChatGPT <notify@email.chatgpt.com>',
      subject: 'ChatGPT',
      bodyPreview: 'Your code is 222222',
      code: null,
      receivedDateTime: '2026-04-05T00:00:00.000Z',
    }];
    const chatgpt = await ask();
    assert.equal(chatgpt.code, '222222');
    assert.equal(chatgpt.id, 'chatgpt');
  } finally {
    releaseReclaimMailbox(account.id);
    process.env.PROTOCOL_WORKER_TOKEN = previous;
  }
});

test('多张卡时网关时间不足不再登录也不刷新', async (t) => {
  const f = await fixture(t);
  const first = await createAccount(f.prisma, 1);
  const held = await createAccount(f.prisma, 2);
  const second = await createAccount(f.prisma, 3);
  await markRedeemed(f.prisma, first);
  await markRedeemed(f.prisma, held);
  await markRedeemed(f.prisma, second);
  await giveLoginMaterials(f.prisma, first);
  await giveLoginMaterials(f.prisma, held);
  await giveLoginMaterials(f.prisma, second);
  await f.prisma.account.update({ where: { id: held.id }, data: { refreshHeld: true } });
  const logins = [];
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'refreshed-access', refreshToken: 'refreshed-token' } };
  });
  let now = 1_000_000;
  service.reclaimLogin.now = () => now;
  service.extractClient = async (input) => {
    logins.push(input.email);
    now += 750_000;
    return loginOk(input.email, 'login-refresh');
  };
  const result = await service.reclaim({
    cards: [first.cardKey, held.cardKey, second.cardKey],
    format: 'sub2api',
  });
  assert.deepEqual(logins, [first.email]);
  assert.deepEqual(refreshes, []);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '已重新登录原卡密账号');
  assert.equal(result.results[1].ok, true);
  assert.equal(result.results[1].message, '凭据已重新登录过，本次没有再次登录');
  assert.equal(result.results[2].ok, false);
  assert.equal(result.results[2].code, 'REQUEST_BUDGET');
  assert.equal(result.results[2].message, '本次请求时间不足，请稍后单独找回');
  assert.equal(String(result.results[2].message).includes('代理'), false);
  const cooling = await f.prisma.redeemLog.findMany({
    where: { accountId: second.id, message: { in: ['LOGIN_FAILED', 'LOGIN_MISMATCH'] } },
  });
  assert.equal(cooling.length, 0);
  const saved = await f.prisma.account.findUnique({ where: { id: second.id } });
  assert.equal(saved.refreshToken, 'synthetic-openai-refresh');
  assert.equal(saved.cardDisabled, false);
});

test('验证码被拒绝后冷却，不再立刻登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'refreshed-access', refreshToken: 'refreshed-token' } };
  });
  service.extractClient = async () => {
    logins += 1;
    return { ok: false, temporary: true, code: 'email_otp_rejected_401', message: 'email_otp_rejected_401' };
  };
  const first = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(first.results[0].ok, false);
  assert.equal(first.results[0].code, 'LOGIN_FAILED');
  const second = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(second.results[0].code, 'LOGIN_FAILED');
  const failed = await f.prisma.redeemLog.findMany({ where: { accountId: account.id, message: 'LOGIN_FAILED' } });
  const cooling = await f.prisma.redeemLog.findMany({ where: { accountId: account.id, message: 'LOGIN_COOLING' } });
  assert.equal(failed.length, 1);
  assert.equal(cooling.length, 1);
});

test('验证码被限流后冷却，不再立刻登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'refreshed-access', refreshToken: 'refreshed-token' } };
  });
  service.extractClient = async () => {
    logins += 1;
    return {
      ok: false,
      temporary: true,
      code: 'RETRY',
      message: '授权失败：邮箱验证码被限流，请稍后重试',
    };
  };
  const first = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(first.results[0].ok, false);
  assert.equal(first.results[0].code, 'LOGIN_FAILED');
  const second = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  const failed = await f.prisma.redeemLog.findMany({ where: { accountId: account.id, message: 'LOGIN_FAILED' } });
  const cooling = await f.prisma.redeemLog.findMany({ where: { accountId: account.id, message: 'LOGIN_COOLING' } });
  assert.equal(failed.length, 1);
  assert.equal(cooling.length, 1);
});

test('邮箱页验证失败后冷却，不再立刻登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    return { ok: true, credentials: { accessToken: 'refreshed-access', refreshToken: 'refreshed-token' } };
  });
  service.extractClient = async () => {
    logins += 1;
    return {
      ok: false,
      temporary: true,
      code: 'RETRY',
      message: '授权失败：email_otp_verification_failed',
    };
  };
  const first = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(first.results[0].code, 'LOGIN_FAILED');
  const second = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_FAILED' } }), 1);
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_COOLING' } }), 1);
});

test('找回验证码只认六位，不先拿走短数字', () => {
  const { verificationCode } = require('../dist/mailbox/mail-analyzer.service');
  assert.equal(verificationCode({
    subject: 'Your ChatGPT code',
    bodyPreview: 'code 2024. Your verification code is 111111',
  }), '111111');
  assert.equal(verificationCode({
    bodyPreview: 'Your verification code is 2024',
  }), null);
});

test('登录令牌没有邮箱声明但标记一致时仍然落库', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    throw new Error('不应刷新');
  });
  service.extractClient = async () => loginOk(account.email, 'no-email-refresh', {
    accessToken: claimsJwt({ chatgpt_plan_type: 'plus' }),
    idToken: claimsJwt({ chatgpt_plan_type: 'plus' }),
  });
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.deepEqual(refreshes, []);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '已重新登录原卡密账号');
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).refreshToken, 'no-email-refresh');
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_MISMATCH' } }), 0);
});

test('登录令牌没有套餐声明但标记一致时仍然落库', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    throw new Error('不应刷新');
  });
  service.extractClient = async () => loginOk(account.email, 'no-plan-refresh', {
    accessToken: claimsJwt({ email: account.email }),
    idToken: claimsJwt({ email: account.email }),
  });
  const result = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.deepEqual(refreshes, []);
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].message, '已重新登录原卡密账号');
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).refreshToken, 'no-plan-refresh');
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_MISMATCH' } }), 0);
});

test('找回提取接受缺套餐声明，首次提取仍然拒绝', async () => {
  const worker = require('../dist/team/team-worker');
  const client = require('../dist/accounts/extract-client');
  const original = worker.workerPost;
  const missing = claimsJwt({ email: 'a@b.c' });
  const free = claimsJwt({ chatgpt_plan_type: 'free', email: 'a@b.c' });
  const conflict = claimsJwt({ email: 'a@b.c', chatgpt_account_id: 'personal', chatgpt_workspace_id: 'other' });
  const base = {
    email: 'a@b.c',
    password: 'p',
    totp: 'JBSWY3DPEHPK3PXP',
    proxy: 'socks5://127.0.0.1:1080',
    subscriptionTag: 'Plus',
  };
  worker.workerPost = async () => ({ ok: true, accessToken: missing, refreshToken: 'kept-refresh', message: '提取完成' });
  try {
    const kept = await client.postAccountExtract({ ...base, otpPolicy: 'reclaim' });
    assert.equal(kept.ok, true);
    assert.equal(kept.refreshToken, 'kept-refresh');
    const dropped = await client.postAccountExtract(base);
    assert.equal(dropped.ok, false);
    assert.equal(dropped.code, 'PLAN_MISMATCH');
    assert.equal(dropped.refreshToken, undefined);
    worker.workerPost = async () => ({ ok: true, accessToken: free, refreshToken: 'free-refresh', message: '提取完成' });
    const rejected = await client.postAccountExtract({ ...base, otpPolicy: 'reclaim' });
    assert.equal(rejected.ok, false);
    assert.equal(rejected.code, 'PLAN_MISMATCH');
    assert.equal(rejected.refreshToken, undefined);
    worker.workerPost = async () => ({ ok: true, accessToken: conflict, refreshToken: 'conflict-refresh', message: '提取完成' });
    const mismatched = await client.postAccountExtract({ ...base, otpPolicy: 'reclaim' });
    assert.equal(mismatched.ok, false);
    assert.equal(mismatched.code, 'PLAN_MISMATCH');
    assert.equal(mismatched.refreshToken, undefined);
  } finally {
    worker.workerPost = original;
  }
});

test('找回取件换 token 和拉信共用一个截止时间', async () => {
  const { MailboxService } = require('../dist/mailbox/mailbox.service');
  const service = new MailboxService({
    analyzeMessage() { return {}; },
    detectBanned() { return { banned: false, keywords: [] }; },
    extractCredits() { return null; },
  });
  const credential = {
    email: 'a@b.c',
    provider: 'outlook',
    authType: 'oauth',
    password: 'p',
    clientId: 'client',
    refreshToken: 'ms-refresh',
  };
  service.exchangeMsToken = async () => {
    await new Promise((resolve) => setTimeout(resolve, 40));
    return { ok: true, accessToken: 'ms-token', invalidCredential: false };
  };
  let sharedTimeout = 0;
  service.fetchMessages = async (_token, _max, timeoutMs) => {
    sharedTimeout = timeoutMs;
    return { ok: true, messages: [] };
  };
  await service.pickupOne(credential, { timeoutMs: 100, sharedDeadline: true, maxMessages: 1 });
  assert.ok(sharedTimeout > 0 && sharedTimeout < 100, `shared fetch timeout ${sharedTimeout}`);
  let separateTimeout = 0;
  service.fetchMessages = async (_token, _max, timeoutMs) => {
    separateTimeout = timeoutMs;
    return { ok: true, messages: [] };
  };
  await service.pickupOne(credential, { timeoutMs: 100, maxMessages: 1 });
  assert.equal(separateTimeout, 100);
});

test('找回邮箱回调的等待时间盖住取件', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  const { allowReclaimMailbox, releaseReclaimMailbox } = require('../dist/public/reclaim-login');
  allowReclaimMailbox(account.id);
  t.after(() => releaseReclaimMailbox(account.id));
  let seen = null;
  f.mailbox.pickupOne = async (_credential, options) => {
    seen = options;
    return { ok: false, messages: [] };
  };
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  await service.readMailboxOtp({ accountId: account.id, email: account.email, baseline: true });
  assert.equal(seen.maxMessages, 200);
  assert.equal(seen.timeoutMs, 40000);
  assert.equal(seen.sharedDeadline, true);
});

test('登录令牌邮箱和原账号不一致时不落库并冷却', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  let logins = 0;
  const refreshes = [];
  const service = reclaimService(f.prisma, f.mailbox, async (token) => {
    refreshes.push(token);
    throw new Error('不应刷新');
  });
  service.extractClient = async () => {
    logins += 1;
    return loginOk('other@example.com', 'wrong-email-refresh');
  };
  const first = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.deepEqual(refreshes, []);
  assert.equal(first.results[0].ok, false);
  assert.equal(first.results[0].message, '新凭据与原空间不一致，已保留原文件。请联系管理员');
  assert.equal((await f.prisma.account.findUnique({ where: { id: account.id } })).refreshToken, 'synthetic-openai-refresh');
  const second = await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(logins, 1);
  assert.equal(second.results[0].message, '新凭据与原空间不一致，已保留原文件。请联系管理员');
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_MISMATCH' } }), 1);
  assert.equal(await f.prisma.redeemLog.count({ where: { accountId: account.id, message: 'LOGIN_COOLING' } }), 1);
});

test('没有进行中的找回时，内部邮箱回调不返回验证码', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  f.mailbox.pickupOne = async () => ({
    ok: true,
    messages: [{
      id: 'openai',
      from: 'OpenAI <noreply@tm.openai.com>',
      subject: 'Your ChatGPT code',
      bodyPreview: 'Your ChatGPT verification code is 111111',
      receivedDateTime: '2026-04-01T00:00:00.000Z',
    }],
  });
  const { InternalMailboxController } = require('../dist/public/internal-mailbox.controller');
  const { allowReclaimMailbox, releaseReclaimMailbox } = require('../dist/public/reclaim-login');
  const controller = new InternalMailboxController(reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  }));
  const previous = process.env.PROTOCOL_WORKER_TOKEN;
  process.env.PROTOCOL_WORKER_TOKEN = 'worker-token-test';
  try {
    const blocked = await controller.otp({
      accountId: account.id,
      email: account.email,
    }, 'Bearer worker-token-test');
    assert.equal(blocked.ok, false);
    assert.equal(blocked.code, 'MAILBOX_EMPTY');
    assert.equal(JSON.stringify(blocked).includes('111111'), false);
    allowReclaimMailbox(account.id);
    const opened = await controller.otp({
      accountId: account.id,
      email: account.email,
    }, 'Bearer worker-token-test');
    assert.equal(opened.code, '111111');
  } finally {
    releaseReclaimMailbox(account.id);
    process.env.PROTOCOL_WORKER_TOKEN = previous;
  }
});

test('找回取件会跟着下一页把第 51 封之后的邮件取回来', async () => {
  const { MailboxService } = require('../dist/mailbox/mailbox.service');
  const { MailAnalyzerService } = require('../dist/mailbox/mail-analyzer.service');
  const service = new MailboxService(new MailAnalyzerService());
  const original = global.fetch;
  const urls = [];
  global.fetch = async (url) => {
    const text = String(url);
    urls.push(text);
    if (text.includes('login.microsoftonline.com')) {
      return { ok: true, json: async () => ({ access_token: 'ms-access' }), text: async () => '' };
    }
    if (text.includes('skip=50')) {
      return {
        ok: true,
        json: async () => ({
          value: [{
            Id: 'late',
            Subject: 'later',
            From: { EmailAddress: { Name: 'OpenAI', Address: 'noreply@openai.com' } },
            ReceivedDateTime: '2026-04-01T00:00:00.000Z',
            BodyPreview: 'later',
            Body: { Content: '' },
            IsRead: false,
          }],
        }),
        text: async () => '',
      };
    }
    return {
      ok: true,
      json: async () => ({
        value: Array.from({ length: 50 }, (_, index) => ({
          Id: `old-${index}`,
          Subject: 'noise',
          From: { EmailAddress: { Address: 'shop@example.com' } },
          ReceivedDateTime: '2026-04-02T00:00:00.000Z',
          BodyPreview: '',
          Body: { Content: '' },
          IsRead: true,
        })),
        '@odata.nextLink': 'https://outlook.office.com/api/v2.0/me/messages?$skip=50',
      }),
      text: async () => '',
    };
  };
  try {
    const result = await service.pickupOne({
      email: 'reader@example.com',
      provider: 'microsoft',
      authType: 'graph',
      clientId: '00000000-0000-0000-0000-000000000001',
      refreshToken: 'M'.repeat(64),
    }, { maxMessages: 200, timeoutMs: 5000 });
    assert.equal(result.ok, true);
    assert.equal(result.messages.some((item) => item.id === 'late'), true);
    assert.equal(urls.some((item) => item.includes('skip=50')), true);
  } finally {
    global.fetch = original;
  }
});

test('登录超时后协议仍返回成对凭据时不中止', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const loaded = await f.prisma.account.findUnique({ where: { id: account.id }, include: { mailbox: true } });
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  let aborted = false;
  service.extractClient = (_input, signal) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(loginOk(account.email, 'late-refresh')), 80);
    signal.addEventListener('abort', () => {
      aborted = true;
      clearTimeout(timer);
      const error = new Error('This operation was aborted');
      error.name = 'AbortError';
      reject(error);
    });
  });
  const result = await service.reclaimLogin.callLogin(
    loaded,
    { password: 'stored-pass', totp: 'JBSWY3DPEHPK3PXP', proxy: 'socks5://127.0.0.1:1080' },
    'socks5://127.0.0.1:1080',
    () => false,
    20,
    200,
  );
  assert.equal(aborted, false);
  assert.equal(result.ok, true);
  assert.equal(result.refreshToken, 'late-refresh');
});

test('登录超时后没有成对凭据才中止', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const loaded = await f.prisma.account.findUnique({ where: { id: account.id }, include: { mailbox: true } });
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = (_input, signal) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(loginOk(account.email, 'should-not-return')), 500);
    signal.addEventListener('abort', () => {
      clearTimeout(timer);
      const error = new Error('This operation was aborted');
      error.name = 'AbortError';
      reject(error);
    });
  });
  const result = await service.reclaimLogin.callLogin(
    loaded,
    { password: 'stored-pass', totp: 'JBSWY3DPEHPK3PXP', proxy: 'socks5://127.0.0.1:1080' },
    'socks5://127.0.0.1:1080',
    () => false,
    20,
    40,
  );
  assert.equal(result.code, 'ABORTED');
  assert.equal(result.refreshToken, undefined);
});

test('个人号残留 Team 密文时仍用库存密码登录', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: 'Plus' });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const { encryptSecret } = require('../dist/common/secret-box');
  await f.prisma.teamSecret.create({
    data: {
      accountId: account.id,
      passwordCipher: encryptSecret('team-pass'),
      totpCipher: encryptSecret('JBSWY3DPEHPK3PXP'),
    },
  });
  const passwords = [];
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async (input) => {
    passwords.push(input.password);
    return loginOk(account.email, 'notes-refresh');
  };
  const matched = await service.reclaim({
    lines: ['account1@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
  });
  assert.equal(passwords[0], 'stored-pass');
  assert.equal(matched.results[0].ok, true);
  const loaded = await f.prisma.account.findUnique({
    where: { id: account.id },
    include: { mailbox: true, teamSecret: true },
  });
  const direct = [];
  service.extractClient = async (input) => {
    direct.push(input.password);
    return loginOk(account.email, 'direct-refresh');
  };
  const attempt = await service.reclaimLogin.loginOriginalAccount(loaded, () => false);
  assert.equal(direct[0], 'stored-pass');
  assert.equal(attempt.status, 'wrote');
});

test('5X Team 登录使用 Team 密文而不是库存密码', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1, { subscriptionTag: '5X Team', remoteWorkspaceId: 'ws-1' });
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account, { password: 'stored-pass' });
  const { encryptSecret } = require('../dist/common/secret-box');
  await f.prisma.teamSecret.create({
    data: {
      accountId: account.id,
      passwordCipher: encryptSecret('team-pass'),
      totpCipher: encryptSecret('JBSWY3DPEHPK3PXP'),
    },
  });
  const passwords = [];
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  service.extractClient = async (input) => {
    passwords.push(input.password);
    return loginOk(account.email, 'team-refresh');
  };
  await service.reclaim({ cards: [account.cardKey], format: 'sub2api' });
  assert.equal(passwords[0], 'team-pass');
});

test('同一张卡登录窗口用尽时不说代理失败', async (t) => {
  const f = await fixture(t);
  const account = await createAccount(f.prisma, 1);
  await markRedeemed(f.prisma, account);
  await giveLoginMaterials(f.prisma, account);
  const loaded = await f.prisma.account.findUnique({ where: { id: account.id }, include: { mailbox: true } });
  const service = reclaimService(f.prisma, f.mailbox, async () => {
    throw new Error('不应刷新');
  });
  let calls = 0;
  service.reclaimLogin.now = () => {
    calls += 1;
    if (calls === 1) return 1_000_000;
    return 1_700_000;
  };
  service.extractClient = async () => {
    throw new Error('不应登录');
  };
  const attempt = await service.reclaimLogin.loginOriginalAccount(loaded, () => false, 1_700_000);
  assert.equal(attempt.code, 'REQUEST_BUDGET');
  assert.equal(attempt.message, '本次请求时间不足，请稍后单独找回');
  assert.equal(String(attempt.message).includes('代理'), false);
  assert.equal(attempt.logCode, undefined);
});
