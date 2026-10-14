const assert = require('node:assert/strict');
const { test } = require('node:test');
const { randomBytes } = require('node:crypto');

process.env.NODE_ENV = 'test';
process.env.GPTCDK_SECRET = process.env.GPTCDK_SECRET || 'gptcdk-team-test-secret-32chars-min';

const { Logger } = require('@nestjs/common');
const { PrismaClient } = require('@prisma/client');
const { initializeSchema } = require('../dist/prisma/initialize-schema');
const { SCHEMA_STATEMENTS } = require('../dist/prisma/schema-statements');
const { RedeemService } = require('../dist/public/public.service');
const { AccountsService } = require('../dist/accounts/accounts.service');
const { ConvertService } = require('../dist/convert/convert.service');
const { MailboxService } = require('../dist/mailbox/mailbox.service');
const { MailAnalyzerService } = require('../dist/mailbox/mail-analyzer.service');
const { DEFAULT_SETTINGS } = require('../dist/settings/settings.service');
const { runExtractJob } = require('../dist/accounts/extract-runner');
const { encryptSecret } = require('../dist/team/team-crypto');

Logger.overrideLogger(false);
global.fetch = async () => { throw new Error('回归测试禁止外部网络请求'); };

function postgresUrl() {
  const url = process.env.DATABASE_URL || '';
  if (!/^postgres(ql)?:\/\//i.test(url)) throw new Error('DATABASE_URL 必须是 PostgreSQL');
  return url;
}

function urlForSchema(base, schema) {
  const url = new URL(base);
  url.searchParams.set('schema', schema);
  return url.toString();
}

function token(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `e30.${body}.sig`;
}

async function fixture(t) {
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
  await initializeSchema(prisma);
  const settings = { getAll: async () => ({ ...DEFAULT_SETTINGS }) };
  const mailbox = new MailboxService(new MailAnalyzerService());
  const convert = new ConvertService();
  return {
    prisma,
    mailbox,
    accounts: new AccountsService(prisma, convert, mailbox, settings),
    redeem: new RedeemService(prisma, convert, mailbox, settings),
  };
}

test('建表语句包含提取任务表', () => {
  assert.equal(SCHEMA_STATEMENTS.some((item) => item.includes('CREATE TABLE IF NOT EXISTS "ExtractJob"')), true);
  assert.equal(SCHEMA_STATEMENTS.some((item) => item.includes('"updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP')), true);
});

test('账密导入没有代理时不建账号', async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    () => f.accounts.importAccounts({
      content: 'seller@example.com----secret-pass----JBSWY3DPEHPK3PXP',
      remark: '测试批次',
      subscriptionTag: 'Plus',
    }),
    (error) => {
      assert.equal(error.message, '没有可用的 SOCKS 代理');
      return true;
    },
  );
  assert.equal(await f.prisma.account.count(), 0);
  assert.equal(await f.prisma.extractJob.count(), 0);
});

test('账密导入只排队，成功后才发卡且文件不带代理', async (t) => {
  const f = await fixture(t);
  const calls = [];
  f.accounts.extractClient = async (body) => {
    calls.push(body.proxy);
    return {
      ok: true,
      temporary: false,
      accessToken: token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' }),
      refreshToken: 'refresh-1',
      accountId: 'personal-1',
      planType: 'plus',
    };
  };
  const imported = await f.accounts.importAccounts({
    content: 'seller@example.com----secret-pass----JBSWY3DPEHPK3PXP',
    remark: '测试批次',
    subscriptionTag: 'Plus',
    proxy: 'socks5://user:pass@127.0.0.1:1080',
  });
  assert.equal(imported.imported, 0);
  assert.equal(imported.queued, 1);
  assert.equal(await f.prisma.account.count(), 0);
  const job = await f.prisma.extractJob.findFirst();
  await runExtractJob(f.accounts, job.id);
  const account = await f.prisma.account.findFirst();
  assert.equal(account.subscriptionTag, 'Plus');
  assert.equal(account.credits, 0);
  assert.equal(account.remark, '测试批次');
  const raw = JSON.parse(account.rawJson);
  assert.equal(JSON.parse(raw.notes).gpt.password, 'secret-pass');
  assert.equal(raw.proxy, undefined);
  assert.equal(calls[0].includes('socks5://'), true);
  assert.equal(String(account.rawJson).includes('socks5://'), false);
});

test('账号已入库后排队提取不再登录', async (t) => {
  const f = await fixture(t);
  const calls = [];
  f.accounts.extractClient = async (body) => {
    calls.push(body.email);
    return {
      ok: true,
      temporary: false,
      accessToken: token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' }),
      refreshToken: 'rt-from-login',
      accountId: 'personal-1',
      planType: 'plus',
    };
  };
  const queued = await f.accounts.importAccounts({
    content: 'queued@example.com----secret-pass----JBSWY3DPEHPK3PXP',
    remark: '先排队',
    subscriptionTag: 'Plus',
    proxy: 'socks5://127.0.0.1:1080',
  });
  assert.equal(queued.queued, 1);
  const plus = token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' });
  const json = await f.accounts.importAccounts({
    content: JSON.stringify([{ email: 'queued@example.com', access_token: plus, refresh_token: 'rt-json' }]),
    remark: '后入库',
    subscriptionTag: 'Plus',
  });
  assert.equal(json.imported, 1);
  const job = await f.prisma.extractJob.findFirst({ where: { email: 'queued@example.com', status: 'queued' } });
  await runExtractJob(f.accounts, job.id);
  assert.deepEqual(calls, []);
  const saved = await f.prisma.extractJob.findUnique({ where: { id: job.id } });
  assert.equal(saved.status, 'failed');
  assert.equal(saved.code, 'DUPLICATE');
  const account = await f.prisma.account.findFirst({ where: { email: 'queued@example.com' } });
  assert.equal(account.refreshToken, 'rt-json');
  assert.equal(await f.prisma.account.count({ where: { email: 'queued@example.com' } }), 1);
});

test('同一邮箱两个提取任务只登录一次', async (t) => {
  const f = await fixture(t);
  let release = () => undefined;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const calls = [];
  f.accounts.extractClient = async () => {
    calls.push('login');
    await gate;
    return {
      ok: true,
      temporary: false,
      accessToken: token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' }),
      refreshToken: 'rt-from-login',
      accountId: 'personal-1',
      planType: 'plus',
    };
  };
  await f.accounts.importAccounts({
    content: 'race@example.com----secret-pass----JBSWY3DPEHPK3PXP',
    remark: '并发',
    subscriptionTag: 'Plus',
    proxy: 'socks5://127.0.0.1:1080',
  });
  const first = await f.prisma.extractJob.findFirst({ where: { email: 'race@example.com' } });
  const running = runExtractJob(f.accounts, first.id);
  const started = Date.now();
  while (calls.length === 0 && Date.now() - started < 5000) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(calls.length, 1);
  const second = await f.prisma.extractJob.create({
    data: {
      batchId: first.batchId,
      email: first.email,
      subscriptionTag: first.subscriptionTag,
      passwordCipher: first.passwordCipher,
      totpCipher: first.totpCipher,
      proxyCipher: first.proxyCipher,
      status: 'queued',
      keyPrefix: first.keyPrefix,
      keyGroups: first.keyGroups,
      keyLength: first.keyLength,
    },
  });
  const other = runExtractJob(f.accounts, second.id);
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(calls.length, 1);
  release();
  await Promise.all([running, other]);
  assert.equal(calls.length, 1);
  assert.equal(await f.prisma.account.count({ where: { email: 'race@example.com' } }), 1);
  const duplicate = await f.prisma.extractJob.findUnique({ where: { id: second.id } });
  assert.equal(duplicate.status, 'failed');
  assert.equal(duplicate.code, 'DUPLICATE');
  assert.equal((await f.prisma.extractJob.findUnique({ where: { id: first.id } })).status, 'succeeded');
});

test('5X 个人文件不入库', async (t) => {
  const f = await fixture(t);
  f.accounts.extractClient = async () => ({
    ok: true,
    temporary: false,
    accessToken: token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' }),
    refreshToken: 'refresh-1',
    remoteWorkspaceId: 'ws-team',
    planType: 'plus',
  });
  await f.accounts.importAccounts({
    content: 'team@example.com----secret-pass----JBSWY3DPEHPK3PXP',
    remark: '测试批次',
    subscriptionTag: '5X Team',
    proxy: 'socks5://127.0.0.1:1080',
  });
  const job = await f.prisma.extractJob.findFirst();
  await runExtractJob(f.accounts, job.id);
  const saved = await f.prisma.extractJob.findUnique({ where: { id: job.id } });
  assert.equal(saved.status, 'failed');
  assert.equal(saved.failureClass, 'permanent');
  assert.equal(await f.prisma.account.count(), 0);
});

test('账密对不上不登录，对上后没有可用代理也不刷新', async (t) => {
  const f = await fixture(t);
  const access = token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' });
  const account = await f.prisma.account.create({
    data: {
      name: 'buyer@example.com',
      email: 'buyer@example.com',
      credits: 0,
      subscriptionTag: 'Plus',
      accessToken: access,
      refreshToken: 'old-refresh',
      rawSource: 'sub2api',
      rawJson: JSON.stringify({
        email: 'buyer@example.com',
        access_token: access,
        notes: JSON.stringify({ gpt: { password: 'stored-pass' }, two_factor: { secret: 'JBSWY3DPEHPK3PXP' } }),
      }),
      cardKey: 'CARD-TEST-TEST-TEST',
      redeemStatus: 'redeemed',
      redeemedByCard: 'CARD-TEST-TEST-TEST',
      stockKind: 'standard',
      banStatus: 'unknown',
      updatedAt: new Date(),
    },
  });
  await f.prisma.extractJob.create({
    data: {
      batchId: 'batch-test',
      email: account.email,
      subscriptionTag: 'Plus',
      passwordCipher: 'unused',
      totpCipher: 'unused',
      proxyCipher: 'unused',
      status: 'succeeded',
      accountId: account.id,
      updatedAt: new Date(),
    },
  });
  let calls = 0;
  f.redeem.extractClient = async () => {
    calls += 1;
    return { ok: false, temporary: true, code: 'UPSTREAM', message: '稍后' };
  };
  const miss = await f.redeem.reclaim({
    lines: ['buyer@example.com----wrong-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.10',
  });
  assert.equal(calls, 0);
  assert.equal(miss.results[0].message, '找不到对应的已交付账号');
  assert.equal(String(miss.results[0].card).includes('wrong-pass'), false);

  let refreshes = 0;
  f.redeem.refresher = {
    refresh: async () => {
      refreshes += 1;
      return { ok: false, invalidCredential: true, error: 'invalid_grant' };
    },
  };
  f.redeem.extractClient = async () => {
    calls += 1;
    return { ok: false, temporary: true, code: 'UPSTREAM', message: '稍后' };
  };
  await f.prisma.extractJob.update({
    where: { id: (await f.prisma.extractJob.findFirst()).id },
    data: {
      passwordCipher: encryptSecret('stored-pass'),
      totpCipher: encryptSecret('JBSWY3DPEHPK3PXP'),
      proxyCipher: 'unused',
    },
  });
  const hit = await f.redeem.reclaim({
    lines: ['buyer@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.11',
  });
  assert.equal(calls, 0);
  assert.equal(refreshes, 0);
  assert.equal(hit.results[0].ok, false);
  assert.equal(hit.results[0].message, '重新登录缺少可用密码或代理，请联系管理员');
  const kept = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(kept.cardDisabled, false);
  assert.equal(kept.banStatus, 'unknown');
  assert.equal(kept.refreshToken, 'old-refresh');
  assert.equal(kept.accessToken, access);
  assert.equal(JSON.stringify(hit).includes('stored-pass'), false);

  f.redeem.refresher = { refresh: async () => ({ ok: false, invalidCredential: false, error: 'invalid_client' }) };
  const untouched = await f.prisma.account.create({
    data: {
      name: 'other@example.com',
      email: 'other@example.com',
      credits: 0,
      subscriptionTag: 'Plus',
      accessToken: access,
      refreshToken: 'keep-refresh',
      rawSource: 'sub2api',
      rawJson: JSON.stringify({
        email: 'other@example.com',
        access_token: access,
        notes: JSON.stringify({ gpt: { password: 'other-pass' }, two_factor: { secret: 'JBSWY3DPEHPK3PXP' } }),
      }),
      cardKey: 'CARD-OTHER',
      redeemStatus: 'redeemed',
      redeemedByCard: 'CARD-OTHER',
      stockKind: 'standard',
      banStatus: 'unknown',
      updatedAt: new Date(),
    },
  });
  const rejected = await f.redeem.reclaim({
    lines: ['other@example.com----other-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.12',
  });
  assert.equal(calls, 0);
  assert.equal(rejected.results[0].ok, false);
  const other = await f.prisma.account.findUnique({ where: { id: untouched.id } });
  assert.equal(other.cardDisabled, false);
  assert.equal(other.banStatus, 'unknown');
  assert.equal(other.refreshToken, 'keep-refresh');
});

test('凭据找回只恢复对上的那一条，且不交出卡密', async (t) => {
  const f = await fixture(t);
  const plus = token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' });
  const primary = await f.prisma.account.create({
    data: {
      name: 'primary@example.com',
      email: 'primary@example.com',
      credits: 0,
      subscriptionTag: 'Plus',
      accessToken: plus,
      refreshToken: 'old-primary',
      rawSource: 'sub2api',
      rawJson: JSON.stringify({ email: 'primary@example.com', access_token: plus }),
      cardKey: 'CARD-PRIMARY',
      redeemStatus: 'redeemed',
      redeemedByCard: 'CARD-PRIMARY',
      stockKind: 'standard',
      banStatus: 'unknown',
      updatedAt: new Date(),
    },
  });
  const extra = await f.prisma.account.create({
    data: {
      name: 'extra@example.com',
      email: 'extra@example.com',
      credits: 0,
      subscriptionTag: 'Plus',
      accessToken: plus,
      refreshToken: 'old-extra',
      rawSource: 'sub2api',
      rawJson: JSON.stringify({
        email: 'extra@example.com',
        access_token: plus,
        notes: JSON.stringify({ gpt: { password: 'extra-pass' }, two_factor: { secret: 'JBSWY3DPEHPK3PXP' } }),
      }),
      cardKey: 'CARD-EXTRA',
      redeemStatus: 'redeemed',
      redeemedByCard: primary.cardKey,
      stockKind: 'standard',
      banStatus: 'unknown',
      updatedAt: new Date(),
    },
  });
  const refreshed = [];
  f.redeem.refresher = {
    refresh: async (current) => {
      refreshed.push(current);
      return {
        ok: true,
        credentials: {
          accessToken: token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' }),
          refreshToken: `new-${current}`,
        },
      };
    },
  };
  const hit = await f.redeem.reclaim({
    lines: ['extra@example.com----extra-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.40',
  });
  const body = JSON.stringify(hit);
  assert.deepEqual(refreshed, []);
  assert.equal(hit.results[0].ok, false);
  assert.equal(hit.results[0].card, '第1行');
  assert.equal(hit.results[0].message, '重新登录缺少可用密码或代理，请联系管理员');
  assert.equal(body.includes('CARD-PRIMARY'), false);
  assert.equal(body.includes('CARD-EXTRA'), false);
  assert.equal(body.includes('old-primary'), false);
  assert.equal(body.includes('new-old-extra'), false);
  assert.equal(body.includes('primary@example.com'), false);
  const extraRow = await f.prisma.account.findUnique({ where: { id: extra.id } });
  const primaryRow = await f.prisma.account.findUnique({ where: { id: primary.id } });
  assert.equal(extraRow.refreshToken, 'old-extra');
  assert.equal(primaryRow.refreshToken, 'old-primary');

  refreshed.length = 0;
  const byCard = await f.redeem.reclaim({ cards: [primary.cardKey], format: 'sub2api' });
  assert.equal(byCard.results[0].ok, true);
  assert.equal(String(byCard.results[0].content).includes('primary@example.com'), true);
  assert.equal(String(byCard.results[0].content).includes('extra@example.com'), false);
  assert.equal(refreshed.includes('old-primary'), true);
  assert.equal(refreshed.includes('old-extra'), false);
  assert.equal(refreshed.includes('new-old-extra'), false);
});

test('5X Team 不能靠标记卖出个人文件', async (t) => {
  const f = await fixture(t);
  const personal = token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' });
  const business = token({ chatgpt_plan_type: 'self_serve_business_prolite', chatgpt_account_id: 'ws-team' });
  const missingPlan = token({ chatgpt_account_id: 'personal-2' });
  const imported = await f.accounts.importAccounts({
    content: JSON.stringify([
      { email: 'bad-team@example.com', access_token: personal, refresh_token: 'rt-bad' },
      { email: 'good-team@example.com', access_token: business, refresh_token: 'rt-good' },
    ]),
    remark: '测试批次',
    subscriptionTag: '5X Team',
  });
  assert.equal(imported.imported, 1);
  assert.equal(imported.failed, 1);
  assert.equal(await f.prisma.account.count({ where: { email: 'bad-team@example.com' } }), 0);
  const saved = await f.prisma.account.findFirst({ where: { email: 'good-team@example.com' } });
  assert.equal(saved.remoteWorkspaceId, 'ws-team');
  assert.equal(saved.planType, 'self_serve_business_prolite');
  assert.equal(saved.subscriptionTag, '5X Team');

  const plusImport = await f.accounts.importAccounts({
    content: JSON.stringify([{ email: 'bare@example.com', access_token: missingPlan, refresh_token: 'rt-bare' }]),
    remark: '测试批次',
    subscriptionTag: 'Plus',
  });
  assert.equal(plusImport.imported, 0);
  assert.equal(plusImport.failed, 1);

  const tagged = await f.prisma.account.create({
    data: {
      name: 'sold-personal@example.com',
      email: 'sold-personal@example.com',
      credits: 0,
      subscriptionTag: '5X Team',
      accessToken: personal,
      refreshToken: 'old-personal',
      rawSource: 'sub2api',
      rawJson: JSON.stringify({ email: 'sold-personal@example.com', access_token: personal }),
      cardKey: 'CARD-BAD-TEAM',
      redeemStatus: 'unredeemed',
      stockKind: 'standard',
      banStatus: 'unknown',
      updatedAt: new Date(),
    },
  });
  const redeemed = await f.redeem.redeem({ cards: [tagged.cardKey], format: 'sub2api' });
  assert.equal(redeemed.results[0].ok, false);
  assert.equal(redeemed.results[0].code, 'PLAN_MISMATCH');
  const kept = await f.prisma.account.findUnique({ where: { id: tagged.id } });
  assert.equal(kept.redeemStatus, 'unredeemed');
  assert.equal(kept.redeemedByCard, null);
  assert.equal(kept.accessToken, personal);

  await assert.rejects(
    () => f.accounts.retag({ ids: [tagged.id], subscriptionTag: '5X Team' }),
    (error) => {
      assert.match(error.message, /空间 token/);
      return true;
    },
  );
  assert.equal((await f.prisma.account.findUnique({ where: { id: tagged.id } })).remoteWorkspaceId, null);
});


test('入库后找回登录一次，不刷新且不停用', async (t) => {
  const f = await fixture(t);
  const access = token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1', email: 'buyer@example.com' });
  const refreshedAccess = token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1', email: 'buyer@example.com' });
  const account = await f.prisma.account.create({
    data: {
      name: 'buyer@example.com',
      email: 'buyer@example.com',
      credits: 0,
      subscriptionTag: 'Plus',
      accessToken: access,
      refreshToken: 'old-refresh',
      rawSource: 'sub2api',
      rawJson: JSON.stringify({
        email: 'buyer@example.com',
        access_token: access,
        notes: JSON.stringify({ gpt: { password: 'stored-pass' }, two_factor: { secret: 'JBSWY3DPEHPK3PXP' } }),
      }),
      cardKey: 'CARD-PASSWORD',
      redeemStatus: 'redeemed',
      redeemedByCard: 'CARD-PASSWORD',
      stockKind: 'standard',
      banStatus: 'unknown',
      updatedAt: new Date(),
    },
  });
  await f.prisma.extractJob.create({
    data: {
      batchId: 'batch-password',
      email: account.email,
      subscriptionTag: 'Plus',
      passwordCipher: encryptSecret('stored-pass'),
      totpCipher: encryptSecret('JBSWY3DPEHPK3PXP'),
      proxyCipher: encryptSecret('socks5://127.0.0.1:1080'),
      status: 'succeeded',
      accountId: account.id,
      updatedAt: new Date(),
    },
  });
  let calls = 0;
  let refreshes = 0;
  f.redeem.refresher = {
    refresh: async (value) => {
      refreshes += 1;
      assert.equal(value, 'old-refresh');
      return {
        ok: true,
        credentials: {
          accessToken: refreshedAccess,
          refreshToken: 'rotated-refresh',
          idToken: refreshedAccess,
        },
      };
    },
  };
  f.redeem.extractClient = async (input) => {
    calls += 1;
    assert.equal(input.password, 'stored-pass');
    assert.equal(input.otpPolicy, 'reclaim');
    assert.equal(input.mailboxAccountId, undefined);
    return {
      ok: true,
      accessToken: token({ chatgpt_plan_type: 'plus', email: 'buyer@example.com' }),
      refreshToken: 'login-refresh',
      idToken: token({ chatgpt_plan_type: 'plus', email: 'buyer@example.com' }),
    };
  };
  const first = await f.redeem.reclaim({
    lines: ['buyer@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.50',
  });
  assert.equal(calls, 1);
  assert.equal(refreshes, 0);
  assert.equal(first.results[0].ok, true);
  assert.equal(first.results[0].message, '已重新登录原卡密账号');
  const job = await f.prisma.extractJob.findFirst({ where: { accountId: account.id } });
  assert.equal(job.status, 'succeeded');
  const saved = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(saved.cardDisabled, false);
  assert.equal(saved.banStatus, 'unknown');
  assert.equal(saved.refreshToken, 'login-refresh');
  const second = await f.redeem.reclaim({
    lines: ['buyer@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.51',
  });
  assert.equal(calls, 1);
  assert.equal(refreshes, 0);
  assert.equal(second.results[0].ok, true);
  assert.equal(second.results[0].message, '凭据已重新登录过，本次没有再次登录');
});

test('缺套餐和限流分类在入库前就被拦住', () => {
  const { classifyLoginFailure, personalPlanAllowed, acceptExtractResult } = require('../dist/common/subscription');
  assert.equal(classifyLoginFailure('mfa_totp_rejected_429', '授权失败：mfa_totp_rejected_429').temporary, true);
  assert.equal(classifyLoginFailure('mfa_totp_code_unavailable', '授权失败：mfa_totp_code_unavailable').temporary, false);
  assert.equal(personalPlanAllowed({}), false);
  const rejected = acceptExtractResult('5X Team', {
    ok: true,
    accessToken: token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' }),
    refreshToken: 'rt',
    remoteWorkspaceId: null,
  });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.code, 'PLAN_MISMATCH');
});

function stagedCredential(accessToken, refreshToken, previousRefreshToken) {
  return JSON.stringify({
    accessToken,
    refreshToken,
    idToken: null,
    expiresAt: null,
    previousRefreshToken,
  });
}

test('对上的暂存仍可交付，对不上的不能兑换、导出或覆盖', async (t) => {
  const f = await fixture(t);
  const business = token({ chatgpt_plan_type: 'self_serve_business_prolite', chatgpt_account_id: 'ws-team' });
  const personal = token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' });
  const plus = token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'plus-1' });
  const rotatedBusiness = token({ chatgpt_plan_type: 'self_serve_business_prolite', chatgpt_account_id: 'ws-team', jti: 'rotated' });
  const team = await f.prisma.account.create({
    data: {
      name: 'team-staged@example.com',
      email: 'team-staged@example.com',
      credits: 0,
      subscriptionTag: '5X Team',
      planType: 'self_serve_business_prolite',
      remoteWorkspaceId: 'ws-team',
      accessToken: business,
      refreshToken: 'rt-team',
      rawSource: 'sub2api',
      rawJson: JSON.stringify({ email: 'team-staged@example.com' }),
      cardKey: 'CARD-TEAM-STAGED',
      redeemStatus: 'redeemed',
      redeemedByCard: 'CARD-TEAM-STAGED',
      redeemedAt: new Date('2026-01-01T00:00:00Z'),
      stockKind: 'standard',
      banStatus: 'unknown',
      stagedCredential: stagedCredential(personal, 'rt-personal', 'rt-team'),
      updatedAt: new Date(),
    },
  });
  const redeemed = await f.redeem.redeem({ cards: [team.cardKey], format: 'sub2api' });
  assert.equal(redeemed.results[0].ok, true);
  assert.equal(String(redeemed.results[0].content).includes(business), true);
  assert.equal(String(redeemed.results[0].content).includes(personal), false);
  assert.equal(String(redeemed.results[0].content).includes('rt-personal'), false);
  const kept = await f.prisma.account.findUnique({ where: { id: team.id } });
  assert.equal(kept.accessToken, business);
  assert.equal(kept.refreshToken, 'rt-team');
  assert.equal(kept.stagedCredential, null);
  assert.notEqual(kept.banStatus, 'invalid');

  await f.prisma.account.update({
    where: { id: team.id },
    data: { stagedCredential: stagedCredential(personal, 'rt-personal-export', 'rt-team') },
  });
  const exported = await f.accounts.exportAccounts({ ids: [team.id], format: 'sub2api' });
  assert.equal(String(exported.content).includes(business), true);
  assert.equal(String(exported.content).includes(personal), false);
  assert.equal(String(exported.content).includes('rt-personal-export'), false);
  const afterExport = await f.prisma.account.findUnique({ where: { id: team.id } });
  assert.equal(afterExport.accessToken, business);
  assert.equal(afterExport.refreshToken, 'rt-team');
  assert.equal(afterExport.stagedCredential, null);

  const plusAccount = await f.prisma.account.create({
    data: {
      name: 'plus-staged@example.com',
      email: 'plus-staged@example.com',
      credits: 20,
      subscriptionTag: 'Plus',
      planType: 'plus',
      accessToken: plus,
      refreshToken: 'rt-plus',
      rawSource: 'sub2api',
      rawJson: JSON.stringify({ email: 'plus-staged@example.com' }),
      cardKey: 'CARD-PLUS-STAGED',
      redeemStatus: 'redeemed',
      redeemedByCard: 'CARD-PLUS-STAGED',
      redeemedAt: new Date('2026-01-01T00:00:00Z'),
      stockKind: 'standard',
      banStatus: 'unknown',
      stagedCredential: stagedCredential(business, 'rt-business-staged', 'rt-plus'),
      updatedAt: new Date(),
    },
  });
  const plusRedeem = await f.redeem.redeem({ cards: [plusAccount.cardKey], format: 'cpa' });
  assert.equal(plusRedeem.results[0].ok, true);
  assert.equal(String(plusRedeem.results[0].content).includes(plus), true);
  assert.equal(String(plusRedeem.results[0].content).includes(business), false);
  const plusKept = await f.prisma.account.findUnique({ where: { id: plusAccount.id } });
  assert.equal(plusKept.accessToken, plus);
  assert.equal(plusKept.refreshToken, 'rt-plus');
  assert.equal(plusKept.stagedCredential, null);

  await f.prisma.account.update({
    where: { id: team.id },
    data: {
      stagedCredential: stagedCredential(rotatedBusiness, 'rt-team-next', 'rt-team'),
    },
  });
  const matched = await f.redeem.redeem({ cards: [team.cardKey], format: 'sub2api' });
  assert.equal(matched.results[0].ok, true);
  assert.equal(String(matched.results[0].content).includes(rotatedBusiness), true);
  assert.equal(String(matched.results[0].content).includes('rt-team-next'), true);
  const rotated = await f.prisma.account.findUnique({ where: { id: team.id } });
  assert.equal(rotated.accessToken, rotatedBusiness);
  assert.equal(rotated.refreshToken, 'rt-team-next');
  assert.equal(rotated.remoteWorkspaceId, 'ws-team');
  assert.equal(rotated.stagedCredential, null);

  await f.prisma.account.update({
    where: { id: team.id },
    data: { expiresAt: new Date(0), accessToken: business, refreshToken: 'rt-team-live' },
  });
  let openAiCalls = 0;
  f.mailbox.refreshOpenAiToken = async () => {
    openAiCalls += 1;
    return {
      ok: true,
      accessToken: personal,
      refreshToken: 'rt-personal-refresh',
      expiresAt: new Date(Date.now() + 3600000),
    };
  };
  const rejected = await f.accounts.refreshStatus({ ids: [team.id], targets: ['redeem'] });
  assert.equal(openAiCalls, 0);
  assert.equal(rejected.redeem.failed, 1);
  assert.equal(rejected.items[0].error, '已兑换账号不在后台轮换凭据');
  const untouched = await f.prisma.account.findUnique({ where: { id: team.id } });
  assert.equal(untouched.accessToken, business);
  assert.equal(untouched.refreshToken, 'rt-team-live');
  assert.equal(untouched.stagedCredential, null);
  assert.notEqual(untouched.banStatus, 'invalid');

  const unsold = await f.prisma.account.create({
    data: {
      name: 'team-unsold@example.com',
      email: 'team-unsold@example.com',
      credits: 0,
      subscriptionTag: '5X Team',
      planType: 'self_serve_business_prolite',
      remoteWorkspaceId: 'ws-team',
      accessToken: business,
      refreshToken: 'rt-unsold',
      rawSource: 'sub2api',
      rawJson: JSON.stringify({ email: 'team-unsold@example.com' }),
      cardKey: 'CARD-TEAM-UNSOLD',
      redeemStatus: 'unredeemed',
      stockKind: 'standard',
      banStatus: 'unknown',
      expiresAt: new Date(0),
      updatedAt: new Date(),
    },
  });
  const tagRejected = await f.accounts.refreshStatus({ ids: [unsold.id], targets: ['redeem'] });
  assert.equal(tagRejected.redeem.failed, 1);
  assert.match(tagRejected.items[0].error, /订阅标记/);
  const unsoldKept = await f.prisma.account.findUnique({ where: { id: unsold.id } });
  assert.equal(unsoldKept.accessToken, business);
  assert.equal(unsoldKept.refreshToken, 'rt-unsold');
  assert.notEqual(unsoldKept.banStatus, 'invalid');

  f.mailbox.refreshOpenAiToken = async () => ({
    ok: true,
    accessToken: rotatedBusiness,
    refreshToken: 'rt-team-refreshed',
    expiresAt: new Date(Date.now() + 3600000),
  });
  const accepted = await f.accounts.refreshStatus({ ids: [unsold.id], targets: ['redeem'] });
  assert.equal(accepted.redeem.failed, 0);
  const refreshed = await f.prisma.account.findUnique({ where: { id: unsold.id } });
  assert.equal(refreshed.accessToken, rotatedBusiness);
  assert.equal(refreshed.refreshToken, 'rt-team-refreshed');
  assert.equal(refreshed.remoteWorkspaceId, 'ws-team');
  const soldStill = await f.prisma.account.findUnique({ where: { id: team.id } });
  assert.equal(soldStill.refreshToken, 'rt-team-live');
});

test('停用、Team、已成功提取和密码失败不再登录', async (t) => {
  const f = await fixture(t);
  const calls = [];
  f.accounts.extractClient = async (body) => {
    calls.push(body.email);
    throw new Error('不应登录');
  };
  await f.prisma.account.create({
    data: {
      name: 'disabled@example.com',
      email: 'disabled@example.com',
      credits: 0,
      cardKey: 'CARD-DISABLED-LOGIN',
      cardDisabled: true,
      stockKind: 'standard',
      banStatus: 'invalid',
      accessToken: 'kept',
      refreshToken: 'rt-disabled',
    },
  });
  await f.prisma.account.create({
    data: {
      name: 'team@example.com',
      email: 'team@example.com',
      credits: 0,
      cardKey: 'CARD-TEAM-LOGIN',
      stockKind: 'team',
      accessToken: 'kept',
      refreshToken: 'rt-team',
    },
  });
  const loginLine = (email, remark) => f.accounts.importAccounts({
    content: `${email}----secret-pass----JBSWY3DPEHPK3PXP`,
    remark,
    subscriptionTag: 'Plus',
    proxy: 'socks5://127.0.0.1:1080',
  });
  const disabled = await loginLine('disabled@example.com', '停用后再提取');
  const team = await loginLine('team@example.com', 'Team 后再提取');
  assert.equal(disabled.queued, 0);
  assert.equal(team.queued, 0);
  assert.match(disabled.errors.map((item) => item.reason).join(' '), /邮箱已在库/);
  assert.deepEqual(calls, []);

  const tombstone = await loginLine('gone@example.com', '成功后删除');
  assert.equal(tombstone.queued, 1);
  await f.prisma.extractJob.update({
    where: { id: tombstone.jobs[0].id },
    data: { status: 'succeeded', accountId: null },
  });
  const again = await loginLine('gone@example.com', '删除后重提');
  assert.equal(again.queued, 0);
  await runExtractJob(f.accounts, tombstone.jobs[0].id);
  assert.deepEqual(calls, []);
  assert.equal((await f.prisma.extractJob.findUnique({ where: { id: tombstone.jobs[0].id } })).status, 'succeeded');

  const failed = await loginLine('badpass@example.com', '密码已失败');
  await f.prisma.extractJob.update({
    where: { id: failed.jobs[0].id },
    data: { status: 'failed', failureClass: 'permanent', code: 'invalid_username_or_password', message: '密码错误' },
  });
  const retry = await loginLine('badpass@example.com', '密码失败后再提取');
  assert.equal(retry.queued, 0);
  assert.match(retry.errors.map((item) => item.reason).join(' '), /密码登录已失败/);
  await runExtractJob(f.accounts, failed.jobs[0].id);
  assert.deepEqual(calls, []);
});

test('更早的密码失败不会被 50 条新失败盖住', async (t) => {
  const f = await fixture(t);
  const calls = [];
  f.accounts.extractClient = async () => {
    calls.push('login');
    throw new Error('不应登录');
  };
  const old = await f.prisma.extractJob.create({
    data: {
      batchId: 'old-password',
      email: 'hidden-pass@example.com',
      subscriptionTag: 'Plus',
      passwordCipher: 'stocked',
      totpCipher: 'stocked',
      proxyCipher: 'stocked',
      status: 'failed',
      failureClass: 'permanent',
      code: 'FAILED',
      message: '密码不正确',
    },
  });
  for (let index = 0; index < 50; index += 1) {
    await f.prisma.extractJob.create({
      data: {
        batchId: 'newer-retry',
        email: 'hidden-pass@example.com',
        subscriptionTag: 'Plus',
        passwordCipher: 'stocked',
        totpCipher: 'stocked',
        proxyCipher: 'stocked',
        status: 'failed',
        failureClass: 'temporary',
        code: 'RETRY',
        message: '稍后重试',
      },
    });
  }
  const retry = await f.accounts.importAccounts({
    content: 'hidden-pass@example.com----secret-pass----JBSWY3DPEHPK3PXP',
    remark: '旧密码失败后再提取',
    subscriptionTag: 'Plus',
    proxy: 'socks5://127.0.0.1:1080',
  });
  assert.equal(retry.queued, 0);
  assert.match(retry.errors.map((item) => item.reason).join(' '), /密码登录已失败/);
  await runExtractJob(f.accounts, old.id);
  assert.deepEqual(calls, []);
});

test('JSON 导入删除后不能再密码登录', async (t) => {
  const f = await fixture(t);
  const calls = [];
  f.accounts.extractClient = async () => {
    calls.push('login');
    throw new Error('不应登录');
  };
  const imported = await f.accounts.importAccounts({
    content: JSON.stringify([{
      email: 'json-gone@example.com',
      access_token: token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' }),
      refresh_token: 'rt-json',
    }]),
    remark: 'JSON 入库',
    subscriptionTag: 'Plus',
  });
  assert.equal(imported.imported, 1);
  const account = await f.prisma.account.findFirst({ where: { email: 'json-gone@example.com' } });
  const stocked = await f.prisma.extractJob.findFirst({ where: { email: 'json-gone@example.com', code: 'STOCKED' } });
  assert.equal(stocked.status, 'succeeded');
  assert.equal(stocked.passwordCipher, 'stocked');
  const listed = await f.accounts.listExtractJobs();
  assert.equal(listed.items.some((item) => item.code === 'STOCKED'), false);
  await f.accounts.batchDelete([account.id], false);
  assert.equal(await f.prisma.account.count({ where: { email: 'json-gone@example.com' } }), 0);
  const again = await f.accounts.importAccounts({
    content: 'json-gone@example.com----secret-pass----JBSWY3DPEHPK3PXP',
    remark: '删除后重提',
    subscriptionTag: 'Plus',
    proxy: 'socks5://127.0.0.1:1080',
  });
  assert.equal(again.queued, 0);
  assert.match(again.errors.map((item) => item.reason).join(' '), /邮箱已在库或提取队列中/);
  const forced = await f.prisma.extractJob.create({
    data: {
      batchId: 'forced',
      email: 'json-gone@example.com',
      subscriptionTag: 'Plus',
      passwordCipher: 'stocked',
      totpCipher: 'stocked',
      proxyCipher: 'stocked',
      status: 'queued',
    },
  });
  await runExtractJob(f.accounts, forced.id);
  assert.deepEqual(calls, []);
  assert.equal((await f.prisma.extractJob.findUnique({ where: { id: forced.id } })).code, 'DUPLICATE');
});
