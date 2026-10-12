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
  const raw = JSON.parse(account.rawJson);
  assert.equal(JSON.parse(raw.notes).gpt.password, 'secret-pass');
  assert.equal(raw.proxy, undefined);
  assert.equal(calls[0].includes('socks5://'), true);
  assert.equal(String(account.rawJson).includes('socks5://'), false);
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

test('账密对不上不登录，匹配后作废才重登一次', async (t) => {
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

  f.redeem.refresher = { refresh: async () => ({ ok: false, invalidCredential: true, error: 'invalid_grant' }) };
  f.redeem.extractClient = async () => {
    calls += 1;
    return { ok: false, temporary: true, code: 'UPSTREAM', message: '稍后' };
  };
  await f.prisma.extractJob.update({
    where: { id: (await f.prisma.extractJob.findFirst()).id },
    data: {
      passwordCipher: encryptSecret('stored-pass'),
      totpCipher: encryptSecret('JBSWY3DPEHPK3PXP'),
      proxyCipher: encryptSecret('socks5://127.0.0.1:1080'),
    },
  });
  const hit = await f.redeem.reclaim({
    lines: ['buyer@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.11',
  });
  assert.equal(calls, 1);
  assert.equal(hit.results[0].message, '登录暂时失败，请稍后重试');

  await assert.rejects(
    () => f.redeem.reclaim({
      cards: [account.cardKey],
      lines: ['buyer@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
      format: 'sub2api',
    }),
    (error) => {
      assert.equal(error.message, '不能同时提交卡密和账密');
      return true;
    },
  );

  const next = token({ chatgpt_plan_type: 'plus', chatgpt_account_id: 'personal-1' });
  f.redeem.extractClient = async (body) => {
    calls += 1;
    assert.equal(body.password, 'stored-pass');
    assert.equal(body.proxy, 'socks5://127.0.0.1:1080');
    assert.equal(body.workspaceId || '', '');
    return { ok: true, temporary: false, accessToken: next, refreshToken: 'refresh-new' };
  };
  const saved = await f.redeem.reclaim({
    lines: ['buyer@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.12',
  });
  assert.equal(calls, 2);
  assert.equal(saved.results[0].ok, true);
  const delivered = `${saved.results[0].content || ''}\n${saved.mergedContent || ''}`;
  assert.equal(delivered.includes('stored-pass'), false);
  assert.equal(delivered.includes('JBSWY3DPEHPK3PXP'), false);
  assert.equal(delivered.includes('socks5://'), false);
  assert.equal(delivered.includes('refresh-new'), true);
  const row = await f.prisma.account.findUnique({ where: { id: account.id } });
  assert.equal(row.refreshToken, 'refresh-new');
  assert.equal(row.accessToken, next);
  assert.notEqual(row.refreshToken, 'old-refresh');
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
  assert.deepEqual(refreshed, ['old-extra']);
  assert.equal(hit.results[0].ok, true);
  assert.equal(hit.results[0].card, '第1行');
  assert.equal(hit.results[0].accountCount, 1);
  assert.equal(body.includes('CARD-PRIMARY'), false);
  assert.equal(body.includes('CARD-EXTRA'), false);
  assert.equal(body.includes('old-primary'), false);
  assert.equal(body.includes('new-old-extra'), true);
  assert.equal(body.includes('primary@example.com'), false);
  const extraRow = await f.prisma.account.findUnique({ where: { id: extra.id } });
  const primaryRow = await f.prisma.account.findUnique({ where: { id: primary.id } });
  assert.equal(extraRow.refreshToken, 'new-old-extra');
  assert.equal(primaryRow.refreshToken, 'old-primary');

  refreshed.length = 0;
  const byCard = await f.redeem.reclaim({ cards: [primary.cardKey], format: 'sub2api' });
  assert.equal(byCard.results[0].ok, true);
  assert.equal(String(byCard.results[0].content).includes('primary@example.com'), true);
  assert.equal(String(byCard.results[0].content).includes('extra@example.com'), true);
  assert.equal(refreshed.includes('old-primary'), true);
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

test('密码错误后不再登录，也不把账号标成失效', async (t) => {
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
  f.redeem.refresher = { refresh: async () => ({ ok: false, invalidCredential: true, error: 'invalid_grant' }) };
  f.redeem.extractClient = async () => {
    calls += 1;
    return {
      ok: false,
      temporary: false,
      code: 'FAILED',
      message: '授权失败：邮箱或密码不正确｜若你这行里出现超过 4 个连续短横线，请确认密码里是不是真的带 -',
    };
  };
  const first = await f.redeem.reclaim({
    lines: ['buyer@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.50',
  });
  assert.equal(calls, 1);
  assert.equal(first.results[0].message, '凭据已作废，重新登录失败，请联系管理员');
  const job = await f.prisma.extractJob.findFirst({ where: { accountId: account.id } });
  assert.equal(job.code, 'PASSWORD_REJECTED');
  assert.equal(job.status, 'succeeded');
  assert.notEqual((await f.prisma.account.findUnique({ where: { id: account.id } })).banStatus, 'invalid');
  const second = await f.redeem.reclaim({
    lines: ['buyer@example.com----stored-pass----JBSWY3DPEHPK3PXP'],
    format: 'sub2api',
    ip: '203.0.113.51',
  });
  assert.equal(calls, 1);
  assert.equal(second.results[0].message, '凭据已作废，重新登录失败，请联系管理员');
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
  f.mailbox.refreshOpenAiToken = async () => ({
    ok: true,
    accessToken: personal,
    refreshToken: 'rt-personal-refresh',
    expiresAt: new Date(Date.now() + 3600000),
  });
  const rejected = await f.accounts.refreshStatus({ ids: [team.id], targets: ['redeem'] });
  assert.equal(rejected.redeem.failed, 1);
  assert.match(rejected.items[0].error, /订阅标记/);
  const untouched = await f.prisma.account.findUnique({ where: { id: team.id } });
  assert.equal(untouched.accessToken, business);
  assert.equal(untouched.refreshToken, 'rt-team-live');
  assert.equal(untouched.stagedCredential, null);
  assert.notEqual(untouched.banStatus, 'invalid');

  f.mailbox.refreshOpenAiToken = async () => ({
    ok: true,
    accessToken: rotatedBusiness,
    refreshToken: 'rt-team-refreshed',
    expiresAt: new Date(Date.now() + 3600000),
  });
  const accepted = await f.accounts.refreshStatus({ ids: [team.id], targets: ['redeem'] });
  assert.equal(accepted.redeem.failed, 0);
  const refreshed = await f.prisma.account.findUnique({ where: { id: team.id } });
  assert.equal(refreshed.accessToken, rotatedBusiness);
  assert.equal(refreshed.refreshToken, 'rt-team-refreshed');
  assert.equal(refreshed.remoteWorkspaceId, 'ws-team');
});
