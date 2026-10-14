const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const { randomBytes } = require('node:crypto');

process.env.NODE_ENV = 'test';
process.env.GPTCDK_SECRET = 'gptcdk-team-test-secret-32chars-min';

const { PrismaClient } = require('@prisma/client');
const { initializeSchema } = require('../dist/prisma/initialize-schema');
const { RedeemService } = require('../dist/public/public.service');
const { ConvertService } = require('../dist/convert/convert.service');
const { MailboxService } = require('../dist/mailbox/mailbox.service');
const { MailAnalyzerService } = require('../dist/mailbox/mail-analyzer.service');
const { DEFAULT_SETTINGS } = require('../dist/settings/settings.service');
const { encryptSecret } = require('../dist/team/team-crypto');
const { parseTeamLine, resolveSocks, normalizeSocks } = require('../dist/team/team-rules');

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
  return {
    prisma,
    redeem: new RedeemService(prisma, new ConvertService(), new MailboxService(new MailAnalyzerService()), settings),
  };
}

async function teamAccount(prisma, cardKey, extra = {}) {
  const account = await prisma.account.create({
    data: {
      name: '子号',
      email: 'kid@example.com',
      credits: 0,
      cardKey,
      accessToken: extra.accessToken || 'pending-token',
      stockKind: 'team',
      teamStatus: extra.teamStatus || 'waiting',
      rawSource: 'sub2api',
      rawJson: extra.rawJson || null,
      updatedAt: new Date(),
    },
  });
  if (extra.secret !== false) {
    await prisma.teamSecret.create({
      data: {
        accountId: account.id,
        passwordCipher: encryptSecret('chatgpt-pass'),
        totpCipher: encryptSecret('JBSWY3DPEHPK3PXP'),
      },
    });
  }
  return account;
}

test('四列取件凭据不能加入，六列只取邮箱、ChatGPT 密码和 2FA', () => {
  const rejected = parseTeamLine('mail@example.com----mailbox-pass----client----refresh');
  assert.equal(rejected.ok, false);
  assert.match(rejected.message, /取件凭据/);
  const parsed = parseTeamLine('kid@example.com----ignore----ignore----ignore----chatgpt-pass----JBSWY3DPEHPK3PXP');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.line.password, 'chatgpt-pass');
  assert.equal(parsed.line.totp, 'JBSWY3DPEHPK3PXP');
});

test('代理只接受 SOCKS，空值不能当成直连', () => {
  assert.equal(resolveSocks('socks5://child', 'socks5://mother', 'socks5://global'), 'socks5://child');
  assert.equal(resolveSocks('', '', null), null);
  assert.throws(() => normalizeSocks('http://127.0.0.1:8080'), /只接受 SOCKS/);
  assert.throws(() => normalizeSocks(''), /没有可用的 SOCKS/);
});

test('已保存的 Team 账密可以兑换和重复导出，文件未生成不能下文件', async (t) => {
  const { prisma, redeem } = await fixture(t);
  await prisma.account.create({
    data: { name: '普通', credits: 0, cardKey: 'CARD-STD0', accessToken: 'std', stockKind: 'standard', updatedAt: new Date() },
  });
  assert.equal((await redeem.redeem({ cards: ['CARD-STD0'], format: 'sub2api' })).results[0].code, 'CREDITS_PENDING');

  const card = 'CARD-TEAM-LOGIN';
  await teamAccount(prisma, card);
  const file = await redeem.redeem({ cards: [card], format: 'sub2api' });
  assert.equal(file.results[0].message, '文件还没生成');
  assert.equal((await prisma.account.findUnique({ where: { cardKey: card } })).redeemStatus, 'unredeemed');

  const login = await redeem.redeem({ cards: [card], format: 'login' });
  assert.equal(login.results[0].ok, true);
  assert.equal(login.results[0].content, 'kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP\n');
  const again = await redeem.redeem({ cards: [card], format: 'login' });
  assert.equal(again.results[0].ok, true);
  assert.equal(again.results[0].content, login.results[0].content);
});

test('封禁或失效的 Team 卡找回不输出账密和文件', async (t) => {
  const { prisma, redeem } = await fixture(t);
  const card = 'CARD-TEAM-BANNED';
  await teamAccount(prisma, card);
  assert.equal((await redeem.redeem({ cards: [card], format: 'login' })).results[0].ok, true);

  await prisma.account.update({ where: { cardKey: card }, data: { banStatus: 'banned' } });
  const banned = await redeem.reclaim({ cards: [card], format: 'login' });
  assert.equal(banned.results[0].ok, false);
  assert.equal(banned.results[0].code, 'NO_STOCK');
  assert.equal(JSON.stringify(banned).includes('chatgpt-pass'), false);

  await prisma.account.update({ where: { cardKey: card }, data: { banStatus: 'invalid' } });
  const invalid = await redeem.reclaim({ cards: [card], format: 'login' });
  assert.equal(invalid.results[0].code, 'NO_STOCK');
  assert.equal(JSON.stringify(invalid).includes('chatgpt-pass'), false);

  await prisma.account.update({
    where: { cardKey: card },
    data: {
      banStatus: 'banned',
      teamStatus: 'file_ready',
      accessToken: 'child-at',
      rawJson: JSON.stringify({ access_token: 'child-at' }),
    },
  });
  const file = await redeem.reclaim({ cards: [card], format: 'sub2api' });
  assert.equal(file.results[0].code, 'NO_STOCK');
  assert.equal(JSON.stringify(file).includes('child-at'), false);
  assert.equal(JSON.stringify(file).includes('chatgpt-pass'), false);
});

test('公开文件兑换不含密码、2FA 和 session', async (t) => {
  const { prisma, redeem } = await fixture(t);
  await prisma.account.create({
    data: {
      name: '子号',
      email: 'kid@example.com',
      credits: 0,
      cardKey: 'CARD-FILE',
      accessToken: 'child-at',
      stockKind: 'team',
      teamStatus: 'file_ready',
      rawSource: 'sub2api',
      updatedAt: new Date(),
      rawJson: JSON.stringify({ accessToken: 'child-at', password: 'secret-pass', totp: 'secret-2fa', session: 'secret-session' }),
    },
  });
  const result = await redeem.redeem({ cards: ['CARD-FILE'], format: 'sub2api' });
  const text = JSON.stringify(result);
  assert.equal(result.results[0].ok, true);
  assert.equal(text.includes('secret-pass'), false);
  assert.equal(text.includes('secret-2fa'), false);
  assert.equal(text.includes('secret-session'), false);
});

test('密钥缺失时公开兑换和找回都停用，不泄露内部异常', async (t) => {
  const { prisma, redeem } = await fixture(t);
  const card = 'CARD-SECRET';
  await teamAccount(prisma, card);
  const previous = process.env.GPTCDK_SECRET;
  delete process.env.GPTCDK_SECRET;
  try {
    const result = await redeem.redeem({ cards: [card], format: 'login' });
    assert.equal(result.results[0].code, 'TEAM_DISABLED');
    assert.equal(result.results[0].message, 'GPTCDK_SECRET 缺失或短于 32 字符，Team 功能已停用');
    assert.equal((await prisma.account.findUnique({ where: { cardKey: card } })).redeemStatus, 'unredeemed');

    await prisma.account.update({
      where: { cardKey: card },
      data: {
        redeemStatus: 'redeemed',
        redeemedByCard: card,
        teamStatus: 'file_ready',
        accessToken: 'child-at',
        rawJson: JSON.stringify({ accessToken: 'child-at' }),
      },
    });
    const again = await redeem.reclaim({ cards: [card], format: 'sub2api' });
    assert.equal(again.results[0].code, 'TEAM_DISABLED');
    assert.equal(again.results[0].message, 'GPTCDK_SECRET 缺失或短于 32 字符，Team 功能已停用');
  } finally {
    process.env.GPTCDK_SECRET = previous;
  }
});

test('5x Team 管理入口和协议邀请接口已移除，认证提取仍保留', () => {
  assert.throws(() => require('../dist/team/team.service'));
  assert.throws(() => require('../dist/team/team.controller'));
  const protocol = readFileSync(require('node:path').join(__dirname, '../../../services/protocol/internal_server.py'), 'utf8');
  assert.equal(protocol.includes('"/internal/account/extract"'), true);
  assert.equal(protocol.includes('"/internal/session/inspect"'), true);
  for (const route of ['snapshot', 'invite', 'onboard', 'usage', 'kick', 'revoke']) {
    assert.equal(protocol.includes(`"/internal/team/${route}"`), false);
  }
});
