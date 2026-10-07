const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { test } = require('node:test');
const { randomBytes } = require('node:crypto');

process.env.NODE_ENV = 'test';
process.env.GPTCDK_SECRET = 'gptcdk-team-test-secret-32chars-min';
process.env.PROTOCOL_WORKER_TOKEN = 'team-test-token';

const { PrismaClient } = require('@prisma/client');
const { initializeSchema } = require('../dist/prisma/initialize-schema');
const { RedeemService } = require('../dist/public/public.service');
const { AccountsService } = require('../dist/accounts/accounts.service');
const { ConvertService } = require('../dist/convert/convert.service');
const { MailboxService } = require('../dist/mailbox/mailbox.service');
const { MailAnalyzerService } = require('../dist/mailbox/mail-analyzer.service');
const { DEFAULT_SETTINGS } = require('../dist/settings/settings.service');
const { TeamService } = require('../dist/team/team.service');
const { countedMembers, parseTeamLine, resolveSocks, normalizeSocks } = require('../dist/team/team-rules');

const calls = [];
let route = () => ({ ok: true });
let workerUrl = '';

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

function errorText(error) {
  const body = typeof error.getResponse === 'function' ? error.getResponse() : null;
  if (body && typeof body === 'object') return String(body.message || '');
  return String(error.message || error);
}

function errorDetails(error) {
  const body = typeof error.getResponse === 'function' ? error.getResponse() : null;
  return body && typeof body === 'object' ? body.details : undefined;
}

function sessionFor(email) {
  return JSON.stringify({ accessToken: `token-${email}`, email });
}

async function listen() {
  if (workerUrl) return;
  await new Promise((resolve) => {
    const server = createServer((req, res) => {
      let raw = '';
      req.on('data', (chunk) => { raw += chunk; });
      req.on('end', () => {
        const body = raw ? JSON.parse(raw) : {};
        calls.push({ path: req.url, body, authorization: req.headers.authorization });
        Promise.resolve(route(req.url, body)).then((payload) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify(payload));
        }).catch((error) => {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: false, message: String(error.message || error) }));
        });
      });
    });
    server.listen(0, '127.0.0.1', () => {
      workerUrl = `http://127.0.0.1:${server.address().port}`;
      process.env.PROTOCOL_WORKER_URL = workerUrl;
      server.unref();
      resolve();
    });
  });
}

async function fixture(t) {
  await listen();
  calls.length = 0;
  route = () => ({ ok: true });
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
  const settings = { getAll: async () => ({ ...DEFAULT_SETTINGS, teamGlobalSocksProxy: '' }) };
  return {
    prisma,
    team: new TeamService(prisma, settings),
    redeem: new RedeemService(prisma, new ConvertService(), new MailboxService(new MailAnalyzerService()), settings),
  };
}

async function mother(team, email = 'mother@example.com', workspaceId = 'ws-1') {
  route = (path) => path.includes('inspect')
    ? { ok: true, email, workspaces: [{ id: workspaceId, name: 'Team', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  const created = await team.createWorkspace({ session: sessionFor(email), socks: 'socks5://127.0.0.1:1080' });
  calls.length = 0;
  return created;
}

function members(extra = []) {
  return [{ id: 'owner', email: 'mother@example.com', role: 'account-owner' }, ...extra];
}

test('四列取件凭据不能加入，六列只取邮箱、ChatGPT 密码和 2FA', () => {
  const rejected = parseTeamLine('mail@example.com----mailbox-pass----client----refresh');
  assert.equal(rejected.ok, false);
  assert.match(rejected.message, /取件凭据/);
  const emptyThird = parseTeamLine('user@mail.com----mailpass---- ----JBSWY3DPEHPK3PXP');
  assert.equal(emptyThird.ok, false);
  assert.match(emptyThird.message, /取件凭据/);
  const parsed = parseTeamLine('kid@example.com----ignore----ignore----ignore----chatgpt-pass----JBSWY3DPEHPK3PXP');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.line.password, 'chatgpt-pass');
  assert.equal(parsed.line.totp, 'JBSWY3DPEHPK3PXP');
});

test('代理按子号、母号、全局取值，空值和 HTTP 代理都停止', () => {
  assert.equal(resolveSocks('socks5://child', 'socks5://mother', 'socks5://global'), 'socks5://child');
  assert.equal(resolveSocks('', 'socks5://mother', 'socks5://global'), 'socks5://mother');
  assert.equal(resolveSocks('', '', null), null);
  assert.throws(() => normalizeSocks('http://127.0.0.1:8080'), /只接受 SOCKS/);
  assert.throws(() => normalizeSocks(''), /没有可用的 SOCKS/);
});

test('三列导入立刻生成等待卡密，列表不返回 session 和密码', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  assert.equal(imported.created.length, 1);
  assert.match(imported.created[0].cardKey, /^CARD-/);
  const listed = JSON.stringify(await team.listWorkspaces());
  assert.equal(listed.includes('chatgpt-pass'), false);
  assert.equal(listed.includes('token-mother'), false);
  const revealed = await team.revealSession(created.id);
  assert.match(revealed.session, /token-mother/);
  const child = await team.listWaiting();
  const secret = await team.revealChild(child.items[0].id);
  assert.equal(secret.password, 'chatgpt-pass');
  assert.equal(JSON.stringify(await team.listMembers()).includes('chatgpt-pass'), false);
});

test('新 session 邮箱不一致时不能保存', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  await assert.rejects(
    () => team.updateWorkspace(created.id, { session: sessionFor('other@example.com') }),
    (error) => /邮箱和已绑定母号不一致/.test(errorText(error)),
  );
});

test('快照不完整或没有空位时不发送邀请', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: false, seatsEntitled: 5, members: members() }
    : { ok: true };
  const incomplete = await team.assign(created.id);
  assert.match(incomplete.results[0].message, /不完整/);
  assert.equal(calls.some((item) => item.path.includes('invite')), false);
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 1, members: members(), total: 1 }
    : { ok: true };
  const full = await team.assign(created.id);
  assert.match(full.results[0].message, /没有空位/);
  assert.equal(calls.some((item) => item.path.includes('invite')), false);
});

test('邀请返回错误邮箱不算加入，快照没有该邮箱不写文件', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 };
    if (path.includes('invite')) return { ok: true, successes: ['kid@example.com'], errored: ['kid@example.com'] };
    return { ok: true, raw: { password: 'should-not-save' } };
  };
  await team.assign(created.id);
  const errored = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  assert.equal(errored.teamStatus, 'waiting');
  assert.equal(calls.some((item) => item.path.includes('onboard')), false);

  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 };
    if (path.includes('invite')) return { ok: true, successes: ['kid@example.com'], errored: [] };
    if (path.includes('onboard')) return { ok: true, accessToken: 'child-at', raw: { password: 'should-not-save', accessToken: 'child-at' } };
    return { ok: true };
  };
  await assert.rejects(() => team.assign(created.id), (error) => /上车后快照里没有这个邮箱/.test(errorText(error)));
  const missing = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  assert.equal(missing.rawJson, null);
  assert.notEqual(missing.teamStatus, 'file_ready');
});

test('普通额度 0 仍待定，Team 额度 0 可下账密，文件未生成时不能下文件', async (t) => {
  const { prisma, team, redeem } = await fixture(t);
  await prisma.account.create({
    data: { name: '普通', credits: 0, cardKey: 'CARD-STD0', accessToken: 'std', stockKind: 'standard', updatedAt: new Date() },
  });
  const pending = await redeem.redeem({ cards: ['CARD-STD0'], format: 'sub2api' });
  assert.equal(pending.results[0].code, 'CREDITS_PENDING');
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const card = imported.created[0].cardKey;
  const file = await redeem.redeem({ cards: [card], format: 'sub2api' });
  assert.equal(file.results[0].message, '文件还没生成');
  const afterFile = await prisma.account.findUnique({ where: { cardKey: card } });
  assert.equal(afterFile.redeemStatus, 'unredeemed');
  assert.equal(afterFile.redeemedByCard, null);
  await assert.rejects(
    () => redeem.redeem({ cards: [card], format: 'email' }),
    (error) => /不支持邮箱 TXT/.test(errorText(error)),
  );
  const afterEmail = await prisma.account.findUnique({ where: { cardKey: card } });
  assert.equal(afterEmail.redeemStatus, 'unredeemed');
  const login = await redeem.redeem({ cards: [card], format: 'login' });
  assert.equal(login.results[0].ok, true);
  assert.equal(login.results[0].content, 'kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP\n');
  assert.equal(login.mergedContent, login.results[0].content);
});

test('封禁或失效的 Team 卡找回不输出账密和文件', async (t) => {
  const { prisma, team, redeem } = await fixture(t);
  const imported = await team.importChildren('banned-team@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const card = imported.created[0].cardKey;
  const first = await redeem.redeem({ cards: [card], format: 'login' });
  assert.equal(first.results[0].ok, true);

  await prisma.account.update({ where: { cardKey: card }, data: { banStatus: 'banned' } });
  const again = await redeem.redeem({ cards: [card], format: 'login' });
  assert.equal(again.results[0].ok, false);
  assert.equal(again.results[0].code, 'NO_STOCK');
  assert.equal(JSON.stringify(again).includes('chatgpt-pass'), false);

  const banned = await redeem.reclaim({ cards: [card], format: 'login' });
  assert.equal(banned.results[0].ok, false);
  assert.equal(banned.results[0].code, 'NO_STOCK');
  assert.equal(banned.results[0].message, '交付账号已封禁或凭据失效，请联系管理员');
  assert.equal(JSON.stringify(banned).includes('chatgpt-pass'), false);

  await prisma.account.update({ where: { cardKey: card }, data: { banStatus: 'invalid' } });
  const invalid = await redeem.reclaim({ cards: [card], format: 'login' });
  assert.equal(invalid.results[0].ok, false);
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
  assert.equal(file.results[0].ok, false);
  assert.equal(file.results[0].code, 'NO_STOCK');
  assert.equal(JSON.stringify(file).includes('child-at'), false);
  assert.equal(JSON.stringify(file).includes('chatgpt-pass'), false);
});

test('公开文件兑换不含密码、2FA 和 session', async (t) => {
  const { prisma, redeem } = await fixture(t);
  await prisma.account.create({
    data: {
      name: '子号', email: 'kid@example.com', credits: 0, cardKey: 'CARD-FILE', accessToken: 'child-at',
      stockKind: 'team', teamStatus: 'file_ready', rawSource: 'sub2api', updatedAt: new Date(),
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

test('人还在快照里不删除；确认离开后卡密保留但账密删除', async (t) => {
  const { prisma, team, redeem } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'child-user', teamStatus: 'file_ready', redeemStatus: 'redeemed' },
  });
  let kicks = 0;
  route = (path) => {
    if (path.includes('kick')) {
      kicks += 1;
      return { ok: true };
    }
    if (path.includes('snapshot')) {
      const extra = kicks >= 2 ? [] : [{ id: 'child-user', email: 'kid@example.com', role: 'standard-user' }];
      return { ok: true, complete: true, seatsEntitled: 5, members: members(extra), total: 1 + extra.length };
    }
    return { ok: true };
  };
  await team.kickOne(child.id);
  const still = await prisma.teamSecret.findUnique({ where: { accountId: child.id } });
  assert.ok(still);
  await team.kickOne(child.id);
  const wiped = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(wiped.teamStatus, 'kicked');
  assert.equal(wiped.cardKey, imported.created[0].cardKey);
  assert.equal(await prisma.teamSecret.findUnique({ where: { accountId: wiped.id } }), null);
  const kicked = await redeem.redeem({ cards: [wiped.cardKey], format: 'login' });
  assert.equal(kicked.results[0].message, '该账号已被踢出空间');
});

test('已经不在完整名单里的子号，再次踢出会补删账密和文件', async (t) => {
  const { prisma, team, redeem } = await fixture(t);
  const created = await mother(team);
  const other = await mother(team, 'other-mother@example.com', 'ws-2');
  const goneImport = await team.importChildren('gone@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const stayImport = await team.importChildren('stay@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const otherImport = await team.importChildren('other@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const gone = await prisma.account.findUnique({ where: { cardKey: goneImport.created[0].cardKey } });
  const stay = await prisma.account.findUnique({ where: { cardKey: stayImport.created[0].cardKey } });
  const foreign = await prisma.account.findUnique({ where: { cardKey: otherImport.created[0].cardKey } });
  await prisma.account.update({
    where: { id: gone.id },
    data: {
      workspaceId: created.id, userId: 'gone-user', teamStatus: 'file_ready', redeemStatus: 'redeemed',
      accessToken: 'gone-at', rawJson: JSON.stringify({ access_token: 'gone-at' }),
    },
  });
  await prisma.account.update({
    where: { id: stay.id },
    data: { workspaceId: created.id, userId: 'stay-user', teamStatus: 'file_ready', accessToken: 'stay-at' },
  });
  await prisma.account.update({
    where: { id: foreign.id },
    data: { workspaceId: other.id, userId: 'other-user', teamStatus: 'file_ready', accessToken: 'other-at' },
  });
  await prisma.teamUsage.create({ data: { accountId: gone.id, status: 'probed' } });
  route = (path) => {
    if (path.includes('snapshot')) {
      return {
        ok: true,
        complete: true,
        seatsEntitled: 5,
        members: members([{ id: 'stay-user', email: 'stay@example.com', role: 'standard-user' }]),
        total: 2,
      };
    }
    return { ok: true };
  };
  await team.kickOne(gone.id);
  const wiped = await prisma.account.findUnique({ where: { id: gone.id } });
  assert.equal(wiped.teamStatus, 'kicked');
  assert.equal(wiped.cardKey, goneImport.created[0].cardKey);
  assert.equal(wiped.accessToken, '');
  assert.equal(wiped.rawJson, null);
  assert.equal(wiped.email, null);
  assert.equal(await prisma.teamSecret.findUnique({ where: { accountId: gone.id } }), null);
  assert.equal(await prisma.teamUsage.findUnique({ where: { accountId: gone.id } }), null);
  const file = await redeem.redeem({ cards: [wiped.cardKey], format: 'sub2api' });
  assert.equal(file.results[0].message, '该账号已被踢出空间');
  const kept = await prisma.account.findUnique({ where: { id: stay.id } });
  assert.equal(kept.teamStatus, 'file_ready');
  assert.equal(await prisma.teamSecret.findUnique({ where: { accountId: stay.id } }) == null, false);
  const untouched = await prisma.account.findUnique({ where: { id: foreign.id } });
  assert.equal(untouched.teamStatus, 'file_ready');
  assert.equal(calls.some((item) => item.path.includes('kick')), false);
});

test('退出全部只踢当前空间的子号，不踢母号和其他空间', async (t) => {
  const { prisma, team } = await fixture(t);
  const first = await mother(team, 'mother@example.com', 'ws-1');
  const second = await mother(team, 'other-mother@example.com', 'ws-2');
  const local = await team.importChildren('local@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const other = await team.importChildren('other@example.com----other-pass----JBSWY3DPEHPK3PXP');
  const localRow = await prisma.account.findUnique({ where: { cardKey: local.created[0].cardKey } });
  const otherRow = await prisma.account.findUnique({ where: { cardKey: other.created[0].cardKey } });
  await prisma.account.update({ where: { id: localRow.id }, data: { workspaceId: first.id, userId: 'local-user', teamStatus: 'file_ready' } });
  await prisma.account.update({ where: { id: otherRow.id }, data: { workspaceId: second.id, userId: 'other-user', teamStatus: 'file_ready' } });
  route = (path, body) => {
    if (path.includes('snapshot')) {
      const extra = body.workspaceId === 'ws-2'
        ? [{ id: 'other-user', email: 'other@example.com', role: 'standard-user' }]
        : [{ id: 'local-user', email: 'local@example.com', role: 'standard-user' }];
      return { ok: true, complete: true, seatsEntitled: 5, members: members(extra), total: 1 + extra.length };
    }
    if (path.includes('kick')) return { ok: true };
    return { ok: true };
  };
  const preview = await team.previewKickAll(first.id);
  assert.deepEqual(preview.userIds, ['local-user']);
  await team.kickAll(first.id, '退出全部', preview.userIds);
  const kickedIds = calls.filter((item) => item.path.includes('kick')).map((item) => item.body.userId);
  assert.deepEqual(kickedIds, ['local-user']);
  const otherSecret = await team.revealChild(otherRow.id);
  assert.equal(otherSecret.password, 'other-pass');
});

test('子号、母号、全局都没有代理时不直连', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await prisma.teamWorkspace.update({ where: { id: created.id }, data: { socksCipher: null } });
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = () => ({ ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 });
  await assert.rejects(() => team.assign(created.id), (error) => /SOCKS/.test(errorText(error)));
  assert.equal(calls.some((item) => item.path.includes('invite')), false);
});

test('没有新 session 时不能改空间编号', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await assert.rejects(
    () => team.updateWorkspace(created.id, { workspaceId: 'ws-other' }),
    (error) => /不能悄悄换成另一个空间/.test(errorText(error)),
  );
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.openaiWorkspaceId, 'ws-1');
  assert.equal(calls.some((item) => item.path.includes('inspect')), false);
});

test('添加母号没填代理时使用全局 SOCKS，但不把全局代理写进母号', async (t) => {
  const { prisma } = await fixture(t);
  const settings = { getAll: async () => ({ ...DEFAULT_SETTINGS, teamGlobalSocksProxy: 'socks5://10.0.0.8:1080' }) };
  const team = new TeamService(prisma, settings);
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'mother@example.com', workspaces: [{ id: 'ws-1', name: 'Team', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  const created = await team.createWorkspace({ session: sessionFor('mother@example.com') });
  const inspect = calls.find((item) => item.path.includes('inspect'));
  assert.equal(inspect.body.proxy, 'socks5://10.0.0.8:1080');
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.socksCipher, null);
});

test('撤回失败时本地仍保持已邀请', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, teamStatus: 'invited' },
  });
  route = (path) => {
    if (path.includes('snapshot')) {
      return { ok: true, complete: true, seatsEntitled: 5, members: members(), invites: [{ email: 'kid@example.com' }], total: 1 };
    }
    if (path.includes('revoke')) return { ok: false, message: '上游拒绝撤回' };
    return { ok: true };
  };
  await team.revokeInvites(created.id);
  const kept = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(kept.teamStatus, 'invited');
  assert.equal(kept.workspaceId, created.id);
});

test('上车文件写入空间账号编号，邮箱格式不能合成取件行', async (t) => {
  const { prisma, team, redeem } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const card = imported.created[0].cardKey;
  route = (path) => {
    if (path.includes('snapshot')) {
      return {
        ok: true,
        complete: true,
        seatsEntitled: 5,
        total: 2,
        members: members([{ id: 'user-9', email: 'kid@example.com', role: 'standard-user' }]),
      };
    }
    if (path.includes('invite')) return { ok: true, successes: ['kid@example.com'], errored: [] };
    if (path.includes('onboard')) {
      return {
        ok: true,
        accessToken: 'workspace-at',
        refreshToken: 'workspace-rt',
        accountId: 'ws-team',
        userId: 'user-9',
        planType: 'team',
        expiresAt: '2026-10-01T00:00:00.000Z',
        raw: { credentials: { chatgpt_account_id: 'ws-team', access_token: 'workspace-at' }, password: 'should-not-save' },
      };
    }
    return { ok: true };
  };
  await team.assign(created.id);
  const child = await prisma.account.findUnique({ where: { cardKey: card } });
  assert.equal(child.teamStatus, 'file_ready');
  assert.equal(child.accountId, 'ws-team');
  assert.equal(child.planType, 'team');
  const file = await redeem.redeem({ cards: [card], format: 'sub2api' });
  assert.equal(file.results[0].ok, true);
  assert.match(file.results[0].content, /ws-team/);
  assert.equal(JSON.stringify(file).includes('should-not-save'), false);
  await assert.rejects(
    () => redeem.redeem({ cards: [card], format: 'email' }),
    (error) => /不支持邮箱 TXT/.test(errorText(error)),
  );
  const afterEmail = await prisma.account.findUnique({ where: { cardKey: card } });
  assert.equal(afterEmail.redeemStatus, 'redeemed');
});

test('踢人优先用子号代理，并在没有本地编号时按邮箱清掉账密', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await team.updateChildProxy(child.id, 'socks5://10.1.1.1:1080');
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: null, teamStatus: 'file_ready', email: 'kid@example.com' },
  });
  let kicks = 0;
  route = (path) => {
    if (path.includes('kick')) {
      kicks += 1;
      return { ok: true };
    }
    if (path.includes('snapshot')) {
      const extra = kicks >= 1 ? [] : [{ id: 'remote-user', email: 'kid@example.com', role: 'standard-user' }];
      return { ok: true, complete: true, seatsEntitled: 5, members: members(extra), total: 1 + extra.length };
    }
    return { ok: true };
  };
  const preview = await team.previewKickAll(created.id);
  await team.kickAll(created.id, '退出全部', preview.userIds);
  const kick = calls.find((item) => item.path.includes('kick'));
  assert.equal(kick.body.proxy, 'socks5://10.1.1.1:1080');
  assert.equal(kick.body.password, 'chatgpt-pass');
  assert.match(kick.body.session, /token-mother/);
  const wiped = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(wiped.teamStatus, 'kicked');
  assert.equal(await prisma.teamSecret.findUnique({ where: { accountId: child.id } }), null);
});

test('同一母号的任务在执行期间不会再开一个', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  let release = () => {};
  const gate = new Promise((resolve) => { release = resolve; });
  let entered = false;
  route = async (path) => {
    if (path.includes('snapshot')) {
      entered = true;
      await gate;
      return { ok: true, complete: false, seatsEntitled: 5, members: members(), total: 1 };
    }
    return { ok: true };
  };
  const first = team.assign(created.id);
  for (let i = 0; i < 50 && !entered; i += 1) await new Promise((resolve) => setTimeout(resolve, 20));
  await assert.rejects(() => team.assign(created.id), (error) => /已有任务在跑/.test(errorText(error)));
  release();
  await first;
  assert.equal(calls.filter((item) => item.path.includes('invite')).length, 0);
});

test('任务锁在执行期间占住，不会因为旧记录超时再开一个', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const schemaRows = await prisma.$queryRaw`SELECT current_schema() AS schema`;
  const schema = schemaRows[0].schema;
  const { Client } = require('pg');
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();
  try {
    await client.query(`SET search_path TO "${String(schema).replace(/"/g, '""')}"`);
    const held = await client.query('SELECT pg_try_advisory_lock(hashtext(current_schema()), hashtext($1)) AS locked', ['ws:ws-1']);
    assert.equal(held.rows[0].locked, true);
    await prisma.teamJob.create({
      data: {
        workspaceRowId: created.id,
        kind: 'assign',
        status: 'running',
        message: '旧任务',
        createdAt: new Date(Date.now() - 16 * 60 * 1000),
      },
    });
    route = () => ({ ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1, successes: ['kid@example.com'], errored: [] });
    await assert.rejects(() => team.assign(created.id), (error) => /已有任务在跑/.test(errorText(error)));
    assert.equal(calls.some((item) => item.path.includes('invite')), false);
  } finally {
    await client.query('SELECT pg_advisory_unlock(hashtext(current_schema()), hashtext($1))', ['ws:ws-1']);
    await client.end();
  }
});

test('上游限流不能记成额度用尽，没有空间编号不能标文件就绪', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  const { encryptSecret } = require('../dist/team/team-crypto');
  await prisma.teamSecret.update({
    where: { accountId: child.id },
    data: { tokenCipher: encryptSecret(JSON.stringify({ accessToken: 'child-at' })) },
  });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, teamStatus: 'file_ready', email: 'kid@example.com' },
  });
  route = (path) => {
    if (path.includes('usage')) return { ok: true, code: 'RATE_LIMITED', httpStatus: 429, usageStatus: 'exhausted', pct7d: 100 };
    if (path.includes('snapshot')) {
      return {
        ok: true,
        complete: true,
        seatsEntitled: 5,
        total: 2,
        members: members([{ id: 'user-9', email: 'kid@example.com', role: 'standard-user' }]),
      };
    }
    if (path.includes('onboard')) return { ok: true, accessToken: 'workspace-at', raw: { credentials: {} } };
    return { ok: true, successes: ['kid@example.com'], errored: [] };
  };
  await team.probe(created.id);
  const listed = await team.listMembers(created.id);
  assert.equal(listed.items[0].usage.label, '未探测');
  await prisma.account.update({ where: { id: child.id }, data: { teamStatus: 'invited' } });
  await assert.rejects(() => team.assign(created.id), (error) => /没有可用文件/.test(errorText(error)));
  const kept = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(kept.teamStatus, 'invited');
  assert.equal(kept.accountId, null);
  const job = await prisma.teamJob.findFirst({ where: { workspaceRowId: created.id, kind: 'assign' }, orderBy: { id: 'desc' } });
  assert.equal(job.status, 'failed');
});

test('只有短时 token 的母号会标明不能自动续期', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  const listed = await team.listWorkspaces();
  const row = listed.items.find((item) => item.id === created.id);
  assert.equal(row.canAutoRenew, false);
});

test('可回放 cookie 和 sessionToken 都能自动续期，refresh token 不行', async (t) => {
  const { team } = await fixture(t);
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'live@example.com', workspaces: [{ id: 'ws-live', name: 'Team', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  const living = await team.createWorkspace({
    session: JSON.stringify({
      accessToken: 'at',
      sessionToken: 'sess-live',
      cookies: [{ name: 'oai-did', value: 'cookie-1' }],
      email: 'live@example.com',
    }),
    socks: 'socks5://127.0.0.1:1080',
  });
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'token@example.com', workspaces: [{ id: 'ws-token', name: 'Team', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  const tokenOnly = await team.createWorkspace({
    session: JSON.stringify({ accessToken: 'at', sessionToken: 'sess-only', email: 'token@example.com' }),
    socks: 'socks5://127.0.0.1:1080',
  });
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'refresh@example.com', workspaces: [{ id: 'ws-refresh', name: 'Team', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  const refreshOnly = await team.createWorkspace({
    session: JSON.stringify({ accessToken: 'at', refreshToken: 'rt-only', email: 'refresh@example.com' }),
    socks: 'socks5://127.0.0.1:1080',
  });
  const listed = await team.listWorkspaces();
  assert.equal(listed.items.find((item) => item.id === living.id).canAutoRenew, true);
  assert.equal(listed.items.find((item) => item.id === tokenOnly.id).canAutoRenew, true);
  assert.equal(listed.items.find((item) => item.id === refreshOnly.id).canAutoRenew, false);
});

test('人已经在名单里但上车失败时记为已加入，下次成功再写文件', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { teamStatus: 'invited', workspaceId: created.id },
  });
  const snapshot = {
    ok: true,
    complete: true,
    seatsEntitled: 5,
    total: 2,
    members: members([{ id: 'user-9', email: 'kid@example.com', role: 'standard-user' }]),
  };
  route = (path) => {
    if (path.includes('onboard')) return { ok: false, code: 'AUTH', message: '加入空间失败' };
    if (path.includes('snapshot')) return snapshot;
    return { ok: true };
  };
  await team.assign(created.id);
  const joined = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(joined.teamStatus, 'joined');
  assert.equal(joined.userId, 'user-9');
  assert.equal(joined.rawJson, null);
  route = (path) => {
    if (path.includes('onboard')) {
      return {
        ok: true,
        accessToken: 'workspace-at',
        accountId: 'ws-1',
        userId: 'user-9',
        raw: { credentials: { chatgpt_account_id: 'ws-1' } },
      };
    }
    if (path.includes('snapshot')) return snapshot;
    return { ok: true };
  };
  await team.assign(created.id);
  const ready = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(ready.teamStatus, 'file_ready');
  assert.equal(ready.accountId, 'ws-1');
});

test('撤回邀请按邮箱忽略大小写', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { email: 'Kid@Example.com', teamStatus: 'invited', workspaceId: created.id },
  });
  route = (path) => {
    if (path.includes('snapshot')) {
      return { ok: true, complete: true, seatsEntitled: 5, members: members(), invites: [{ email: 'kid@example.com' }] };
    }
    if (path.includes('revoke')) return { ok: true };
    return { ok: true };
  };
  await team.revokeInvites(created.id);
  const after = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(after.teamStatus, 'waiting');
  assert.equal(after.workspaceId, null);
});

test('母号不在名单里也占一个席位', () => {
  assert.equal(countedMembers([{ email: 'kid@example.com' }], 'mother@example.com'), 2);
  assert.equal(countedMembers([{ email: 'Mother@Example.com' }], 'mother@example.com'), 1);
});

test('原空间消失且没有重新选择时不能悄悄换绑', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const before = await team.revealSession(created.id);
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'mother@example.com', workspaces: [{ id: 'ws-only', name: 'Only', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  await assert.rejects(
    () => team.updateWorkspace(created.id, { session: JSON.stringify({ accessToken: 'new-at', email: 'mother@example.com' }) }),
    (error) => /请选择空间后再保存/.test(errorText(error)),
  );
  const kept = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(kept.openaiWorkspaceId, 'ws-1');
  const revealed = await team.revealSession(created.id);
  assert.equal(revealed.session, before.session);
  assert.doesNotMatch(revealed.session, /new-at/);
  await team.updateWorkspace(created.id, {
    session: JSON.stringify({ accessToken: 'new-at', email: 'mother@example.com' }),
    workspaceId: 'ws-only',
  });
  const switched = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(switched.openaiWorkspaceId, 'ws-only');
});

test('名单漏了母号时按多占一席，不再发送邀请', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 2, members: [{ id: 'child', email: 'kid@example.com', role: 'standard-user' }], total: 1 }
    : { ok: true };
  const full = await team.assign(created.id);
  assert.match(full.results[0].message, /没有空位/);
  assert.equal(calls.some((item) => item.path.includes('invite')), false);
});

test('邀请请求失败不进入 10 分钟冷却，任务仍记为失败', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 };
    if (path.includes('invite')) return { ok: false, message: '邀请被拒绝' };
    return { ok: true };
  };
  await assert.rejects(() => team.assign(created.id), (error) => /邀请被拒绝/.test(errorText(error)));
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.lastInviteAt, null);
  const job = await prisma.teamJob.findFirst({ where: { workspaceRowId: created.id, kind: 'assign' }, orderBy: { id: 'desc' } });
  assert.equal(job.status, 'failed');
  assert.match(job.message, /邀请被拒绝/);
  const child = await prisma.account.findFirst({ where: { email: 'kid@example.com' } });
  assert.equal(child.teamStatus, 'waiting');
  assert.equal(child.workspaceId, null);
});

test('复核快照不完整时任务失败且不删账密', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'child-user', teamStatus: 'file_ready', redeemStatus: 'redeemed' },
  });
  let snaps = 0;
  route = (path) => {
    if (path.includes('kick')) return { ok: true };
    if (path.includes('snapshot')) {
      snaps += 1;
      if (snaps === 1) {
        return { ok: true, complete: true, members: members([{ id: 'child-user', email: 'kid@example.com', role: 'standard-user' }]), total: 2 };
      }
      return { ok: true, complete: false, members: [], total: null };
    }
    return { ok: true };
  };
  await assert.rejects(() => team.kickOne(child.id), (error) => /复核快照不完整/.test(errorText(error)));
  const secret = await prisma.teamSecret.findUnique({ where: { accountId: child.id } });
  assert.ok(secret);
  const kept = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(kept.teamStatus, 'file_ready');
  const job = await prisma.teamJob.findFirst({ where: { workspaceRowId: created.id, kind: 'kick' }, orderBy: { id: 'desc' } });
  assert.equal(job.status, 'failed');
  assert.match(job.message, /复核快照不完整/);
});

function unsignedJwt(payload) {
  return `eyJhbGciOiJub25lIn0.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.sig`;
}

test('两个母号不能同时邀请同一个等待子号', async (t) => {
  const { prisma, team } = await fixture(t);
  const first = await mother(team, 'mother-a@example.com', 'ws-a');
  const second = await mother(team, 'mother-b@example.com', 'ws-b');
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  let invites = 0;
  route = (path, body) => {
    if (path.includes('snapshot')) {
      return { ok: true, complete: true, seatsEntitled: 5, members: [{ id: 'owner', email: 'someone@example.com', role: 'account-owner' }], total: 1 };
    }
    if (path.includes('invite')) {
      invites += 1;
      const emails = (body.emails || []).map((item) => String(item).toLowerCase());
      return new Promise((resolve) => setTimeout(() => resolve({ ok: true, successes: emails, errored: [] }), 250));
    }
    if (path.includes('onboard')) return { ok: false, message: '先不测上车' };
    return { ok: true };
  };
  await Promise.allSettled([team.assign(first.id), team.assign(second.id)]);
  assert.equal(invites, 1);
  const child = await prisma.account.findFirst({ where: { email: 'kid@example.com' } });
  assert.equal(child.teamStatus, 'invited');
  assert.ok(child.workspaceId === first.id || child.workspaceId === second.id);
  const otherId = child.workspaceId === first.id ? second.id : first.id;
  const other = await prisma.account.count({ where: { workspaceId: otherId, email: 'kid@example.com' } });
  assert.equal(other, 0);
});

test('席位已满时已经成功的邀请仍记为已邀请', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('ok@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP\nfull@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 };
    if (path.includes('invite')) {
      return { ok: true, successes: ['ok@example.com'], errored: ['full@example.com'], seatFull: true, message: '席位已满，已停止邀请' };
    }
    if (path.includes('onboard')) return { ok: false, message: '先不测上车' };
    return { ok: true };
  };
  await assert.rejects(() => team.assign(created.id), (error) => /席位已满|上车没有成功/.test(errorText(error)));
  const ok = await prisma.account.findFirst({ where: { email: 'ok@example.com' } });
  assert.equal(ok.teamStatus, 'invited');
  assert.equal(ok.workspaceId, created.id);
  const full = await prisma.account.findFirst({ where: { email: 'full@example.com' } });
  assert.equal(full.teamStatus, 'waiting');
  assert.equal(full.workspaceId, null);
});

test('公式仍有空位的超卖满员会停住，成员减少后才再邀请', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('one@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP\ntwo@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  let opened = false;
  let invites = 0;
  route = (path) => {
    if (path.includes('snapshot')) {
      const extra = opened ? [] : [
        { id: 'guest-1', email: 'guest1@example.com', role: 'standard-user' },
        { id: 'guest-2', email: 'guest2@example.com', role: 'standard-user' },
      ];
      return { ok: true, complete: true, seatsEntitled: 5, members: members(extra), total: 1 + extra.length };
    }
    if (path.includes('invite')) {
      invites += 1;
      if (opened) return { ok: true, successes: ['one@example.com'], errored: [] };
      return { ok: true, successes: [], errored: ['one@example.com', 'two@example.com'], seatFull: true, message: '席位已满，已停止邀请' };
    }
    if (path.includes('onboard')) return { ok: false, message: '先不测上车' };
    return { ok: true };
  };
  const first = await team.assign(created.id);
  assert.match(first.results[0].message, /席位已满/);
  const held = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(held.inviteHold, 'seat_full');
  assert.notEqual(held.sessionStatus, 'expired');
  const again = await team.assign(created.id);
  assert.match(again.results[0].message, /席位已满已停止/);
  assert.equal(invites, 1);
  opened = true;
  await assert.rejects(() => team.assign(created.id), (error) => /上车失败|先不测上车/.test(errorText(error)));
  assert.equal(invites, 2);
  const resumed = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(resumed.inviteHold, null);
});

test('失效 session 不再发邀请、探测或踢人', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'child-user', teamStatus: 'file_ready' },
  });
  await prisma.teamWorkspace.update({ where: { id: created.id }, data: { sessionStatus: 'expired' } });
  calls.length = 0;
  await assert.rejects(() => team.assign(created.id), (error) => /母号 session 已失效/.test(errorText(error)));
  await assert.rejects(() => team.probe(created.id), (error) => /母号 session 已失效/.test(errorText(error)));
  await assert.rejects(() => team.kickOne(child.id), (error) => /母号 session 已失效/.test(errorText(error)));
  assert.equal(calls.length, 0);
});

test('只有 token 的新 session 先检查再比对邮箱', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'mother@example.com', workspaces: [{ id: 'ws-1', name: 'Team', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  await team.updateWorkspace(created.id, { session: JSON.stringify({ accessToken: unsignedJwt({}) }) });
  const revealed = await team.revealSession(created.id);
  assert.match(revealed.session, /eyJhbGciOiJub25lIn0/);
});

test('多个 Team 空间的错误里带可点选编号', async (t) => {
  const { team } = await fixture(t);
  route = () => ({
    ok: true,
    email: 'mother@example.com',
    workspaces: [
      { id: 'ws-a', name: '甲', planType: 'team', role: 'account-owner' },
      { id: 'ws-b', name: '乙', planType: 'team', role: 'account-owner' },
    ],
  });
  await assert.rejects(
    () => team.createWorkspace({ session: sessionFor('mother@example.com'), socks: 'socks5://127.0.0.1:1080' }),
    (error) => {
      const body = error.getResponse();
      assert.match(String(body.message), /点选/);
      assert.deepEqual(body.details.workspaces.map((item) => item.id), ['ws-a', 'ws-b']);
      return true;
    },
  );
});

test('密钥缺失时公开兑换返回停用说明，不泄露内部异常', async (t) => {
  const { prisma, redeem, team } = await fixture(t);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const card = imported.created[0].cardKey;
  const previous = process.env.GPTCDK_SECRET;
  delete process.env.GPTCDK_SECRET;
  try {
    const result = await redeem.redeem({ cards: [card], format: 'login' });
    assert.match(String(result.results[0].message), /Team 功能已停用/);
    const row = await prisma.account.findUnique({ where: { cardKey: card } });
    assert.equal(row.redeemStatus, 'unredeemed');
  } finally {
    process.env.GPTCDK_SECRET = previous;
  }
});

test('后台账密导出读取 Team 密文，不回退备注', async (t) => {
  const { prisma, team } = await fixture(t);
  const settings = { getAll: async () => ({ ...DEFAULT_SETTINGS }) };
  const accounts = new AccountsService(
    prisma,
    new ConvertService(),
    new MailboxService(new MailAnalyzerService()),
    settings,
  );
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  const kicked = await prisma.account.create({
    data: {
      name: 'kicked', email: 'kicked@example.com', credits: 0, cardKey: 'CARD-KICKED', accessToken: '',
      stockKind: 'team', teamStatus: 'kicked', updatedAt: new Date(),
      rawJson: JSON.stringify({ notes: { gpt: { password: 'should-not-export' } } }),
    },
  });
  const exported = await accounts.exportAccounts({ format: 'login', ids: [child.id, kicked.id] });
  assert.equal(exported.content, 'kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP\n');
  assert.equal(exported.content.includes('should-not-export'), false);
  assert.equal(exported.filename.endsWith('.txt'), true);
});

test('并发导入同一邮箱只留一张未踢出的卡', async (t) => {
  const { prisma, team } = await fixture(t);
  const line = 'dup@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP';
  const [left, right] = await Promise.all([team.importChildren(line), team.importChildren(line)]);
  assert.equal(left.created.length + right.created.length, 1);
  const rows = await prisma.account.findMany({
    where: { email: { equals: 'dup@example.com', mode: 'insensitive' }, teamStatus: { not: 'kicked' } },
  });
  assert.equal(rows.length, 1);
});

test('全局 SOCKS 只以密文落库，读出来仍是原文', async (t) => {
  const { prisma } = await fixture(t);
  const { SettingsService } = require('../dist/settings/settings.service');
  const settings = new SettingsService(prisma);
  await settings.update({ teamGlobalSocksProxy: 'socks5://user:pass@10.0.0.8:1080' });
  const stored = await prisma.setting.findUnique({ where: { key: 'teamGlobalSocksProxy' } });
  assert.equal(stored.value.includes('socks5://'), false);
  assert.equal(stored.value.includes('pass'), false);
  const all = await settings.getAll();
  assert.equal(all.teamGlobalSocksProxy, 'socks5://user:pass@10.0.0.8:1080');
});

test('封禁地区停止后续探测，不把子号记成额度用尽', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const { encryptSecret } = require('../dist/team/team-crypto');
  const ids = [];
  for (const email of ['one@example.com', 'two@example.com']) {
    const imported = await team.importChildren(`${email}----chatgpt-pass----JBSWY3DPEHPK3PXP`);
    const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
    await prisma.teamSecret.update({
      where: { accountId: child.id },
      data: { tokenCipher: encryptSecret(JSON.stringify({ accessToken: `at-${email}` })) },
    });
    await prisma.account.update({
      where: { id: child.id },
      data: { workspaceId: created.id, teamStatus: 'file_ready', email },
    });
    ids.push(child.id);
  }
  let usage = 0;
  route = (path) => {
    if (path.includes('usage')) {
      usage += 1;
      return { ok: false, code: 'BANNED_EGRESS', message: '出口在封禁地区，已停止' };
    }
    return { ok: true };
  };
  await assert.rejects(() => team.probe(created.id), (error) => /封禁地区/.test(errorText(error)));
  assert.equal(usage, 1);
  const firstUsage = await prisma.teamUsage.findUnique({ where: { accountId: ids[0] } });
  const secondUsage = await prisma.teamUsage.findUnique({ where: { accountId: ids[1] } });
  assert.equal(firstUsage, null);
  assert.equal(secondUsage, null);
  const motherRow = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(motherRow.inviteHold, null);
  assert.notEqual(motherRow.sessionStatus, 'expired');
  await team.importChildren('next@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  calls.length = 0;
  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 };
    if (path.includes('invite')) return { ok: true, successes: [], errored: ['next@example.com'] };
    return { ok: true };
  };
  const assigned = await team.assign(created.id);
  assert.equal(calls.some((item) => item.path.includes('invite')), true);
  assert.doesNotMatch(String(assigned.results?.[0]?.message || ''), /空间不可用已停止/);
});

test('session 预览不是全文，列表也不带 session', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  const preview = await team.previewSession(created.id);
  assert.equal(preview.preview.includes('token-mother@example.com'), false);
  assert.equal(preview.preview.includes('mother@example.com'), false);
  assert.ok(preview.preview.length < 20);
  const listed = JSON.stringify(await team.listWorkspaces());
  assert.equal(listed.includes('token-mother'), false);
});

test('同一个 ChatGPT 空间不能绑定两行，不同空间可以', async (t) => {
  const { team } = await fixture(t);
  await mother(team, 'mother@example.com', 'ws-same');
  await assert.rejects(
    () => mother(team, 'other@example.com', 'ws-same'),
    (error) => /已经绑定过/.test(errorText(error)),
  );
  const other = await mother(team, 'other@example.com', 'ws-other');
  assert.equal(other.workspaceId, 'ws-other');
});

test('账密写入失败时导入整行回滚', async (t) => {
  const { prisma, team } = await fixture(t);
  await prisma.$executeRawUnsafe(`CREATE OR REPLACE FUNCTION team_secret_fail() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'secret insert failed';
    END;
    $$ LANGUAGE plpgsql`);
  await prisma.$executeRawUnsafe('CREATE TRIGGER team_secret_fail BEFORE INSERT ON "TeamSecret" FOR EACH ROW EXECUTE PROCEDURE team_secret_fail()');
  await assert.rejects(() => team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP'));
  assert.equal(await prisma.account.count(), 0);
  assert.equal(await prisma.teamSecret.count(), 0);
});

test('远程未接受邀请不占空位，本地已邀请记录不占，名单被截断时不邀请', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  await prisma.account.create({
    data: {
      name: 'old', email: 'old@example.com', credits: 0, cardKey: 'CARD-OLD1', accessToken: '',
      stockKind: 'team', teamStatus: 'invited', workspaceId: created.id, updatedAt: new Date(),
    },
  });
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 5, members: members(), invites: [], total: 1 }
    : path.includes('invite')
      ? { ok: true, successes: [], errored: ['kid@example.com'] }
      : { ok: true };
  await team.assign(created.id);
  assert.equal(calls.filter((item) => item.path.includes('invite')).length, 1);

  await prisma.teamWorkspace.update({ where: { id: created.id }, data: { lastInviteAt: null } });
  calls.length = 0;
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 2, members: members(), invites: [{ email: 'pending@example.com' }], total: 1 }
    : path.includes('invite')
      ? { ok: true, successes: [], errored: ['kid@example.com'] }
      : { ok: true };
  const sent = await team.assign(created.id);
  assert.equal(calls.filter((item) => item.path.includes('invite')).length, 1);
  assert.doesNotMatch(sent.results[0].message, /没有空位/);

  calls.length = 0;
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 5, members: members(), invitesTruncated: true, total: 1 }
    : { ok: true };
  const truncated = await team.assign(created.id);
  assert.match(truncated.results[0].message, /邀请列表不完整/);
  assert.equal(calls.filter((item) => item.path.includes('invite')).length, 0);
});

test('席位已满或空间停用后不再邀请，空位或新 session 才恢复', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  await prisma.teamWorkspace.update({ where: { id: created.id }, data: { inviteHold: 'seat_full' } });
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 1, members: members(), total: 1 }
    : { ok: true };
  const held = await team.assign(created.id);
  assert.match(held.results[0].message, /席位已满已停止/);
  assert.equal(calls.some((item) => item.path.includes('invite')), false);

  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 }
    : path.includes('invite')
      ? { ok: true, successes: [], errored: ['kid@example.com'] }
      : { ok: true };
  await team.assign(created.id);
  assert.equal(calls.some((item) => item.path.includes('invite')), true);

  await prisma.teamWorkspace.update({ where: { id: created.id }, data: { inviteHold: 'stopped' } });
  calls.length = 0;
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 }
    : { ok: true };
  const stopped = await team.assign(created.id);
  assert.match(stopped.results[0].message, /空间不可用已停止/);
  assert.equal(calls.some((item) => item.path.includes('invite')), false);
  const still = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(still.inviteHold, 'stopped');
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'mother@example.com', workspaces: [{ id: 'ws-1', name: 'Team', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  await team.updateWorkspace(created.id, { session: sessionFor('mother@example.com') });
  const cleared = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(cleared.inviteHold, null);
});

test('出口被拦截停止后续探测，不记额度用尽也不停用空间', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const { encryptSecret } = require('../dist/team/team-crypto');
  const ids = [];
  for (const email of ['one@example.com', 'two@example.com']) {
    const imported = await team.importChildren(`${email}----chatgpt-pass----JBSWY3DPEHPK3PXP`);
    const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
    await prisma.teamSecret.update({
      where: { accountId: child.id },
      data: { tokenCipher: encryptSecret(JSON.stringify({ accessToken: `at-${email}` })) },
    });
    await prisma.account.update({
      where: { id: child.id },
      data: { workspaceId: created.id, teamStatus: 'file_ready', email },
    });
    ids.push(child.id);
  }
  let usage = 0;
  route = (path) => {
    if (path.includes('usage')) {
      usage += 1;
      return { ok: false, code: 'EGRESS_BLOCKED', message: '出口被拦截，已停止' };
    }
    return { ok: true };
  };
  await assert.rejects(() => team.probe(created.id), (error) => /出口被拦截/.test(errorText(error)));
  assert.equal(usage, 1);
  assert.equal(await prisma.teamUsage.count(), 0);
  const motherRow = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(motherRow.inviteHold, null);
  assert.notEqual(motherRow.sessionStatus, 'expired');
});

test('文件已就绪但密钥缺失时公开兑换和找回都停用', async (t) => {
  const { prisma, redeem } = await fixture(t);
  await prisma.account.create({
    data: {
      name: '子号', email: 'kid@example.com', credits: 0, cardKey: 'CARD-FILE2', accessToken: 'child-at',
      stockKind: 'team', teamStatus: 'file_ready', redeemStatus: 'redeemed', rawSource: 'sub2api', updatedAt: new Date(),
      rawJson: JSON.stringify({ accessToken: 'child-at' }),
    },
  });
  const previous = process.env.GPTCDK_SECRET;
  delete process.env.GPTCDK_SECRET;
  try {
    const file = await redeem.redeem({ cards: ['CARD-FILE2'], format: 'sub2api' });
    assert.equal(file.results[0].code, 'TEAM_DISABLED');
    const again = await redeem.reclaim({ cards: ['CARD-FILE2'], format: 'sub2api' });
    assert.equal(again.results[0].code, 'TEAM_DISABLED');
  } finally {
    process.env.GPTCDK_SECRET = previous;
  }
});

test('启动迁移带上未踢出邮箱的部分唯一索引', async (t) => {
  const { prisma } = await fixture(t);
  const rows = await prisma.$queryRaw`SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'Account_team_active_email_key'`;
  assert.equal(rows.length, 1);
});

test('退出确认和实时名单不一致时一个人都不踢', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('snapshot')
    ? {
      ok: true,
      complete: true,
      seatsEntitled: 5,
      members: [
        { id: 'mom', email: 'mother@example.com', role: 'standard-user' },
        { id: 'guest', email: 'guest@example.com', role: 'standard-user' },
      ],
      total: 2,
    }
    : { ok: true };
  const preview = await team.previewKickAll(created.id);
  assert.deepEqual(preview.userIds, ['guest']);
  await assert.rejects(
    () => team.kickAll(created.id, '退出全部', ['mom', 'guest']),
    (error) => /不一致/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => item.path.includes('kick')), false);
  await assert.rejects(
    () => team.kickAll(created.id, '退出全部', []),
    (error) => /请先确认要退出的成员/.test(errorText(error)),
  );
});

test('分配失败时卡密仍留下，并单独返回分配错误', async (t) => {
  const { prisma, team } = await fixture(t);
  const previous = process.env.PROTOCOL_WORKER_URL;
  delete process.env.PROTOCOL_WORKER_URL;
  try {
    const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
    assert.equal(imported.created.length, 1);
    assert.match(imported.assignError, /协议服务未配置/);
    assert.equal(await prisma.account.count({ where: { email: 'kid@example.com' } }), 1);
  } finally {
    process.env.PROTOCOL_WORKER_URL = previous;
  }
});

test('退出全部确认名单带上卡密和是否已兑换', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('guest@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'guest', teamStatus: 'file_ready', redeemStatus: 'redeemed' },
  });
  route = () => ({
    ok: true,
    complete: true,
    seatsEntitled: 5,
    members: members([{ id: 'guest', email: 'guest@example.com', role: 'standard-user' }]),
    total: 2,
  });
  const preview = await team.previewKickAll(created.id);
  assert.equal(preview.members[0].cardKey, imported.created[0].cardKey);
  assert.equal(preview.members[0].redeemStatus, 'redeemed');
  assert.equal(preview.members[0].email, 'guest@example.com');
});

test('满员母号的全局分配仍补跑已邀请子号上车，但不发新邀请', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, teamStatus: 'invited', accessToken: '', userId: null },
  });
  let onboard = 0;
  route = (path) => {
    if (path.includes('onboard')) {
      onboard += 1;
      return { ok: false, message: '上车没有成功' };
    }
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 1, members: members(), total: 1 };
    return { ok: true };
  };
  const assigned = await team.assign();
  assert.equal(onboard, 1);
  assert.match(JSON.stringify(assigned.results), /上车没有成功/);
  assert.equal(calls.some((item) => item.path.includes('invite')), false);
});

test('母号 session 踢人时任务结果写明可能被限流', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('guest@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'guest', teamStatus: 'file_ready' },
  });
  let kicked = false;
  route = (path) => {
    if (path.includes('kick')) {
      kicked = true;
      return { ok: true, rateLimited: true, message: '可能被限流' };
    }
    if (path.includes('snapshot')) {
      const extra = kicked ? [] : [{ id: 'guest', email: 'guest@example.com', role: 'standard-user' }];
      return { ok: true, complete: true, seatsEntitled: 5, members: members(extra), total: 1 + extra.length };
    }
    return { ok: true };
  };
  const preview = await team.previewKickAll(created.id);
  const job = await team.kickAll(created.id, '退出全部', preview.userIds);
  assert.match(job.message, /可能被限流/);
});

test('改绑空间会拆开旧子号，不把旧成员编号带到新空间', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const ready = await team.importChildren('ready@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const invited = await team.importChildren('invited@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const readyRow = await prisma.account.findUnique({ where: { cardKey: ready.created[0].cardKey } });
  const invitedRow = await prisma.account.findUnique({ where: { cardKey: invited.created[0].cardKey } });
  await prisma.account.update({
    where: { id: readyRow.id },
    data: { workspaceId: created.id, userId: 'old-user', teamStatus: 'file_ready', redeemStatus: 'redeemed' },
  });
  await prisma.account.update({
    where: { id: invitedRow.id },
    data: { workspaceId: created.id, userId: 'old-invite', teamStatus: 'invited' },
  });
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'mother@example.com', workspaces: [{ id: 'ws-new', name: 'New', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  const saved = await team.updateWorkspace(created.id, { session: sessionFor('mother@example.com'), workspaceId: 'ws-new' });
  assert.equal(saved.workspaceId, 'ws-new');
  assert.ok(saved.detachedChildren.includes('ready@example.com'));
  assert.ok(saved.detachedChildren.includes('invited@example.com'));
  const kept = await prisma.account.findUnique({ where: { id: readyRow.id } });
  assert.equal(kept.workspaceId, null);
  assert.equal(kept.userId, null);
  assert.equal(kept.teamStatus, 'file_ready');
  assert.equal(kept.redeemStatus, 'redeemed');
  const released = await prisma.account.findUnique({ where: { id: invitedRow.id } });
  assert.equal(released.workspaceId, null);
  assert.equal(released.userId, null);
  assert.equal(released.teamStatus, 'waiting');
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.openaiWorkspaceId, 'ws-new');
});

test('邀请失败不刷新十分钟冷却', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 };
    if (path.includes('invite')) return { ok: false, successes: [], errored: ['kid@example.com'], message: '邀请被拒绝' };
    return { ok: true };
  };
  await assert.rejects(() => team.assign(created.id));
  const afterFail = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(afterFail.lastInviteAt, null);
  calls.length = 0;
  await assert.rejects(() => team.assign(created.id));
  assert.equal(calls.filter((item) => item.path.includes('invite')).length, 1);
});

test('缺代理的母号不会中断其他空间的全局分配', async (t) => {
  const { prisma, team } = await fixture(t);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const early = await mother(team, 'early@example.com', 'ws-early');
  const late = await mother(team, 'late@example.com', 'ws-late');
  await prisma.teamWorkspace.update({ where: { id: late.id }, data: { socksCipher: null } });
  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: [{ id: 'owner', email: 'early@example.com', role: 'account-owner' }], total: 1 };
    if (path.includes('invite')) return { ok: true, successes: ['kid@example.com'], errored: [] };
    if (path.includes('onboard')) return { ok: false, message: '先不测上车' };
    return { ok: true };
  };
  const assigned = await team.assign();
  assert.equal(calls.filter((item) => item.path.includes('invite')).length, 1);
  const blocked = assigned.results.find((item) => item.id === late.id);
  assert.match(blocked.message, /SOCKS/);
  const child = await prisma.account.findFirst({ where: { email: 'kid@example.com' } });
  assert.equal(child.workspaceId, early.id);
  assert.equal(child.teamStatus, 'invited');
});

test('排在前面的母号缺代理时，后面的空间仍会分配', async (t) => {
  const { prisma, team } = await fixture(t);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const early = await mother(team, 'early@example.com', 'ws-early');
  const late = await mother(team, 'late@example.com', 'ws-late');
  await prisma.teamWorkspace.update({ where: { id: early.id }, data: { socksCipher: null } });
  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: [{ id: 'owner', email: 'late@example.com', role: 'account-owner' }], total: 1 };
    if (path.includes('invite')) return { ok: true, successes: ['kid@example.com'], errored: [] };
    if (path.includes('onboard')) return { ok: false, message: '先不测上车' };
    return { ok: true };
  };
  const assigned = await team.assign();
  assert.equal(calls.filter((item) => item.path.includes('invite')).length, 1);
  const blocked = assigned.results.find((item) => item.id === early.id);
  assert.match(blocked.message, /SOCKS/);
  const child = await prisma.account.findFirst({ where: { email: 'kid@example.com' } });
  assert.equal(child.workspaceId, late.id);
  assert.equal(child.teamStatus, 'invited');
});

test('邀请请求已经发出后，失败也要隔 10 分钟', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 };
    if (path.includes('invite')) return { ok: false, code: 'EGRESS_BLOCKED', inviteSent: true, message: '出口被拦截，已停止' };
    return { ok: true };
  };
  await assert.rejects(() => team.assign(created.id), (error) => /出口被拦截/.test(errorText(error)));
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.ok(row.lastInviteAt);
  const child = await prisma.account.findFirst({ where: { email: 'kid@example.com' } });
  assert.equal(child.teamStatus, 'waiting');
  assert.equal(child.workspaceId, null);
  calls.length = 0;
  const again = await team.assign(created.id);
  assert.match(again.results[0].message, /10 分钟/);
  assert.equal(calls.filter((item) => item.path.includes('invite')).length, 0);
});

test('上游收下但全部失败的邀请也占用 10 分钟', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = (path) => {
    if (path.includes('snapshot')) return { ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 };
    if (path.includes('invite')) return { ok: true, inviteSent: true, successes: [], errored: ['kid@example.com'] };
    return { ok: true };
  };
  await team.assign(created.id);
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.ok(row.lastInviteAt);
  const child = await prisma.account.findFirst({ where: { email: 'kid@example.com' } });
  assert.equal(child.teamStatus, 'waiting');
  calls.length = 0;
  const again = await team.assign(created.id);
  assert.match(again.results[0].message, /10 分钟/);
  assert.equal(calls.filter((item) => item.path.includes('invite')).length, 0);
});

test('改绑后原空间再踢会清掉已上车的卡', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team, 'mother@example.com', 'ws-old');
  const ready = await team.importChildren('ready@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const readyRow = await prisma.account.findUnique({ where: { cardKey: ready.created[0].cardKey } });
  await prisma.account.update({
    where: { id: readyRow.id },
    data: { workspaceId: created.id, userId: 'old-user', teamStatus: 'file_ready', redeemStatus: 'redeemed', accessToken: 'file-token' },
  });
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'mother@example.com', workspaces: [{ id: 'ws-new', name: 'New', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  await team.updateWorkspace(created.id, { session: sessionFor('mother@example.com'), workspaceId: 'ws-new' });
  const rebound = await mother(team, 'other@example.com', 'ws-old');
  let kicked = false;
  route = (path) => {
    if (path.includes('kick')) {
      kicked = true;
      return { ok: true };
    }
    if (path.includes('snapshot')) {
      const extra = kicked ? [] : [{ id: 'old-user', email: 'ready@example.com', role: 'standard-user' }];
      return { ok: true, complete: true, seatsEntitled: 5, members: members(extra), total: 1 + extra.length };
    }
    return { ok: true };
  };
  const preview = await team.previewKickAll(rebound.id);
  assert.equal(preview.members[0].cardKey, ready.created[0].cardKey);
  await team.kickAll(rebound.id, '退出全部', preview.userIds);
  const wiped = await prisma.account.findUnique({ where: { id: readyRow.id } });
  assert.equal(wiped.teamStatus, 'kicked');
  assert.equal(wiped.accessToken, '');
  assert.equal(await prisma.teamSecret.count({ where: { accountId: readyRow.id } }), 0);
  const listed = (await team.listMembers()).items.find((item) => item.id === readyRow.id);
  assert.equal(listed, undefined);
});

test('改绑后已离开原空间的子号，再踢会补删文件', async (t) => {
  const { prisma, team } = await fixture(t);
  await mother(team, 'mother@example.com', 'ws-old');
  const ready = await team.importChildren('ready@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const readyRow = await prisma.account.findUnique({ where: { cardKey: ready.created[0].cardKey } });
  await prisma.account.update({
    where: { id: readyRow.id },
    data: {
      workspaceId: null,
      userId: null,
      priorUserId: 'old-user',
      priorRemoteWorkspaceId: 'ws-old',
      teamStatus: 'file_ready',
      accessToken: 'file-token',
      rawJson: JSON.stringify({ access_token: 'file-token' }),
    },
  });
  route = () => ({ ok: true, complete: true, seatsEntitled: 5, members: members(), total: 1 });
  await team.kickOne(readyRow.id);
  const wiped = await prisma.account.findUnique({ where: { id: readyRow.id } });
  assert.equal(wiped.teamStatus, 'kicked');
  assert.equal(wiped.accessToken, '');
  assert.equal(wiped.rawJson, null);
  assert.equal(wiped.priorUserId, null);
  assert.equal(await prisma.teamSecret.findUnique({ where: { accountId: readyRow.id } }), null);
  assert.equal(calls.some((item) => item.path.includes('kick')), false);
});

test('拆开的已上车子号还能从原空间踢出', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team, 'mother@example.com', 'ws-old');
  const ready = await team.importChildren('ready@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const readyRow = await prisma.account.findUnique({ where: { cardKey: ready.created[0].cardKey } });
  await prisma.account.update({
    where: { id: readyRow.id },
    data: { workspaceId: created.id, userId: 'old-user', teamStatus: 'file_ready', accessToken: 'file-token' },
  });
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'mother@example.com', workspaces: [{ id: 'ws-new', name: 'New', planType: 'team', role: 'account-owner' }] }
    : { ok: true };
  await team.updateWorkspace(created.id, { session: sessionFor('mother@example.com'), workspaceId: 'ws-new' });
  const rebound = await mother(team, 'other@example.com', 'ws-old');
  await prisma.teamWorkspace.update({ where: { id: rebound.id }, data: { snapshotComplete: true } });
  let kicked = false;
  route = (path) => {
    if (path.includes('kick')) {
      kicked = true;
      return { ok: true };
    }
    if (path.includes('snapshot')) {
      const extra = kicked ? [] : [{ id: 'old-user', email: 'ready@example.com', role: 'standard-user' }];
      return { ok: true, complete: true, seatsEntitled: 5, members: members(extra), total: 1 + extra.length };
    }
    return { ok: true };
  };
  const visible = (await team.listMembers()).items.find((item) => item.id === readyRow.id);
  assert.equal(visible.priorUserId, 'old-user');
  assert.equal(visible.priorRemoteWorkspaceId, 'ws-old');
  assert.equal(visible.workspaceId, null);
  await team.kickOne(readyRow.id);
  const wiped = await prisma.account.findUnique({ where: { id: readyRow.id } });
  assert.equal(wiped.teamStatus, 'kicked');
  assert.equal(wiped.accessToken, '');
});

test('刷新空间记下成员邮箱和秒级到期，两次使用同一个设备号', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  const devices = [];
  route = (path, body) => {
    if (path.includes('snapshot')) {
      devices.push(body.deviceId);
      return {
        ok: true,
        complete: true,
        seatsEntitled: 5,
        members: [{ id: 'user-1', email: 'kid@example.com', role: 'standard-user' }],
        activeUntil: '2026-10-08T03:12:01Z',
        willRenew: false,
      };
    }
    return { ok: true };
  };
  const refreshed = await team.refresh(created.id);
  assert.match(refreshed.message, /成员 1 人/);
  await team.refresh(created.id);
  assert.equal(devices.length, 2);
  assert.ok(devices[0]);
  assert.equal(devices[0], devices[1]);
  const listed = await team.listWorkspaces();
  const row = listed.items.find((item) => item.id === created.id);
  assert.equal(row.activeUntil, '2026-10-08T03:12:01Z');
  assert.equal(row.willRenew, false);
  const roster = await team.listRemoteMembers();
  assert.equal(roster.items.some((item) => item.email === 'kid@example.com' && item.id === 'user-1'), true);
  const revealed = JSON.parse((await team.revealSession(created.id)).session);
  assert.equal(revealed.oaiDeviceId, devices[0]);
});

test('名单不完整时保留上次成员，并且一个人都不踢', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 5, members: [{ id: 'user-1', email: 'kid@example.com', role: 'standard-user' }], total: 1 }
    : { ok: true };
  await team.refresh(created.id);
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: false, members: [], seatsEntitled: null, activeUntil: null }
    : { ok: true };
  const again = await team.refresh(created.id);
  assert.match(again.message, /不完整/);
  const roster = await team.listRemoteMembers();
  assert.equal(roster.items.some((item) => item.email === 'kid@example.com'), true);
  calls.length = 0;
  await assert.rejects(
    () => team.kickSelected(created.id, '踢出选中', ['user-1']),
    (error) => /一个人都不会踢/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => item.path.includes('kick')), false);
});

test('选中踢出只踢普通成员，所有者跳过，也不自动分配', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'user-1', teamStatus: 'joined', accessToken: 'keep-me' },
  });
  let snapshots = 0;
  route = (path) => {
    if (!path.includes('snapshot')) return { ok: true };
    snapshots += 1;
    const stillThere = snapshots < 3;
    const extra = stillThere
      ? [{ id: 'user-1', email: 'kid@example.com', role: 'standard-user' }, { id: 'user-2', email: 'other@example.com', role: 'standard-user' }]
      : [{ id: 'user-2', email: 'other@example.com', role: 'standard-user' }];
    return { ok: true, complete: true, seatsEntitled: 5, members: members(extra), total: extra.length + 1 };
  };
  calls.length = 0;
  const job = await team.kickSelected(created.id, '踢出选中', ['owner', 'user-1']);
  assert.match(job.message, /所有者/);
  assert.equal(calls.filter((item) => item.path.includes('kick')).map((item) => item.body.userId).join(','), 'user-1');
  assert.equal(calls.some((item) => item.path.includes('assign')), false);
  const wiped = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(wiped.teamStatus, 'kicked');
});

test('踢完仍在名单里时不删除本地账密', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'user-1', teamStatus: 'joined', accessToken: 'keep-me' },
  });
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 5, members: members([{ id: 'user-1', email: 'kid@example.com', role: 'standard-user' }]), total: 2 }
    : { ok: true };
  const job = await team.kickSelected(created.id, '踢出选中', ['user-1']);
  assert.match(job.message, /没有删除资料/);
  const kept = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(kept.teamStatus, 'joined');
  assert.equal(kept.accessToken, 'keep-me');
});

test('空的 session 回写不会清掉母号会话，新 cookie 才会写回', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  const before = await team.revealSession(created.id);
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 5, members: members(), sessionUpdate: {} }
    : { ok: true };
  await team.refresh(created.id);
  const unchanged = await team.revealSession(created.id);
  assert.equal(unchanged.session, before.session);
  route = (path) => path.includes('snapshot')
    ? {
      ok: true,
      complete: true,
      seatsEntitled: 5,
      members: members(),
      sessionUpdate: { accessToken: 'fresh-access', sessionToken: 'rotated-session', deviceId: 'device-kept' },
    }
    : { ok: true };
  await team.refresh(created.id);
  const rotated = JSON.parse((await team.revealSession(created.id)).session);
  assert.equal(rotated.accessToken, 'fresh-access');
  assert.equal(rotated.sessionToken, 'rotated-session');
  assert.equal(rotated.oaiDeviceId, 'device-kept');
});

test('不是所有者的 Team 空间不能绑定', async (t) => {
  const { team } = await fixture(t);
  route = () => ({
    ok: true,
    email: 'mother@example.com',
    workspaces: [{ id: 'ws-member', name: 'Team', planType: 'team', role: 'standard-user' }],
  });
  await assert.rejects(
    () => team.createWorkspace({ session: sessionFor('mother@example.com'), socks: 'socks5://127.0.0.1:1080' }),
    (error) => /所有者/.test(errorText(error)),
  );
});

test('指定停用、非 Team 或非所有者空间不能绕过绑定', async (t) => {
  const { team } = await fixture(t);
  route = () => ({
    ok: true,
    email: 'mother@example.com',
    workspaces: [
      { id: 'ws-dead', name: 'Dead', planType: 'team', role: 'account-owner', deactivated: true },
      { id: 'ws-plus', name: 'Plus', planType: 'plus', role: 'account-owner' },
      { id: 'ws-member', name: 'Member', planType: 'team', role: 'standard-user' },
    ],
  });
  await assert.rejects(
    () => team.createWorkspace({ session: sessionFor('mother@example.com'), socks: 'socks5://127.0.0.1:1080', workspaceId: 'ws-dead' }),
    (error) => /停用/.test(errorText(error)),
  );
  await assert.rejects(
    () => team.createWorkspace({ session: sessionFor('mother@example.com'), socks: 'socks5://127.0.0.1:1080', workspaceId: 'ws-plus' }),
    (error) => /不是 Team/.test(errorText(error)),
  );
  await assert.rejects(
    () => team.createWorkspace({ session: sessionFor('mother@example.com'), socks: 'socks5://127.0.0.1:1080', workspaceId: 'ws-member' }),
    (error) => /不是所有者/.test(errorText(error)),
  );
});

test('多个空间里只自动绑定唯一的所有者', async (t) => {
  const { team } = await fixture(t);
  route = () => ({
    ok: true,
    email: 'mother@example.com',
    workspaces: [
      { id: 'ws-member', name: 'Member', planType: 'team', role: 'standard-user' },
      { id: 'ws-owner', name: 'Owner', planType: 'team', role: 'account-owner' },
    ],
  });
  const created = await team.createWorkspace({ session: sessionFor('mother@example.com'), socks: 'socks5://127.0.0.1:1080' });
  assert.equal(created.workspaceId, 'ws-owner');
});

test('保存时原空间已不是所有者则拒绝', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const before = await team.revealSession(created.id);
  route = (path) => path.includes('inspect')
    ? { ok: true, email: 'mother@example.com', workspaces: [{ id: 'ws-1', name: 'Team', planType: 'team', role: 'standard-user' }] }
    : { ok: true };
  await assert.rejects(
    () => team.updateWorkspace(created.id, { session: sessionFor('mother@example.com') }),
    (error) => /所有者/.test(errorText(error)),
  );
  const kept = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(kept.openaiWorkspaceId, 'ws-1');
  assert.equal((await team.revealSession(created.id)).session, before.session);
});

test('订阅接口失败时不覆盖已有席位和到期', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 5, activeUntil: '2026-10-08T03:12:01Z', willRenew: false, members: members(), total: 1 }
    : { ok: true };
  await team.refresh(created.id);
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, subscriptionRead: false, seatsEntitled: null, activeUntil: null, willRenew: null, members: members(), total: 1 }
    : { ok: true };
  await team.refresh(created.id);
  const row = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(row.seatsEntitled, 5);
  assert.equal(row.activeUntil, '2026-10-08T03:12:01Z');
  assert.equal(row.willRenew, false);
});

test('旧母号缺少设备号时，刷新会补上并在下次继续使用', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const { encryptSecret } = require('../dist/team/team-crypto');
  const current = JSON.parse((await team.revealSession(created.id)).session);
  delete current.oaiDeviceId;
  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: { sessionCipher: encryptSecret(JSON.stringify(current)) },
  });
  const devices = [];
  route = (path, body) => {
    if (path.includes('snapshot')) {
      devices.push(body.deviceId || '');
      return { ok: true, complete: true, seatsEntitled: 2, members: members(), total: 1 };
    }
    return { ok: true };
  };
  await team.refresh(created.id);
  await team.refresh(created.id);
  assert.ok(devices[0]);
  assert.equal(devices[0], devices[1]);
  const revealed = JSON.parse((await team.revealSession(created.id)).session);
  assert.equal(revealed.oaiDeviceId, devices[0]);
});

test('同一次请求换了新 cookie 后失败，不把母号标成失效', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('snapshot')
    ? {
      ok: false,
      code: 'SESSION_EXPIRED',
      message: '母号 session 已失效，请重新贴一次',
      sessionUpdate: { sessionToken: 'rotated-after-401', accessToken: 'fresh-at' },
    }
    : { ok: true };
  await assert.rejects(() => team.refresh(created.id), (error) => /已保留/.test(errorText(error)));
  const row = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(row.sessionStatus, '有效');
  const revealed = JSON.parse((await team.revealSession(created.id)).session);
  assert.equal(revealed.sessionToken, 'rotated-after-401');
  assert.equal(revealed.accessToken, 'fresh-at');
});

test('没有新 cookie 的失效仍然标成失效', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('snapshot')
    ? { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次', sessionUpdate: { deviceId: 'only-device' } }
    : { ok: true };
  await assert.rejects(() => team.refresh(created.id), (error) => /已失效/.test(errorText(error)));
  const row = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(row.sessionStatus, '已失效');
});

test('只有空间 token 变了不能当成换过的 session', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('snapshot')
    ? {
      ok: false,
      code: 'SESSION_EXPIRED',
      message: '母号 session 已失效，请重新贴一次',
      sessionUpdate: { accessToken: 'workspace-at' },
    }
    : { ok: true };
  await assert.rejects(
    () => team.refresh(created.id),
    (error) => /已失效/.test(errorText(error)) && !/已保留/.test(errorText(error)),
  );
  const row = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(row.sessionStatus, '已失效');
});

test('新建母号检查失败时把换过的 session 还给输入框', async (t) => {
  const { prisma, team } = await fixture(t);
  route = () => ({
    ok: false,
    code: 'SESSION_EXPIRED',
    message: '母号 session 已失效，请重新贴一次',
    sessionUpdate: { sessionToken: 'rotated-session', accessToken: 'personal-at' },
  });
  let caught;
  await assert.rejects(
    () => team.createWorkspace({ session: sessionFor('mother@example.com'), socks: 'socks5://127.0.0.1:1080' }),
    (error) => {
      caught = error;
      return /已失效|已保留/.test(errorText(error));
    },
  );
  assert.match(String(errorDetails(caught)?.session || ''), /rotated-session/);
  assert.equal(await prisma.teamWorkspace.count(), 0);
});

test('保存失败且读不出邮箱时，不把换过的 session 写进这行', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const before = await team.revealSession(created.id);
  const pasted = JSON.stringify({
    accessToken: 'old-at',
    sessionToken: 'old-session',
    email: 'mother@example.com',
  });
  route = (path) => path.includes('inspect')
    ? {
      ok: false,
      code: 'SESSION_EXPIRED',
      message: '母号 session 已失效，请重新贴一次',
      sessionUpdate: { sessionToken: 'rotated-session', accessToken: 'personal-at' },
    }
    : { ok: true };
  let caught;
  await assert.rejects(
    () => team.updateWorkspace(created.id, { session: pasted }),
    (error) => {
      caught = error;
      return /已失效/.test(errorText(error)) && !/已保留/.test(errorText(error));
    },
  );
  assert.match(String(errorDetails(caught)?.session || ''), /rotated-session/);
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.openaiWorkspaceId, 'ws-1');
  assert.equal(row.motherEmail, 'mother@example.com');
  assert.equal(row.sessionStatus, 'valid');
  assert.doesNotMatch(String(row.lastError || ''), /已保留/);
  assert.equal((await team.revealSession(created.id)).session, before.session);
});

test('保存时所有者校验失败也不丢掉已换过的 session', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('inspect')
    ? {
      ok: true,
      email: 'mother@example.com',
      workspaces: [{ id: 'ws-1', name: 'Team', planType: 'team', role: 'standard-user' }],
      sessionUpdate: { sessionToken: 'rotated-session', accessToken: 'personal-at' },
    }
    : { ok: true };
  await assert.rejects(
    () => team.updateWorkspace(created.id, { session: sessionFor('mother@example.com') }),
    (error) => /所有者/.test(errorText(error)) && /rotated-session/.test(String(errorDetails(error)?.session || '')),
  );
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.openaiWorkspaceId, 'ws-1');
  const revealed = JSON.parse((await team.revealSession(created.id)).session);
  assert.equal(revealed.sessionToken, 'rotated-session');
});

test('保活遇到不完整名单时仍留下警告', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const { encryptSecret } = require('../dist/team/team-crypto');
  const current = JSON.parse((await team.revealSession(created.id)).session);
  current.sessionToken = 'live-session';
  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: {
      sessionCipher: encryptSecret(JSON.stringify(current)),
      lastError: null,
      snapshotComplete: true,
    },
  });
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: false, members: members(), total: 3 }
    : { ok: true };
  calls.length = 0;
  await team.keepAlive();
  assert.ok(calls.some((item) => String(item.path || '').includes('snapshot')));
  const warned = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(warned.lastError, '成员名单不完整');
  assert.equal(warned.snapshotComplete, false);
  route = (path) => path.includes('snapshot')
    ? { ok: true, complete: true, seatsEntitled: 2, members: members(), total: 1 }
    : { ok: true };
  await team.refresh(created.id);
  const cleared = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(cleared.lastError, null);
  assert.equal(cleared.snapshotComplete, true);
});

test('检查失败只有个人 token 变了，不能把已失效改回有效', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const { encryptSecret } = require('../dist/team/team-crypto');
  const current = JSON.parse((await team.revealSession(created.id)).session);
  current.sessionToken = 'old-session';
  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: {
      sessionCipher: encryptSecret(JSON.stringify(current)),
      sessionStatus: 'expired',
      lastError: '母号 session 已失效，请重新贴一次',
    },
  });
  route = (path) => path.includes('inspect')
    ? {
      ok: false,
      code: 'SESSION_EXPIRED',
      message: '母号 session 已失效，请重新贴一次',
      sessionUpdate: { accessToken: 'fresh-personal-at' },
    }
    : { ok: true };
  await assert.rejects(
    () => team.updateWorkspace(created.id, {
      session: JSON.stringify({ accessToken: 'old-at', sessionToken: 'old-session', email: 'mother@example.com' }),
    }),
    (error) => /已失效/.test(errorText(error)) && !/已保留/.test(errorText(error)),
  );
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.sessionStatus, 'expired');
  assert.doesNotMatch(String(row.lastError || ''), /已保留/);
  const revealed = JSON.parse((await team.revealSession(created.id)).session);
  assert.equal(revealed.sessionToken, 'old-session');
  assert.notEqual(revealed.accessToken, 'fresh-personal-at');
});

test('检查到的邮箱不一致时，不把另一份 session 写进这行母号', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const before = await team.revealSession(created.id);
  route = (path) => path.includes('inspect')
    ? {
      ok: true,
      email: 'other@example.com',
      workspaces: [{ id: 'ws-other', name: 'Other', planType: 'team', role: 'account-owner' }],
      sessionUpdate: { sessionToken: 'rotated-session', accessToken: 'other-at' },
    }
    : { ok: true };
  let caught;
  await assert.rejects(
    () => team.updateWorkspace(created.id, {
      session: JSON.stringify({ accessToken: 'other-at', sessionToken: 'old-session', email: 'mother@example.com' }),
    }),
    (error) => {
      caught = error;
      return /邮箱和已绑定母号不一致/.test(errorText(error));
    },
  );
  assert.match(String(errorDetails(caught)?.session || ''), /rotated-session/);
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.openaiWorkspaceId, 'ws-1');
  assert.equal(row.motherEmail, 'mother@example.com');
  assert.equal((await team.revealSession(created.id)).session, before.session);
});

test('撤回遇到 session 失效会标成失效，换过 cookie 则保留', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  route = (path) => {
    if (path.includes('snapshot')) {
      return { ok: true, complete: true, seatsEntitled: 5, members: members(), invites: [{ email: 'kid@example.com' }], total: 1 };
    }
    if (path.includes('revoke')) {
      return { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次' };
    }
    return { ok: true };
  };
  await team.revokeInvites(created.id);
  const expired = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(expired.sessionStatus, 'expired');
  assert.match(String(expired.lastError || ''), /已失效/);

  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: { sessionStatus: 'valid', lastError: null },
  });
  route = (path) => {
    if (path.includes('snapshot')) {
      return { ok: true, complete: true, seatsEntitled: 5, members: members(), invites: [{ email: 'kid@example.com' }], total: 1 };
    }
    if (path.includes('revoke')) {
      return {
        ok: false,
        code: 'SESSION_EXPIRED',
        message: '母号 session 已失效，请重新贴一次',
        sessionUpdate: { sessionToken: 'rotated-session', accessToken: 'personal-at' },
      };
    }
    return { ok: true };
  };
  await team.revokeInvites(created.id);
  const kept = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.notEqual(kept.sessionStatus, 'expired');
  assert.match(String(kept.lastError || ''), /已保留/);
  const revealed = JSON.parse((await team.revealSession(created.id)).session);
  assert.equal(revealed.sessionToken, 'rotated-session');
});

test('检查失败但邮箱已核对且 session 换过，仍保留', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('inspect')
    ? {
      ok: false,
      code: 'SESSION_EXPIRED',
      email: 'mother@example.com',
      message: '母号 session 已失效，请重新贴一次',
      sessionUpdate: { sessionToken: 'rotated-session', accessToken: 'personal-at' },
    }
    : { ok: true };
  let caught;
  await assert.rejects(
    () => team.updateWorkspace(created.id, {
      session: JSON.stringify({ accessToken: 'old-at', sessionToken: 'old-session', email: 'mother@example.com' }),
    }),
    (error) => {
      caught = error;
      return /已失效/.test(errorText(error));
    },
  );
  assert.match(String(errorDetails(caught)?.session || ''), /rotated-session/);
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.sessionStatus, 'valid');
  assert.match(String(row.lastError || ''), /已保留/);
  const revealed = JSON.parse((await team.revealSession(created.id)).session);
  assert.equal(revealed.sessionToken, 'rotated-session');
});

test('同一份 session 换过但读不出邮箱时，不改这行也不标成已保留', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const { encryptSecret } = require('../dist/team/team-crypto');
  const current = JSON.parse((await team.revealSession(created.id)).session);
  current.sessionToken = 'stored-session';
  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: { sessionCipher: encryptSecret(JSON.stringify(current)), sessionStatus: 'valid', lastError: null },
  });
  const before = await team.revealSession(created.id);
  route = (path) => path.includes('inspect')
    ? {
      ok: false,
      code: 'SESSION_EXPIRED',
      message: '母号 session 已失效，请重新贴一次',
      sessionUpdate: { sessionToken: 'rotated-session', accessToken: 'personal-at' },
    }
    : { ok: true };
  let caught;
  await assert.rejects(
    () => team.updateWorkspace(created.id, {
      session: JSON.stringify({ accessToken: 'token-mother@example.com', sessionToken: 'stored-session', email: 'mother@example.com' }),
    }),
    (error) => {
      caught = error;
      return /已失效/.test(errorText(error)) && !/已保留/.test(errorText(error));
    },
  );
  assert.match(String(errorDetails(caught)?.session || ''), /rotated-session/);
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.sessionStatus, 'valid');
  assert.equal(row.lastError, null);
  assert.equal((await team.revealSession(created.id)).session, before.session);
});

test('另一份失败的 session 不能把仍有效的母号标成失效', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const { encryptSecret } = require('../dist/team/team-crypto');
  const current = JSON.parse((await team.revealSession(created.id)).session);
  current.sessionToken = 'stored-session';
  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: { sessionCipher: encryptSecret(JSON.stringify(current)), sessionStatus: 'valid', lastError: null },
  });
  const before = await team.revealSession(created.id);
  route = (path) => path.includes('inspect')
    ? { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次' }
    : { ok: true };
  await assert.rejects(
    () => team.updateWorkspace(created.id, {
      session: JSON.stringify({ accessToken: 'other-at' }),
    }),
    (error) => /已失效/.test(errorText(error)),
  );
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.sessionStatus, 'valid');
  assert.doesNotMatch(String(row.lastError || ''), /已失效/);
  assert.equal((await team.revealSession(created.id)).session, before.session);
});

test('同一份 session 检查失败仍标成失效', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const { encryptSecret } = require('../dist/team/team-crypto');
  const current = JSON.parse((await team.revealSession(created.id)).session);
  current.sessionToken = 'stored-session';
  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: { sessionCipher: encryptSecret(JSON.stringify(current)), sessionStatus: 'valid', lastError: null },
  });
  route = (path) => path.includes('inspect')
    ? { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次' }
    : { ok: true };
  await assert.rejects(
    () => team.updateWorkspace(created.id, {
      session: JSON.stringify({ accessToken: 'token-mother@example.com', sessionToken: 'stored-session', email: 'mother@example.com' }),
    }),
    (error) => /已失效/.test(errorText(error)),
  );
  const row = await prisma.teamWorkspace.findUnique({ where: { id: created.id } });
  assert.equal(row.sessionStatus, 'expired');
  const revealed = JSON.parse((await team.revealSession(created.id)).session);
  assert.equal(revealed.sessionToken, 'stored-session');
});

test('撤回前刷新失败不能报成已经撤回', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, teamStatus: 'invited' },
  });
  route = (path) => path.includes('snapshot')
    ? { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次' }
    : { ok: true };
  await assert.rejects(
    () => team.revokeInvites(created.id),
    (error) => /已失效/.test(errorText(error)) && !/已按邮箱撤回/.test(errorText(error)),
  );
  const jobs = await team.listJobs();
  const job = jobs.items.find((item) => item.workspaceRowId === created.id && item.kind === 'revoke');
  assert.equal(job.status, 'failed');
  assert.doesNotMatch(String(job.message || ''), /已按邮箱撤回/);
  const kept = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(kept.teamStatus, 'invited');
  assert.equal(kept.workspaceId, created.id);
});

test('选踢前 session 失效要说明失效，一个人都不踢', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('snapshot')
    ? { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次' }
    : { ok: true };
  calls.length = 0;
  await assert.rejects(
    () => team.kickSelected(created.id, '踢出选中', ['user-1']),
    (error) => /已失效/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => item.path.includes('kick')), false);
});

test('单踢和退出全部在刷新失败时说明真实原因，一个人都不踢', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'child-user', teamStatus: 'file_ready' },
  });
  route = (path) => path.includes('snapshot')
    ? { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次' }
    : { ok: true };
  calls.length = 0;
  await assert.rejects(
    () => team.kickOne(child.id),
    (error) => /已失效/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => item.path.includes('kick')), false);
  const kept = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(kept.teamStatus, 'file_ready');
  await assert.rejects(
    () => team.previewKickAll(created.id),
    (error) => /已失效/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  const other = await mother(team, 'other-mother@example.com', 'ws-upstream');
  const otherImport = await team.importChildren('other-kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const otherChild = await prisma.account.findUnique({ where: { cardKey: otherImport.created[0].cardKey } });
  await prisma.account.update({
    where: { id: otherChild.id },
    data: { workspaceId: other.id, userId: 'other-user', teamStatus: 'file_ready' },
  });
  route = (path) => path.includes('snapshot')
    ? { ok: false, code: 'UPSTREAM', message: '上游暂时失败' }
    : { ok: true };
  calls.length = 0;
  await assert.rejects(
    () => team.previewKickAll(other.id),
    (error) => /上游暂时失败/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  await assert.rejects(
    () => team.kickAll(other.id, '退出全部', ['other-user']),
    (error) => /上游暂时失败/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => item.path.includes('kick')), false);
  const still = await prisma.account.findUnique({ where: { id: otherChild.id } });
  assert.equal(still.teamStatus, 'file_ready');
});

test('补删后再复核失败时，不能说一个账密都没删', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const goneImport = await team.importChildren('gone@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const stayImport = await team.importChildren('stay@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const gone = await prisma.account.findUnique({ where: { cardKey: goneImport.created[0].cardKey } });
  const stay = await prisma.account.findUnique({ where: { cardKey: stayImport.created[0].cardKey } });
  await prisma.account.update({
    where: { id: gone.id },
    data: { workspaceId: created.id, userId: 'gone-user', teamStatus: 'file_ready' },
  });
  await prisma.account.update({
    where: { id: stay.id },
    data: { workspaceId: created.id, userId: 'stay-user', teamStatus: 'file_ready' },
  });
  let snaps = 0;
  route = (path) => {
    if (path.includes('kick')) return { ok: true };
    if (path.includes('snapshot')) {
      snaps += 1;
      if (snaps === 1) {
        return {
          ok: true,
          complete: true,
          members: members([{ id: 'stay-user', email: 'stay@example.com', role: 'standard-user' }]),
          total: 2,
        };
      }
      return { ok: true, complete: false, members: [], total: null };
    }
    return { ok: true };
  };
  await assert.rejects(
    () => team.kickOne(stay.id),
    (error) => {
      const text = errorText(error);
      return /已删除 1 个已不在名单里的资料/.test(text)
        && /复核快照不完整/.test(text)
        && !/没有删除任何账密或文件/.test(text);
    },
  );
  const wiped = await prisma.account.findUnique({ where: { id: gone.id } });
  assert.equal(wiped.teamStatus, 'kicked');
  assert.equal(await prisma.teamSecret.findUnique({ where: { accountId: gone.id } }), null);
  const kept = await prisma.account.findUnique({ where: { id: stay.id } });
  assert.equal(kept.teamStatus, 'file_ready');
  assert.ok(await prisma.teamSecret.findUnique({ where: { accountId: stay.id } }));
  const job = await prisma.teamJob.findFirst({ where: { workspaceRowId: created.id, kind: 'kick' }, orderBy: { id: 'desc' } });
  assert.equal(job.status, 'failed');
  assert.match(job.message, /已删除 1 个已不在名单里的资料/);
  assert.match(job.message, /复核快照不完整/);
  assert.doesNotMatch(job.message, /没有删除任何账密或文件/);
});

test('踢完复核遇到 session 失效要说明失效，不删这次要踢的人', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'child-user', teamStatus: 'file_ready' },
  });
  let snaps = 0;
  route = (path) => {
    if (path.includes('kick')) return { ok: true };
    if (path.includes('snapshot')) {
      snaps += 1;
      if (snaps === 1) {
        return {
          ok: true,
          complete: true,
          members: members([{ id: 'child-user', email: 'kid@example.com', role: 'standard-user' }]),
          total: 2,
        };
      }
      return { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次' };
    }
    return { ok: true };
  };
  await assert.rejects(
    () => team.kickOne(child.id),
    (error) => /已失效/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  const kept = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(kept.teamStatus, 'file_ready');
  assert.ok(await prisma.teamSecret.findUnique({ where: { accountId: child.id } }));
});

test('退出全部名单不一致时，已离开的子号也不删账密', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const goneImport = await team.importChildren('gone@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const stayImport = await team.importChildren('stay@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const gone = await prisma.account.findUnique({ where: { cardKey: goneImport.created[0].cardKey } });
  const stay = await prisma.account.findUnique({ where: { cardKey: stayImport.created[0].cardKey } });
  await prisma.account.update({
    where: { id: gone.id },
    data: { workspaceId: created.id, userId: 'gone-user', teamStatus: 'file_ready' },
  });
  await prisma.account.update({
    where: { id: stay.id },
    data: { workspaceId: created.id, userId: 'stay-user', teamStatus: 'file_ready' },
  });
  route = (path) => path.includes('snapshot')
    ? {
      ok: true,
      complete: true,
      seatsEntitled: 5,
      members: members([{ id: 'stay-user', email: 'stay@example.com', role: 'standard-user' }]),
      total: 2,
    }
    : { ok: true };
  calls.length = 0;
  await assert.rejects(
    () => team.kickAll(created.id, '退出全部', ['stay-user', 'extra-user']),
    (error) => /不一致/.test(errorText(error)) && /一个人都不会踢/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => item.path.includes('kick')), false);
  const keptGone = await prisma.account.findUnique({ where: { id: gone.id } });
  assert.equal(keptGone.teamStatus, 'file_ready');
  assert.ok(await prisma.teamSecret.findUnique({ where: { accountId: gone.id } }));
  const keptStay = await prisma.account.findUnique({ where: { id: stay.id } });
  assert.equal(keptStay.teamStatus, 'file_ready');
  assert.ok(await prisma.teamSecret.findUnique({ where: { accountId: stay.id } }));
  const job = await prisma.teamJob.findFirst({ where: { workspaceRowId: created.id, kind: 'kick-all' }, orderBy: { id: 'desc' } });
  assert.equal(job.status, 'failed');
  assert.match(job.message, /不一致/);
  assert.doesNotMatch(job.message, /已删除/);
});

test('分配邀请遇到刷新失败时说明真实原因，不发邀请', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  route = (path) => path.includes('snapshot')
    ? { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次' }
    : { ok: true };
  calls.length = 0;
  await assert.rejects(
    () => team.assign(created.id),
    (error) => /已失效/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => item.path.includes('invite')), false);
  const child = await prisma.account.findFirst({ where: { email: 'kid@example.com' } });
  assert.equal(child.teamStatus, 'waiting');
  assert.equal(child.workspaceId, null);
  const expiredJob = await prisma.teamJob.findFirst({ where: { workspaceRowId: created.id, kind: 'assign' }, orderBy: { id: 'desc' } });
  assert.equal(expiredJob.status, 'failed');
  assert.match(expiredJob.message, /已失效/);
  assert.doesNotMatch(expiredJob.message, /不完整/);

  const other = await mother(team, 'other-mother@example.com', 'ws-upstream');
  route = (path) => path.includes('snapshot')
    ? { ok: false, code: 'UPSTREAM', message: '上游暂时失败' }
    : { ok: true };
  calls.length = 0;
  await assert.rejects(
    () => team.assign(other.id),
    (error) => /上游暂时失败/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => item.path.includes('invite')), false);
  const upstreamJob = await prisma.teamJob.findFirst({ where: { workspaceRowId: other.id, kind: 'assign' }, orderBy: { id: 'desc' } });
  assert.equal(upstreamJob.status, 'failed');
  assert.match(upstreamJob.message, /上游暂时失败/);
  assert.doesNotMatch(upstreamJob.message, /不完整/);
});

test('选踢只剩已离开的人时，仍删除本地账密', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const goneImport = await team.importChildren('gone@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const stayImport = await team.importChildren('stay@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const gone = await prisma.account.findUnique({ where: { cardKey: goneImport.created[0].cardKey } });
  const stay = await prisma.account.findUnique({ where: { cardKey: stayImport.created[0].cardKey } });
  await prisma.account.update({
    where: { id: gone.id },
    data: { workspaceId: created.id, userId: 'gone-user', teamStatus: 'file_ready', accessToken: 'gone-at' },
  });
  await prisma.account.update({
    where: { id: stay.id },
    data: { workspaceId: created.id, userId: 'stay-user', teamStatus: 'file_ready', accessToken: 'stay-at' },
  });
  route = (path) => path.includes('snapshot')
    ? {
      ok: true,
      complete: true,
      seatsEntitled: 5,
      members: members([{ id: 'stay-user', email: 'stay@example.com', role: 'standard-user' }]),
      total: 2,
    }
    : { ok: true };
  calls.length = 0;
  const job = await team.kickSelected(created.id, '踢出选中', ['gone-user']);
  assert.match(job.message, /已确认退出并删除资料/);
  assert.doesNotMatch(job.message, /gone-user：已不在名单里，没有踢/);
  assert.doesNotMatch(job.message, /没有可踢出的成员/);
  assert.equal(calls.some((item) => item.path.includes('kick')), false);
  const wiped = await prisma.account.findUnique({ where: { id: gone.id } });
  assert.equal(wiped.teamStatus, 'kicked');
  assert.equal(wiped.accessToken, '');
  assert.equal(await prisma.teamSecret.findUnique({ where: { accountId: gone.id } }), null);
  const kept = await prisma.account.findUnique({ where: { id: stay.id } });
  assert.equal(kept.teamStatus, 'file_ready');
  assert.equal(kept.accessToken, 'stay-at');
});

test('选踢混有已离开的人时，不能再说没有踢', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const goneImport = await team.importChildren('gone@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const stayImport = await team.importChildren('stay@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const gone = await prisma.account.findUnique({ where: { cardKey: goneImport.created[0].cardKey } });
  const stay = await prisma.account.findUnique({ where: { cardKey: stayImport.created[0].cardKey } });
  await prisma.account.update({
    where: { id: gone.id },
    data: { workspaceId: created.id, userId: 'gone-user', teamStatus: 'file_ready', accessToken: 'gone-at' },
  });
  await prisma.account.update({
    where: { id: stay.id },
    data: { workspaceId: created.id, userId: 'stay-user', teamStatus: 'file_ready', accessToken: 'stay-at' },
  });
  route = (path) => {
    if (path.includes('kick')) return { ok: true };
    if (path.includes('snapshot')) {
      return {
        ok: true,
        complete: true,
        seatsEntitled: 5,
        members: members([{ id: 'stay-user', email: 'stay@example.com', role: 'standard-user' }]),
        total: 2,
      };
    }
    return { ok: true };
  };
  const job = await team.kickSelected(created.id, '踢出选中', ['gone-user', 'stay-user']);
  assert.match(job.message, /gone@example.com/);
  assert.match(job.message, /已确认退出并删除资料/);
  assert.doesNotMatch(job.message, /gone-user：已不在名单里，没有踢/);
  assert.match(job.message, /仍在名单里，没有删除资料/);
  const wiped = await prisma.account.findUnique({ where: { id: gone.id } });
  assert.equal(wiped.teamStatus, 'kicked');
  assert.equal(await prisma.teamSecret.findUnique({ where: { accountId: gone.id } }), null);
  const kept = await prisma.account.findUnique({ where: { id: stay.id } });
  assert.equal(kept.teamStatus, 'file_ready');
  assert.equal(kept.accessToken, 'stay-at');
});

test('刷新失败后快照标成不完整，但保留上次成员和到期', async (t) => {
  const { team } = await fixture(t);
  const created = await mother(team);
  route = (path) => path.includes('snapshot')
    ? {
      ok: true,
      complete: true,
      seatsEntitled: 5,
      willRenew: false,
      activeUntil: '2026-10-08T03:12:01Z',
      members: members([{ id: 'user-1', email: 'kid@example.com', role: 'standard-user' }]),
      total: 2,
    }
    : { ok: true };
  await team.refresh(created.id);
  route = (path) => path.includes('snapshot')
    ? { ok: false, code: 'UPSTREAM', message: '上游暂时失败' }
    : { ok: true };
  await assert.rejects(
    () => team.refresh(created.id),
    (error) => /上游暂时失败/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  const failed = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(failed.snapshotComplete, false);
  assert.equal(failed.seatsEntitled, 5);
  assert.equal(failed.activeUntil, '2026-10-08T03:12:01Z');
  assert.equal(failed.willRenew, false);
  assert.match(failed.lastError, /上游暂时失败/);
  const roster = await team.listRemoteMembers();
  const kid = roster.items.find((item) => item.email === 'kid@example.com');
  assert.equal(kid.snapshotComplete, false);
});

test('协议服务中断时刷新标成不完整，保留上次成员和到期，也不删账密', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'user-1', teamStatus: 'file_ready', accessToken: 'kid-at' },
  });
  route = (path) => path.includes('snapshot')
    ? {
      ok: true,
      complete: true,
      seatsEntitled: 5,
      willRenew: false,
      activeUntil: '2026-10-08T03:12:01Z',
      members: members([{ id: 'user-1', email: 'kid@example.com', role: 'standard-user' }]),
      total: 2,
    }
    : { ok: true };
  await team.refresh(created.id);
  const previousWorker = process.env.PROTOCOL_WORKER_URL;
  process.env.PROTOCOL_WORKER_URL = 'http://127.0.0.1:1';
  try {
    await assert.rejects(
      () => team.refresh(created.id),
      (error) => /协议服务调用失败/.test(errorText(error)) && !/不完整/.test(errorText(error)),
    );
    const failed = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
    assert.equal(failed.snapshotComplete, false);
    assert.equal(failed.sessionStatus, '有效');
    assert.equal(failed.seatsEntitled, 5);
    assert.equal(failed.activeUntil, '2026-10-08T03:12:01Z');
    assert.equal(failed.willRenew, false);
    assert.match(failed.lastError, /协议服务调用失败/);
    const roster = await team.listRemoteMembers();
    const kid = roster.items.find((item) => item.email === 'kid@example.com');
    assert.equal(kid.snapshotComplete, false);
    await assert.rejects(
      () => team.kickSelected(created.id, '踢出选中', ['user-1']),
      (error) => /协议服务调用失败/.test(errorText(error)),
    );
  } finally {
    process.env.PROTOCOL_WORKER_URL = previousWorker;
  }
  const kept = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(kept.teamStatus, 'file_ready');
  assert.equal(kept.accessToken, 'kid-at');
  assert.ok(await prisma.teamSecret.findUnique({ where: { accountId: child.id } }));
  assert.equal(calls.some((item) => String(item.path || '').includes('kick')), false);
});

test('撤回把母号标成失效时，名单也不能再踢', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const snapshot = {
    ok: true,
    complete: true,
    seatsEntitled: 5,
    willRenew: false,
    activeUntil: '2026-10-08T03:12:01Z',
    members: members([{ id: 'user-1', email: 'kid@example.com', role: 'standard-user' }]),
    invites: [{ email: 'pending@example.com' }],
    total: 2,
  };
  route = (path) => path.includes('snapshot') ? snapshot : { ok: true };
  await team.refresh(created.id);
  route = (path) => {
    if (path.includes('snapshot')) return snapshot;
    if (path.includes('revoke')) return { ok: false, code: 'SESSION_EXPIRED', message: '母号 session 已失效，请重新贴一次' };
    return { ok: true };
  };
  const job = await team.revokeInvites(created.id);
  assert.match(job.message, /已失效/);
  const expired = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(expired.sessionStatus, '已失效');
  assert.equal(expired.snapshotComplete, false);
  assert.equal(expired.seatsEntitled, 5);
  assert.equal(expired.activeUntil, '2026-10-08T03:12:01Z');
  assert.equal(expired.willRenew, false);
  const roster = await team.listRemoteMembers();
  assert.equal(roster.items.find((item) => item.email === 'kid@example.com').snapshotComplete, false);

  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: { sessionStatus: 'valid', snapshotComplete: true, lastError: null },
  });
  route = (path) => {
    if (path.includes('snapshot')) return snapshot;
    if (path.includes('revoke')) {
      return {
        ok: false,
        code: 'SESSION_EXPIRED',
        message: '母号 session 已失效，请重新贴一次',
        sessionUpdate: { sessionToken: 'rotated-session', accessToken: 'personal-at' },
      };
    }
    return { ok: true };
  };
  await team.revokeInvites(created.id);
  const kept = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(kept.sessionStatus, '有效');
  assert.equal(kept.snapshotComplete, true);
  assert.equal(kept.seatsEntitled, 5);
  assert.equal(kept.activeUntil, '2026-10-08T03:12:01Z');
  assert.match(String(kept.lastError || ''), /已保留/);
});

test('已经失效的母号再刷新或选踢，也会把名单标成不完整', async (t) => {
  const { prisma, team } = await fixture(t);
  const created = await mother(team);
  const imported = await team.importChildren('kid@example.com----chatgpt-pass----JBSWY3DPEHPK3PXP');
  const child = await prisma.account.findUnique({ where: { cardKey: imported.created[0].cardKey } });
  await prisma.account.update({
    where: { id: child.id },
    data: { workspaceId: created.id, userId: 'user-1', teamStatus: 'file_ready', accessToken: 'kid-at' },
  });
  route = (path) => path.includes('snapshot')
    ? {
      ok: true,
      complete: true,
      seatsEntitled: 5,
      willRenew: true,
      activeUntil: '2026-10-08T03:12:01Z',
      members: members([{ id: 'user-1', email: 'kid@example.com', role: 'standard-user' }]),
      total: 2,
    }
    : { ok: true };
  await team.refresh(created.id);
  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: { sessionStatus: 'expired', snapshotComplete: true },
  });
  calls.length = 0;
  await assert.rejects(
    () => team.refresh(created.id),
    (error) => /已失效/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => String(item.path || '').includes('snapshot')), false);
  const afterRefresh = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(afterRefresh.snapshotComplete, false);
  assert.equal(afterRefresh.seatsEntitled, 5);
  assert.equal(afterRefresh.activeUntil, '2026-10-08T03:12:01Z');
  assert.equal(afterRefresh.willRenew, true);
  const roster = await team.listRemoteMembers();
  assert.equal(roster.items.find((item) => item.email === 'kid@example.com').snapshotComplete, false);

  await prisma.teamWorkspace.update({
    where: { id: created.id },
    data: { snapshotComplete: true },
  });
  calls.length = 0;
  await assert.rejects(
    () => team.kickSelected(created.id, '踢出选中', ['user-1']),
    (error) => /已失效/.test(errorText(error)) && !/不完整/.test(errorText(error)),
  );
  assert.equal(calls.some((item) => String(item.path || '').includes('kick')), false);
  const afterKick = (await team.listWorkspaces()).items.find((item) => item.id === created.id);
  assert.equal(afterKick.snapshotComplete, false);
  assert.equal(afterKick.activeUntil, '2026-10-08T03:12:01Z');
  const kept = await prisma.account.findUnique({ where: { id: child.id } });
  assert.equal(kept.teamStatus, 'file_ready');
  assert.equal(kept.accessToken, 'kid-at');
  assert.ok(await prisma.teamSecret.findUnique({ where: { accountId: child.id } }));
});
