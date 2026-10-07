import { HttpException, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { Client } from 'pg';
import { PrismaService } from '../prisma/prisma.service';
import { SettingsService } from '../settings/settings.service';
import { bizError } from '../common/utils';
import { generateCardKey } from '../common/utils';
import type { ErrorCode } from '../common/error-codes';
import { decryptSecret, encryptSecret, teamSecretReady } from './team-crypto';
import {
  confirmedAbsent,
  deviceIdOf,
  emailsMatch,
  countedMembers,
  emptySeats,
  inviteAllowed,
  inviteSlots,
  kickTargets,
  mergeSession,
  normalizeActiveUntil,
  normalizeRemoteMembers,
  normalizeSocks,
  parseRemoteMembers,
  sameMemberIds,
  orderMothers,
  parseTeamLines,
  resolveSocks,
  sessionAccessAndEmail,
  stampDevice,
} from './team-rules';
import { workerConfigured, workerPost, type WorkerResponse } from './team-worker';

const SECRET_KEYS = new Set([
  'password', 'totp', 'totp_secret', 'totpSecret', 'two_factor_secret', 'twoFactorSecret', 'session', 'sessionToken', 'session_token',
]);
const ASSIGN_LOCK = 2147483001;
const EXPIRED_SESSION = '母号 session 已失效，请重新贴一次';

function responseText(body: unknown): string {
  if (typeof body === 'string' && body.trim()) return body;
  if (body && typeof body === 'object' && 'message' in body) {
    const message = (body as { message?: unknown }).message;
    if (typeof message === 'string' && message.trim()) return message;
  }
  return '';
}

function jobText(error: unknown): string {
  if (error && typeof error === 'object') {
    const candidate = error as { getResponse?: () => unknown; response?: unknown };
    if (typeof candidate.getResponse === 'function') {
      try {
        const text = responseText(candidate.getResponse.call(error));
        if (text) return text;
      } catch {
        const text = responseText(candidate.response);
        if (text) return text;
      }
    }
  }
  if (error instanceof Error && error.message.trim() && error.message !== 'Http Exception') return error.message;
  return '任务失败';
}

@Injectable()
export class TeamService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(TeamService.name);
  private keepAliveTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly settings: SettingsService,
  ) {}

  onModuleInit() {
    this.keepAliveTimer = setInterval(() => {
      void this.keepAlive();
    }, 6 * 60 * 60 * 1000);
    this.keepAliveTimer.unref?.();
  }

  onModuleDestroy() {
    if (this.keepAliveTimer) clearInterval(this.keepAliveTimer);
    this.keepAliveTimer = null;
  }

  status() {
    return {
      secretReady: teamSecretReady(),
      workerReady: workerConfigured(),
    };
  }

  async listWorkspaces() {
    const rows = await this.prisma.teamWorkspace.findMany({ orderBy: { id: 'asc' } });
    return { items: rows.map((row) => this.workspaceView(row, false)) };
  }

  async revealSession(id: number) {
    const row = await this.workspaceOrThrow(id);
    return { id: row.id, email: row.motherEmail, session: decryptSecret(row.sessionCipher) };
  }

  async previewSession(id: number) {
    this.requireSecret();
    const row = await this.workspaceOrThrow(id);
    return {
      id: row.id,
      email: row.motherEmail,
      preview: sessionPreview(decryptSecret(row.sessionCipher)),
      canAutoRenew: this.canAutoRenew(row.sessionCipher),
    };
  }

  async createWorkspace(body: { session?: string; socks?: string; workspaceId?: string }) {
    this.requireSecret();
    const rawSession = String(body?.session || '');
    const parsed = this.readSession(rawSession);
    const session = stampDevice(rawSession);
    const explicit = this.optionalSocks(body?.socks);
    const socks = explicit || await this.globalSocks();
    const inspected = await this.inspect(session, socks);
    try {
      if (!inspected.ok) this.failWithSession(inspected, 'UPSTREAM_ERROR', inspected.message || '母号 session 已失效，请重新贴一次');
      const storedSession = inspected.session || session;
      const email = inspected.email || parsed.email;
      if (!email) this.failWithSession(inspected, 'BAD_INPUT', 'session 里读不出母号邮箱');
      const chosen = this.chooseWorkspace(inspected.workspaces || [], body?.workspaceId);
      if (chosen?.id) await this.assertRemoteWorkspaceFree(String(chosen.id));
      const row = await this.prisma.teamWorkspace.create({
        data: {
          motherEmail: email,
          displayName: chosen?.name || email,
          openaiWorkspaceId: chosen?.id || null,
          sessionCipher: encryptSecret(storedSession),
          sessionStatus: 'valid',
          socksCipher: explicit ? encryptSecret(explicit) : null,
          lastSuccessAt: new Date(),
          updatedAt: new Date(),
        },
      });
      await this.refreshQuiet(row.id);
      return this.workspaceView(await this.workspaceOrThrow(row.id), false);
    } catch (error) {
      if (isUniqueViolation(error)) this.failWithSession(inspected, 'CONFLICT', '这个 ChatGPT 空间已经绑定过，不能再开一行');
      this.rethrowWithSession(error, inspected);
    }
  }

  async updateWorkspace(id: number, body: { session?: string; socks?: string; workspaceId?: string; clearSocks?: boolean }) {
    this.requireSecret();
    const current = await this.workspaceOrThrow(id);
    const data: Prisma.TeamWorkspaceUpdateInput = { updatedAt: new Date() };
    let keptInspect: { rotated?: boolean; session?: string } | null = null;
    if (body?.session) {
      const parsed = this.readSession(body.session);
      if (parsed.email && !emailsMatch(current.motherEmail, parsed.email)) {
        bizError('BAD_INPUT', '新 session 的邮箱和已绑定母号不一致');
      }
      const socks = body.clearSocks
        ? await this.globalSocks()
        : (this.optionalSocks(body.socks) || this.readOptional(current.socksCipher) || await this.globalSocks());
      const inspected = await this.inspect(stampDevice(body.session), socks);
      keptInspect = inspected;
      const liveEmail = String(inspected.email || '').trim();
      const confirmed = Boolean(liveEmail) && emailsMatch(current.motherEmail, liveEmail);
      const foreign = Boolean(liveEmail) && !confirmed;
      if (confirmed && inspected.rotated && inspected.session) await this.persistRotated(id, inspected);
      else if (!foreign && !inspected.ok && !inspected.rotated && (confirmed || this.samePastedSession(current.sessionCipher, body.session))) {
        await this.markSession(id, inspected, body.session);
      }
      try {
        if (!inspected.ok) this.failWithSession(inspected, 'UPSTREAM_ERROR', inspected.message || '母号 session 已失效，请重新贴一次');
        const email = inspected.email || parsed.email;
        if (!email || !emailsMatch(current.motherEmail, email)) {
          this.failWithSession(inspected, 'BAD_INPUT', '新 session 的邮箱和已绑定母号不一致');
        }
        const currentWorkspace = (inspected.workspaces || []).find((item) => item.id === current.openaiWorkspaceId);
        const stillThere = Boolean(currentWorkspace);
        data.sessionCipher = encryptSecret(inspected.session || stampDevice(body.session));
        data.sessionStatus = 'valid';
        data.lastSuccessAt = new Date();
        if (current.lastError && /已失效/.test(current.lastError)) data.lastError = null;
        if (!stillThere) {
          const requested = String(body.workspaceId || '').trim();
          if (!requested) this.failWithSession(inspected, 'BAD_INPUT', '原空间不在这份 session 里，请选择空间后再保存');
          const chosen = this.chooseWorkspace(inspected.workspaces || [], requested);
          data.openaiWorkspaceId = chosen.id;
          data.displayName = chosen.name || current.displayName;
        } else if (body.workspaceId && body.workspaceId !== current.openaiWorkspaceId) {
          this.failWithSession(inspected, 'BAD_INPUT', '不能悄悄换成另一个空间');
        } else if (!this.isOwnerWorkspace(currentWorkspace)) {
          this.failWithSession(inspected, 'BAD_INPUT', '原空间已不是所有者，不能继续绑定');
        }
      } catch (error) {
        this.rethrowWithSession(error, inspected);
      }
    }
    if (body?.clearSocks) data.socksCipher = null;
    else if (body?.socks != null) data.socksCipher = body.socks.trim() ? encryptSecret(this.optionalSocks(body.socks) || '') : null;
    if (body?.workspaceId && !body.session && body.workspaceId !== current.openaiWorkspaceId) {
      bizError('BAD_INPUT', '不能悄悄换成另一个空间');
    }
    if (body?.session && current.inviteHold === 'stopped') data.inviteHold = null;
    const remoteChanged = typeof data.openaiWorkspaceId === 'string' && data.openaiWorkspaceId !== current.openaiWorkspaceId;
    if (remoteChanged) await this.assertRemoteWorkspaceFree(String(data.openaiWorkspaceId), id);
    try {
      const saved = await this.prisma.$transaction(async (tx) => {
        const detached = remoteChanged ? await this.detachReboundChildren(tx, id, current.openaiWorkspaceId) : [];
        const row = await tx.teamWorkspace.update({ where: { id }, data });
        return { row, detached };
      });
      await this.refreshQuiet(saved.row.id);
      return { ...this.workspaceView(await this.workspaceOrThrow(id), false), detachedChildren: saved.detached };
    } catch (error) {
      if (isUniqueViolation(error)) {
        if (keptInspect) this.failWithSession(keptInspect, 'CONFLICT', '这个 ChatGPT 空间已经绑定过，不能再开一行');
        bizError('CONFLICT', '这个 ChatGPT 空间已经绑定过，不能再开一行');
      }
      if (keptInspect) this.rethrowWithSession(error, keptInspect);
      throw error;
    }
  }

  private async detachReboundChildren(tx: Prisma.TransactionClient, workspaceId: number, remoteId: string | null): Promise<string[]> {
    const rows = await tx.account.findMany({
      where: { workspaceId, stockKind: 'team', teamStatus: { not: 'kicked' } },
      select: { id: true, email: true, cardKey: true, teamStatus: true, userId: true },
    });
    const names: string[] = [];
    for (const row of rows) {
      const requeue = row.teamStatus === 'waiting' || row.teamStatus === 'invited';
      await tx.account.update({
        where: { id: row.id },
        data: {
          workspaceId: null,
          userId: null,
          priorUserId: requeue ? null : row.userId,
          priorRemoteWorkspaceId: requeue ? null : remoteId,
          teamStatus: requeue ? 'waiting' : row.teamStatus,
          updatedAt: new Date(),
        },
      });
      names.push(row.email || row.cardKey || String(row.id));
    }
    return names;
  }

  async importChildren(raw: string) {
    this.requireSecret();
    const parsed = parseTeamLines(raw);
    if (!parsed.lines.length) bizError('BAD_INPUT', parsed.errors[0] || '没有可加入的账号');
    const created: Array<{ email: string; cardKey: string }> = [];
    const errors = [...parsed.errors];
    for (const line of parsed.lines) {
      const existing = await this.prisma.account.findFirst({
        where: {
          stockKind: 'team',
          teamStatus: { not: 'kicked' },
          email: { equals: line.email, mode: 'insensitive' },
        },
        select: { id: true },
      });
      if (existing) {
        errors.push(`${line.email}：该邮箱已有未踢出的 Team 卡，未覆盖`);
        continue;
      }
      const cardKey = await this.uniqueCardKey();
      try {
        await this.prisma.$transaction(async (tx) => {
          const account = await tx.account.create({
            data: {
              name: line.email,
              email: line.email,
              credits: 0,
              cardKey,
              accessToken: '',
              rawSource: 'team',
              stockKind: 'team',
              teamStatus: 'waiting',
              banStatus: 'normal',
              updatedAt: new Date(),
            },
          });
          await tx.teamSecret.create({
            data: {
              accountId: account.id,
              passwordCipher: encryptSecret(line.password),
              totpCipher: encryptSecret(line.totp),
              updatedAt: new Date(),
            },
          });
        });
        created.push({ email: line.email, cardKey });
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
        errors.push(`${line.email}：该邮箱已有未踢出的 Team 卡，未覆盖`);
      }
    }
    let assignError = '';
    if (created.length) {
      try {
        const assigned = await this.assign();
        const failed = (assigned.results || []).filter((item) => item && item.ok === false && item.message);
        assignError = failed.map((item) => item.message).join('\n');
      } catch (error) {
        assignError = jobText(error);
      }
    }
    return { created, errors, assignError };
  }

  async listWaiting() {
    const rows = await this.prisma.account.findMany({
      where: { stockKind: 'team', teamStatus: { in: ['waiting', 'invited'] } },
      orderBy: { id: 'asc' },
      select: { id: true, email: true, cardKey: true, teamStatus: true, workspaceId: true, redeemStatus: true },
    });
    return { items: rows };
  }

  async listMembers(workspaceId?: number) {
    if (workspaceId) await this.workspaceOrThrow(workspaceId);
    const rows = await this.prisma.account.findMany({
      where: { stockKind: 'team', ...(workspaceId ? { workspaceId } : {}), teamStatus: { not: 'kicked' } },
      include: { teamUsage: true },
      orderBy: { id: 'asc' },
    });
    return {
      items: rows.map((row) => ({
        id: row.id,
        email: row.email,
        cardKey: row.cardKey,
        teamStatus: row.teamStatus,
        redeemStatus: row.redeemStatus,
        userId: row.userId,
        priorUserId: row.priorUserId,
        priorRemoteWorkspaceId: row.priorRemoteWorkspaceId,
        workspaceId: row.workspaceId,
        usage: this.usageView(row.teamUsage),
      })),
    };
  }

  async revealChild(accountId: number) {
    this.requireSecret();
    const account = await this.teamAccount(accountId);
    const secret = await this.prisma.teamSecret.findUnique({ where: { accountId } });
    if (!secret || account.teamStatus === 'kicked') bizError('NOT_FOUND', '该子号的账密已经删除');
    return {
      id: account.id,
      email: account.email,
      cardKey: account.cardKey,
      password: decryptSecret(secret.passwordCipher),
      totp: decryptSecret(secret.totpCipher),
      socks: secret.socksCipher ? decryptSecret(secret.socksCipher) : '',
    };
  }

  async updateChildProxy(accountId: number, socks: string) {
    this.requireSecret();
    await this.teamAccount(accountId);
    const normalized = socks.trim() ? normalizeSocks(socks) : '';
    await this.prisma.teamSecret.update({
      where: { accountId },
      data: { socksCipher: normalized ? encryptSecret(normalized) : null, updatedAt: new Date() },
    });
    return { ok: true };
  }

  async assign(workspaceId?: number) {
    this.requireReady();
    if (workspaceId) return { results: [await this.assignOne(workspaceId)] };
    const mothers = await this.prisma.teamWorkspace.findMany({
      where: { openaiWorkspaceId: { not: null } },
      orderBy: { createdAt: 'asc' },
    });
    const ranked = [];
    const skipped = [];
    const onboardOnly = [];
    for (const mother of mothers) {
      if (mother.sessionStatus === 'expired') {
        await this.markSnapshotIncomplete(mother.id);
        skipped.push({ id: mother.id, ok: false, message: EXPIRED_SESSION });
        continue;
      }
      let snapshot;
      try {
        snapshot = await this.snapshot(mother);
      } catch (error) {
        skipped.push({ id: mother.id, ok: false, message: jobText(error) });
        continue;
      }
      const empty = emptySeats(snapshot.seatsEntitled, countedMembers(snapshot.members, mother.motherEmail), Boolean(snapshot.complete));
      if (empty == null || empty <= 0) {
        onboardOnly.push(mother.id);
        continue;
      }
      ranked.push({ id: mother.id, empty, createdAt: mother.createdAt });
    }
    const results = [...skipped];
    for (const id of onboardOnly) {
      try {
        results.push(await this.assignOne(id));
      } catch (error) {
        results.push({ id, ok: false, message: jobText(error) });
      }
    }
    for (const mother of orderMothers(ranked)) {
      try {
        results.push(await this.assignOne(mother.id));
      } catch (error) {
        results.push({ id: mother.id, ok: false, message: jobText(error) });
      }
    }
    return { results };
  }

  async probe(workspaceId: number) {
    this.requireReady();
    const mother = await this.workspaceOrThrow(workspaceId);
    return this.runJob(mother.id, 'probe', async () => {
      const live = await this.workspaceOrThrow(workspaceId);
      if (live.sessionStatus === 'expired') {
        await this.markSnapshotIncomplete(live.id);
        bizError('UPSTREAM_ERROR', EXPIRED_SESSION);
      }
      const children = await this.prisma.account.findMany({
        where: { workspaceId, stockKind: 'team', teamStatus: { in: ['joined', 'file_ready'] } },
        orderBy: { id: 'asc' },
      });
      let probed = 0;
      const lines: string[] = [];
      for (const child of children) {
        const label = child.email || String(child.id);
        const secret = await this.prisma.teamSecret.findUnique({ where: { accountId: child.id } });
        const token = this.childAccess(secret?.tokenCipher);
        if (!token) {
          await this.writeUsage(child.id, { ok: false, usageStatus: 'unprobed' });
          lines.push(`${label}：没有子号 token，记为未探测`);
          continue;
        }
        const proxy = await this.proxyFor(child.id, mother.id);
        const result = await workerPost('internal/team/usage', {
          accessToken: token,
          workspaceId: mother.openaiWorkspaceId,
          proxy,
        });
        if (result.code === 'BANNED_EGRESS' || /封禁地区/.test(result.message || '')) {
          lines.push(`${label}：出口在封禁地区，已停止`);
          bizError('BAD_INPUT', ['出口在封禁地区，已停止', ...lines].join('\n'));
        }
        if (result.code === 'EGRESS_BLOCKED' || /出口被拦截|出口预检失败/.test(result.message || '')) {
          lines.push(`${label}：出口被拦截，已停止`);
          bizError('BAD_INPUT', ['出口被拦截，已停止', ...lines].join('\n'));
        }
        await this.writeUsage(child.id, result);
        lines.push(`${label}：${result.ok ? '已探测' : (result.message || '探测失败')}`);
        if (result.ok) probed += 1;
        else await this.markSession(mother.id, result);
      }
      return [`已探测 ${probed} 个已上车的子号`, ...lines].join('\n');
    });
  }

  async kickOne(accountId: number) {
    this.requireReady();
    const account = await this.teamAccount(accountId);
    const seat = await this.kickSeat(account);
    let removed: string[] = [];
    const job = await this.runJob(seat.workspaceId, 'kick', async () => {
      const outcome = await this.kickUsers(seat.workspaceId, [seat.userId]);
      removed = outcome.removed;
      return outcome.message;
    });
    if (removed.length) await this.assign(seat.workspaceId);
    return job;
  }

  private async kickSeat(account: { workspaceId: number | null; userId: string | null; priorUserId: string | null; priorRemoteWorkspaceId: string | null }) {
    if (account.workspaceId && account.userId) return { workspaceId: account.workspaceId, userId: account.userId };
    if (!account.priorUserId || !account.priorRemoteWorkspaceId) bizError('BAD_INPUT', '还没有确认成员编号，不能踢出');
    const mother = await this.prisma.teamWorkspace.findFirst({ where: { openaiWorkspaceId: account.priorRemoteWorkspaceId } });
    if (!mother) bizError('BAD_INPUT', '原空间没有绑定母号，不能确认踢出');
    return { workspaceId: mother.id, userId: account.priorUserId };
  }

  async previewKickAll(workspaceId: number) {
    this.requireReady();
    const mother = await this.workspaceOrThrow(workspaceId);
    const snapshot = await this.snapshot(mother);
    if (!snapshot.ok) bizError('UPSTREAM_ERROR', snapshot.message || '空间刷新失败');
    if (!snapshot.complete) bizError('CONFLICT', '成员快照不完整，一个人都不会踢');
    const targets = kickTargets(snapshot.members, mother.motherEmail);
    const locals = await this.prisma.account.findMany({
      where: {
        stockKind: 'team',
        teamStatus: { not: 'kicked' },
        OR: [
          { workspaceId },
          ...(mother.openaiWorkspaceId ? [{ workspaceId: null, priorRemoteWorkspaceId: mother.openaiWorkspaceId }] : []),
        ],
      },
      select: { email: true, cardKey: true, redeemStatus: true, userId: true, priorUserId: true },
    });
    const members = targets.map((item) => {
      const byId = locals.find((row) => (row.userId && row.userId === item.id) || (row.priorUserId && row.priorUserId === item.id));
      const byEmail = locals.find((row) => row.email && item.email && row.email.toLowerCase() === item.email.toLowerCase());
      const local = byId || byEmail;
      return {
        ...item,
        cardKey: local?.cardKey || '',
        redeemStatus: local?.redeemStatus || '',
      };
    });
    return { userIds: members.map((item) => item.id), members };
  }

  async kickAll(workspaceId: number, confirm: string, userIds: string[] = []) {
    this.requireReady();
    if (confirm !== '退出全部') bizError('BAD_INPUT', '请输入「退出全部」');
    const confirmed = [...new Set((userIds || []).map((item) => String(item || '').trim()).filter(Boolean))];
    if (!confirmed.length) bizError('BAD_INPUT', '请先确认要退出的成员');
    let removed: string[] = [];
    const job = await this.runJob(workspaceId, 'kick-all', async () => {
      const outcome = await this.kickUsers(workspaceId, confirmed, true);
      removed = outcome.removed;
      return outcome.message;
    });
    if (removed.length) await this.assign(workspaceId);
    return job;
  }

  async refresh(id: number) {
    this.requireReady();
    const mother = await this.workspaceOrThrow(id);
    if (mother.sessionStatus === 'expired') {
      await this.markSnapshotIncomplete(id);
      bizError('UPSTREAM_ERROR', EXPIRED_SESSION);
    }
    return this.runJob(id, 'refresh', async () => {
      const snapshot = await this.snapshot(mother);
      if (!snapshot.ok) bizError('UPSTREAM_ERROR', snapshot.message || '空间刷新失败');
      if (!snapshot.complete) {
        await this.prisma.teamWorkspace.update({
          where: { id },
          data: { lastError: '成员名单不完整', updatedAt: new Date() },
        });
        return '成员名单不完整';
      }
      const count = Array.isArray(snapshot.members) ? snapshot.members.length : 0;
      return `已刷新空间，成员 ${count} 人`;
    });
  }

  async kickSelected(workspaceId: number, confirm: string, userIds: string[] = []) {
    this.requireReady();
    if (confirm !== '踢出选中') bizError('BAD_INPUT', '请输入「踢出选中」');
    const requested = [...new Set((userIds || []).map((item) => String(item || '').trim()).filter(Boolean))];
    if (!requested.length) bizError('BAD_INPUT', '请先选择要踢出的成员');
    return this.runJob(workspaceId, 'kick-selected', async () => {
      const mother = await this.workspaceOrThrow(workspaceId);
      const before = await this.snapshot(mother);
      if (!before.ok) bizError('UPSTREAM_ERROR', before.message || '空间刷新失败');
      if (!before.complete) bizError('CONFLICT', '成员快照不完整，一个人都不会踢');
      const members = before.members || [];
      const motherEmail = String(mother.motherEmail || '').toLowerCase();
      const absentSkips: string[] = [];
      const otherSkips: string[] = [];
      const allowed: string[] = [];
      for (const id of requested) {
        const member = members.find((item) => item.id === id);
        if (!member) {
          absentSkips.push(`${id}：已不在名单里，没有踢`);
          continue;
        }
        if (member.role !== 'standard-user' || (member.email && member.email.toLowerCase() === motherEmail)) {
          otherSkips.push(`${member.email || id}：是所有者或母号，没有踢`);
          continue;
        }
        allowed.push(id);
      }
      if (!allowed.length && !absentSkips.length) return ['没有可踢出的成员', ...otherSkips].join('\n');
      const outcome = await this.kickUsers(workspaceId, allowed, false);
      const removed = new Set(outcome.removed);
      const stillAbsent = absentSkips.filter((line) => !removed.has(line.slice(0, line.indexOf('：'))));
      const head = !allowed.length && !outcome.removed.length ? '没有可踢出的成员' : outcome.message;
      return [head, ...otherSkips, ...stillAbsent].filter(Boolean).join('\n');
    });
  }

  async listRemoteMembers() {
    const rows = await this.prisma.teamWorkspace.findMany({ orderBy: { id: 'asc' } });
    const locals = await this.prisma.account.findMany({
      where: { stockKind: 'team', teamStatus: { not: 'kicked' } },
      select: { email: true, cardKey: true, redeemStatus: true, userId: true, workspaceId: true },
    });
    const items = rows.flatMap((row) => parseRemoteMembers(row.remoteMembersJson).map((member) => {
      const local = locals.find((item) => item.workspaceId === row.id && (
        (item.userId && item.userId === member.id)
        || (item.email && member.email && item.email.toLowerCase() === member.email.toLowerCase())
      ));
      return {
        key: `${row.id}:${member.id}`,
        workspaceRowId: row.id,
        workspaceName: row.displayName || row.motherEmail,
        motherEmail: row.motherEmail,
        snapshotComplete: row.snapshotComplete,
        id: member.id,
        email: member.email,
        role: member.role,
        cardKey: local?.cardKey || '',
        redeemStatus: local?.redeemStatus || '',
        local: Boolean(local),
      };
    }));
    return { items };
  }

  async revokeInvites(workspaceId: number) {
    this.requireReady();
    const mother = await this.workspaceOrThrow(workspaceId);
    return this.runJob(workspaceId, 'revoke', async () => {
      const proxy = await this.proxyFor(null, mother.id);
      const snapshot = await this.snapshot(mother);
      if (!snapshot.ok) bizError('UPSTREAM_ERROR', snapshot.message || '空间刷新失败');
      const emails = (snapshot.invites || []).map((item) => item.email).filter(Boolean);
      let cleared = 0;
      let failed = 0;
      const lines: string[] = [];
      for (const email of emails) {
        const session = await this.ensureDevice(mother.id, decryptSecret((await this.workspaceOrThrow(mother.id)).sessionCipher));
        const result = await workerPost('internal/team/revoke', {
          ...this.sessionFields(session),
          workspaceId: mother.openaiWorkspaceId,
          email,
          proxy,
        });
        await this.persistSession(mother.id, session, result);
        if (!result.ok) {
          await this.markSession(mother.id, result, session);
          failed += 1;
          const expired = result.code === 'SESSION_EXPIRED' || /session 已失效/.test(result.message || '');
          const kept = this.rotatedSession(session, result.sessionUpdate);
          lines.push(expired && !kept ? `${email}：母号 session 已失效，请重新贴一次` : `${email}：撤回被拒绝`);
          if (expired && !kept) break;
          continue;
        }
        await this.prisma.account.updateMany({
          where: { workspaceId, teamStatus: 'invited', email: { equals: email, mode: 'insensitive' } },
          data: { teamStatus: 'waiting', workspaceId: null, updatedAt: new Date() },
        });
        cleared += 1;
        lines.push(`${email}：已撤回，回到待分配`);
      }
      const cut = snapshot.invitesTruncated ? '，邀请名单被截断，没有全部撤回' : '';
      const summary = failed
        ? `已撤回 ${cleared} 个，${failed} 个上游拒绝撤回${cut}`
        : `已按邮箱撤回 ${cleared} 个未接受邀请${cut}`;
      return [summary, ...lines].join('\n');
    });
  }

  async listJobs() {
    const rows = await this.prisma.teamJob.findMany({ orderBy: { id: 'desc' }, take: 50 });
    return { items: rows };
  }

  private async assignOne(workspaceId: number) {
    const mother = await this.workspaceOrThrow(workspaceId);
    if (!mother.openaiWorkspaceId) return { id: mother.id, ok: false, message: '请先选择 Team 空间' };
    return this.runJob(mother.id, 'assign', async () => {
      const pending = await this.continueInvited(mother.id);
      const withPending = (message: string) => pending.length ? `${message}\n上车失败：\n${pending.join('\n')}` : message;
      const snapshot = await this.snapshot(mother);
      const fresh = await this.workspaceOrThrow(mother.id);
      if (fresh.inviteHold === 'stopped' || fresh.inviteHold === 'seat_full') {
        const held = fresh.inviteHold === 'stopped' ? '空间不可用已停止' : '席位已满已停止';
        if (pending.length) bizError('UPSTREAM_ERROR', withPending(held));
        return held;
      }
      if (!snapshot.ok) {
        const reason = snapshot.message || '空间刷新失败';
        if (pending.length) bizError('UPSTREAM_ERROR', withPending(reason));
        bizError('UPSTREAM_ERROR', reason);
      }
      if (!snapshot.complete) {
        if (pending.length) bizError('UPSTREAM_ERROR', withPending('成员快照不完整，没有发送邀请'));
        return '成员快照不完整，没有发送邀请';
      }
      if (snapshot.invitesTruncated) {
        if (pending.length) bizError('UPSTREAM_ERROR', withPending('邀请列表不完整，没有发送邀请'));
        return '邀请列表不完整，没有发送邀请';
      }
      const empty = emptySeats(snapshot.seatsEntitled, countedMembers(snapshot.members, mother.motherEmail), true);
      const slots = inviteSlots(empty);
      if (!slots) {
        if (pending.length) bizError('UPSTREAM_ERROR', withPending('没有空位，没有发送邀请'));
        return '没有空位，没有发送邀请';
      }
      if (!inviteAllowed(mother.lastInviteAt)) {
        if (pending.length) bizError('UPSTREAM_ERROR', withPending('距离上次邀请不足 10 分钟，没有发送新邀请'));
        return '距离上次邀请不足 10 分钟，没有发送新邀请';
      }
      const proxy = await this.proxyFor(null, mother.id);
      return this.withAssignLock(async () => {
        const claimed = await this.claimWaiting(mother.id, slots);
        if (!claimed.length) {
          if (pending.length) bizError('UPSTREAM_ERROR', withPending('没有等待分配的子号'));
          return '没有等待分配的子号';
        }
        let settled = false;
        try {
          const session = await this.ensureDevice(mother.id, decryptSecret((await this.workspaceOrThrow(mother.id)).sessionCipher));
          const invited = await workerPost('internal/team/invite', {
            ...this.sessionFields(session),
            workspaceId: mother.openaiWorkspaceId,
            emails: claimed.map((item) => item.email).filter((item): item is string => Boolean(item)),
            proxy,
          });
          await this.persistSession(mother.id, session, invited);
          await this.markSession(mother.id, invited, session);
          const successes = await this.persistInvite(mother.id, claimed, invited);
          const inviteSent = invited.inviteSent === true;
          const inviteHold = invited.stopped ? 'stopped' : invited.seatFull ? 'seat_full' : null;
          if (successes.size || inviteSent || inviteHold) {
            await this.prisma.teamWorkspace.update({
              where: { id: mother.id },
              data: {
                ...(successes.size || inviteSent ? { lastInviteAt: new Date() } : {}),
                ...(inviteHold ? { inviteHold } : {}),
                updatedAt: new Date(),
              },
            });
          }
          settled = true;
          pending.push(...await this.continueInvited(mother.id));
          const summary = this.inviteSummary(claimed, successes, invited);
          if (invited.seatFull || invited.stopped) {
            await this.snapshot(mother);
            const message = invited.message || '席位已满或空间不可用，已停止邀请';
            if (!invited.ok || pending.length) bizError('UPSTREAM_ERROR', withPending(`${message}\n${summary}`));
            return withPending(`${message}\n${summary}`);
          }
          if (!invited.ok || pending.length) {
            bizError('UPSTREAM_ERROR', withPending(invited.ok ? summary : `${invited.message || '邀请被拒绝'}\n${summary}`));
          }
          return summary;
        } finally {
          if (!settled) await this.releaseClaims(claimed.map((item) => item.id), mother.id);
        }
      });
    });
  }

  private async continueInvited(workspaceId: number): Promise<string[]> {
    const mother = await this.workspaceOrThrow(workspaceId);
    const invited = await this.prisma.account.findMany({
      where: { workspaceId, teamStatus: { in: ['invited', 'joined'] }, accessToken: '' },
      orderBy: { id: 'asc' },
    });
    const failures: string[] = [];
    for (const child of invited) {
      const secret = await this.prisma.teamSecret.findUnique({ where: { accountId: child.id } });
      if (!secret || !child.email) continue;
      const proxy = await this.proxyFor(child.id, mother.id);
      const onboard = await workerPost('internal/team/onboard', {
        email: child.email,
        password: decryptSecret(secret.passwordCipher),
        totp: decryptSecret(secret.totpCipher),
        workspaceId: mother.openaiWorkspaceId,
        proxy,
      });
      const snapshot = await this.snapshot(mother);
      const member = (snapshot.members || []).find((item) => item.email.toLowerCase() === child.email?.toLowerCase());
      if (!onboard.ok) {
        if (snapshot.complete && member) {
          await this.prisma.account.update({
            where: { id: child.id },
            data: { teamStatus: 'joined', userId: member.id || child.userId, updatedAt: new Date() },
          });
        } else {
          failures.push(`${child.email}：${onboard.message || '上车没有成功'}`);
        }
        continue;
      }
      if (!snapshot.complete || !member) {
        failures.push(`${child.email}：上车后快照里没有这个邮箱`);
        continue;
      }
      const document = accountDocument(stripSecrets(onboard.raw || {}));
      const accountId = textField(onboard.accountId) || credentialText(document, 'chatgpt_account_id');
      if (!onboard.accessToken || !accountId) {
        failures.push(`${child.email}：上车后没有可用文件`);
        continue;
      }
      const planType = textField(onboard.planType) || credentialText(document, 'plan_type') || null;
      const expiresAt = dateOrNull(onboard.expiresAt) || dateOrNull(credentialText(document, 'expires_at'));
      await this.prisma.account.update({
        where: { id: child.id },
        data: {
          teamStatus: 'file_ready',
          userId: textField(onboard.userId) || member.id,
          accountId,
          planType,
          expiresAt,
          accessToken: onboard.accessToken || '',
          refreshToken: onboard.refreshToken || null,
          idToken: onboard.idToken || null,
          rawJson: JSON.stringify(document),
          rawSource: 'sub2api',
          updatedAt: new Date(),
        },
      });
      await this.prisma.teamSecret.update({
        where: { accountId: child.id },
        data: {
          tokenCipher: encryptSecret(JSON.stringify({
            accessToken: onboard.accessToken || '',
            refreshToken: onboard.refreshToken || '',
            idToken: onboard.idToken || '',
          })),
          updatedAt: new Date(),
        },
      });
    }
    return failures;
  }

  private async kickUsers(workspaceId: number, userIds: string[], exact = false) {
    const mother = await this.workspaceOrThrow(workspaceId);
    const before = await this.snapshot(mother);
    if (!before.ok) bizError('UPSTREAM_ERROR', before.message || '空间刷新失败');
    if (!before.complete) bizError('CONFLICT', '成员快照不完整，一个人都不会踢');
    const members = before.members || [];
    const liveIds = kickTargets(members, mother.motherEmail).map((item) => item.id);
    if (exact && !sameMemberIds(userIds, liveIds)) bizError('CONFLICT', '要退出的成员和当前空间不一致，一个人都不会踢');
    const repaired = await this.wipeConfirmedMissing(mother, members.map((item) => item.id));
    const safeTargets = userIds.filter((id) => liveIds.includes(id));
    const limited = new Set<string>();
    for (const userId of safeTargets) {
      const member = members.find((item) => item.id === userId);
      const child = await this.localChild(workspaceId, userId, member?.email);
      const secret = child ? await this.prisma.teamSecret.findUnique({ where: { accountId: child.id } }) : null;
      const proxy = await this.proxyFor(child?.id ?? null, mother.id);
      const session = await this.ensureDevice(mother.id, decryptSecret((await this.workspaceOrThrow(mother.id)).sessionCipher));
      const kicked = await workerPost('internal/team/kick', {
        accessToken: this.childAccess(secret?.tokenCipher) || '',
        ...this.sessionFields(session),
        password: secret ? decryptSecret(secret.passwordCipher) : '',
        totp: secret ? decryptSecret(secret.totpCipher) : '',
        email: child?.email || member?.email || '',
        workspaceId: mother.openaiWorkspaceId,
        userId,
        proxy,
      });
      await this.persistSession(mother.id, session, kicked);
      if (kicked.rateLimited || /可能被限流/.test(kicked.message || '')) limited.add(userId);
    }
    if (!safeTargets.length) {
      const removed = repaired.map((item) => item.userId);
      const lines = repaired.map((item) => `${item.email || item.userId} / ${item.cardKey || '无卡密'} / ${item.redeemed ? '已兑换' : '未兑换'}：已确认退出并删除资料`);
      return { removed, message: [`已确认退出 ${removed.length} 人`, ...lines].filter(Boolean).join('\n') };
    }
    const after = await this.snapshot(mother);
    if (!after.ok) {
      const extra = repaired.length ? `已删除 ${repaired.length} 个已不在名单里的资料；` : '';
      bizError('UPSTREAM_ERROR', `${extra}${after.message || '空间刷新失败'}`);
    }
    if (!after.complete) {
      const extra = repaired.length ? `已删除 ${repaired.length} 个已不在名单里的资料；` : '';
      const tail = repaired.length
        ? '复核快照不完整，这次要踢的人没有删除账密或文件'
        : '复核快照不完整，没有删除任何账密或文件';
      bizError('CONFLICT', `${extra}${tail}`);
    }
    const removedNow = confirmedAbsent(members.map((item) => item.id), (after.members || []).map((item) => item.id), safeTargets);
    const removed = [...repaired.map((item) => item.userId), ...removedNow];
    const lines: string[] = repaired.map((item) => `${item.email || item.userId} / ${item.cardKey || '无卡密'} / ${item.redeemed ? '已兑换' : '未兑换'}：已确认退出并删除资料`);
    const warn = (userId: string) => limited.has(userId) ? '，可能被限流' : '';
    for (const userId of removedNow) {
      const member = members.find((item) => item.id === userId);
      const child = await this.localChild(workspaceId, userId, member?.email);
      lines.push(`${member?.email || userId} / ${child?.cardKey || '无卡密'} / ${child?.redeemStatus === 'redeemed' ? '已兑换' : '未兑换'}：已确认退出并删除资料${warn(userId)}`);
      if (child) await this.wipeChild(child.id);
    }
    const kept = safeTargets.filter((id) => !removed.includes(id));
    for (const userId of kept) {
      const member = members.find((item) => item.id === userId);
      const child = await this.localChild(workspaceId, userId, member?.email);
      lines.push(`${member?.email || userId} / ${child?.cardKey || '无卡密'} / ${child?.redeemStatus === 'redeemed' ? '已兑换' : '未兑换'}：仍在名单里，没有删除资料${warn(userId)}`);
    }
    const summary = kept.length
      ? `已确认退出 ${removed.length} 人，仍在名单里的 ${kept.length} 人没有删除资料`
      : `已确认退出 ${removed.length} 人`;
    const head = limited.size ? '母号 session 踢人，可能被限流' : '';
    return { removed, message: [head, summary, ...lines].filter(Boolean).join('\n') };
  }

  private async wipeConfirmedMissing(
    mother: { id: number; openaiWorkspaceId: string | null },
    memberIds: string[],
  ): Promise<Array<{ userId: string; email: string; cardKey: string; redeemed: boolean }>> {
    const present = new Set(memberIds.filter(Boolean));
    const bound = await this.prisma.account.findMany({
      where: {
        stockKind: 'team',
        teamStatus: { not: 'kicked' },
        workspaceId: mother.id,
        userId: { not: null },
      },
      select: { id: true, userId: true, email: true, cardKey: true, redeemStatus: true },
    });
    const detached = mother.openaiWorkspaceId
      ? await this.prisma.account.findMany({
          where: {
            stockKind: 'team',
            teamStatus: { not: 'kicked' },
            workspaceId: null,
            priorRemoteWorkspaceId: mother.openaiWorkspaceId,
            priorUserId: { not: null },
          },
          select: { id: true, priorUserId: true, email: true, cardKey: true, redeemStatus: true },
        })
      : [];
    const missing = [
      ...bound.filter((row) => row.userId && !present.has(row.userId)).map((row) => ({
        id: row.id,
        userId: row.userId as string,
        email: row.email || '',
        cardKey: row.cardKey || '',
        redeemed: row.redeemStatus === 'redeemed',
      })),
      ...detached.filter((row) => row.priorUserId && !present.has(row.priorUserId)).map((row) => ({
        id: row.id,
        userId: row.priorUserId as string,
        email: row.email || '',
        cardKey: row.cardKey || '',
        redeemed: row.redeemStatus === 'redeemed',
      })),
    ];
    for (const row of missing) await this.wipeChild(row.id);
    return missing.map(({ userId, email, cardKey, redeemed }) => ({ userId, email, cardKey, redeemed }));
  }

  private async wipeChild(accountId: number) {
    await this.prisma.$transaction(async (tx) => {
      await tx.teamSecret.deleteMany({ where: { accountId } });
      await tx.teamUsage.deleteMany({ where: { accountId } });
      await tx.account.update({
        where: { id: accountId },
        data: {
          teamStatus: 'kicked',
          kickedAt: new Date(),
          workspaceId: null,
          email: null,
          name: '已踢出',
          accessToken: '',
          refreshToken: null,
          idToken: null,
          sessionToken: null,
          rawJson: null,
          userId: null,
          priorUserId: null,
          priorRemoteWorkspaceId: null,
          accountId: null,
          updatedAt: new Date(),
        },
      });
    });
  }

  private seatHoldReleased(
    live: { inviteHold?: string | null; seatsEntitled?: number | null; memberCount?: number | null },
    seatsEntitled: number | null,
    memberCount: number | null,
    openSeats: number | null,
    complete: boolean,
  ): boolean {
    if (!complete || live.inviteHold !== 'seat_full' || openSeats == null || openSeats <= 0) return false;
    const seatsIncreased = seatsEntitled != null && live.seatsEntitled != null && seatsEntitled > live.seatsEntitled;
    const membersDecreased = memberCount != null && live.memberCount != null && memberCount < live.memberCount;
    return seatsIncreased || membersDecreased;
  }

  private async snapshot(mother: { id: number }) {
    const live = await this.workspaceOrThrow(mother.id);
    if (live.sessionStatus === 'expired') {
      await this.markSnapshotIncomplete(live.id);
      bizError('UPSTREAM_ERROR', EXPIRED_SESSION);
    }
    const proxy = await this.proxyFor(null, mother.id);
    const session = await this.ensureDevice(live.id, decryptSecret(live.sessionCipher));
    let result: WorkerResponse;
    try {
      result = await workerPost('internal/team/snapshot', {
        ...this.sessionFields(session),
        workspaceId: live.openaiWorkspaceId,
        proxy,
      });
    } catch (error) {
      this.logger.warn(`母号空间快照失败 id=${live.id} ${error instanceof Error ? error.name : 'error'}`);
      result = { ok: false, code: 'UPSTREAM_ERROR', message: '协议服务调用失败' };
    }
    const keptRotation = this.rotatedSession(session, result.sessionUpdate)
      && (result.code === 'SESSION_EXPIRED' || /session 已失效/.test(result.message || ''));
    await this.persistSession(live.id, session, result);
    const complete = Boolean(result.complete);
    await this.markSession(live.id, result, session, result.ok ? complete : undefined);
    if (!result.ok) {
      await this.noteFailure(live.id, result);
      await this.markSnapshotIncomplete(live.id);
      return {
        ...result,
        complete: false,
        members: parseRemoteMembers(live.remoteMembersJson),
        ...(keptRotation ? { message: '这次调用失败，已保留换过的 session，下次会再用' } : {}),
      };
    }
    const members = normalizeRemoteMembers(result.members);
    const subscriptionMissing = result.subscriptionRead === false;
    const expiry = subscriptionMissing ? (live.activeUntil ?? null) : normalizeActiveUntil(result.activeUntil);
    const memberCount = complete ? countedMembers(members, live.motherEmail) : null;
    const seats = subscriptionMissing
      ? (typeof live.seatsEntitled === 'number' ? live.seatsEntitled : null)
      : (result.seatsEntitled ?? null);
    const willRenew = subscriptionMissing ? (live.willRenew ?? null) : (result.willRenew ?? null);
    const openSeats = emptySeats(seats, memberCount, complete);
    const data: Prisma.TeamWorkspaceUpdateInput = {
      snapshotComplete: complete,
      snapshotAt: new Date(),
      updatedAt: new Date(),
    };
    if (complete) {
      data.remoteMembersJson = JSON.stringify(members);
      data.memberCount = memberCount;
      data.seatsEntitled = seats;
      data.activeUntil = expiry;
      data.willRenew = willRenew;
      if (this.seatHoldReleased(live, seats, memberCount, openSeats, complete)) data.inviteHold = null;
    } else if (!subscriptionMissing) {
      data.memberCount = null;
      if (typeof result.seatsEntitled === 'number') data.seatsEntitled = result.seatsEntitled;
      if (expiry) data.activeUntil = expiry;
      if (result.willRenew != null) data.willRenew = result.willRenew;
    } else {
      data.memberCount = null;
    }
    await this.prisma.teamWorkspace.update({ where: { id: live.id }, data });
    return {
      ...result,
      complete,
      seatsEntitled: seats,
      activeUntil: expiry,
      willRenew,
      members: complete ? members : parseRemoteMembers(live.remoteMembersJson),
    };
  }

  private async inspect(session: string, socks: string) {
    if (!workerConfigured()) bizError('UPSTREAM_ERROR', '协议服务未配置，不能检查母号 session', 503);
    if (!socks) bizError('BAD_INPUT', '没有可用的 SOCKS 代理');
    const stamped = stampDevice(session);
    const result = await workerPost('internal/session/inspect', { ...this.sessionFields(stamped), proxy: socks });
    const merged = mergeSession(stamped, result.sessionUpdate);
    return { ...result, session: merged || stamped, rotated: this.rotatedSession(stamped, result.sessionUpdate) };
  }

  private failWithSession(
    inspected: { rotated?: boolean; session?: string },
    code: ErrorCode,
    message: string,
    status = 400,
    details?: Record<string, unknown>,
  ): never {
    const extra = inspected.rotated && inspected.session
      ? { ...(details || {}), session: inspected.session }
      : details;
    bizError(code, message, status, extra);
  }

  private rethrowWithSession(error: unknown, inspected: { rotated?: boolean; session?: string }): never {
    if (!inspected.rotated || !inspected.session || !(error instanceof HttpException)) throw error;
    const body = error.getResponse();
    if (!body || typeof body !== 'object') throw error;
    const record = body as { code?: ErrorCode; message?: string; statusCode?: number; details?: Record<string, unknown> };
    this.failWithSession(
      inspected,
      record.code || 'BAD_INPUT',
      record.message || '保存失败',
      record.statusCode || error.getStatus(),
      record.details,
    );
  }

  private async persistRotated(id: number, inspected: { session: string; ok?: boolean }) {
    const data: Prisma.TeamWorkspaceUpdateInput = {
      sessionCipher: encryptSecret(inspected.session),
      updatedAt: new Date(),
    };
    if (!inspected.ok) {
      data.sessionStatus = 'valid';
      data.lastError = '这次调用失败，已保留换过的 session，下次会再用';
    }
    try {
      await this.prisma.teamWorkspace.update({ where: { id }, data });
    } catch (error) {
      this.logger.warn(`母号会话回写失败 id=${id} ${error instanceof Error ? error.name : 'error'}`);
    }
  }

  private isOwnerWorkspace(item?: { id?: string; role?: string; planType?: string; deactivated?: boolean } | null): boolean {
    return Boolean(item?.id)
      && !item?.deactivated
      && String(item?.planType || '').toLowerCase().includes('team')
      && String(item?.role || '').trim().toLowerCase() === 'account-owner';
  }

  private chooseWorkspace(items: NonNullable<WorkerResponse['workspaces']>, requested?: string) {
    const usable = items.filter((item) => this.isOwnerWorkspace(item));
    if (requested) {
      const found = items.find((item) => item.id === requested);
      if (!found) bizError('BAD_INPUT', '选择的空间不在这份 session 里');
      if (found.deactivated) bizError('BAD_INPUT', '选择的空间已停用，不能绑定');
      if (!String(found.planType || '').toLowerCase().includes('team')) bizError('BAD_INPUT', '选择的空间不是 Team，不能绑定');
      if (String(found.role || '').trim().toLowerCase() !== 'account-owner') bizError('BAD_INPUT', '选择的空间不是所有者，不能绑定');
      return found;
    }
    if (usable.length === 1) return usable[0];
    if (usable.length > 1) {
      bizError('BAD_INPUT', '这份 session 有多个 Team 空间，请点选一个', 400, {
        workspaces: usable.map((item) => ({
          id: item.id,
          name: item.name || item.id,
          role: item.role || '',
          planType: item.planType || '',
        })),
      });
    }
    const hasTeam = items.some((item) => item.id && !item.deactivated && String(item.planType || '').toLowerCase().includes('team'));
    bizError('BAD_INPUT', hasTeam ? '这份 session 不是空间所有者，不能绑定' : '这份 session 里没有可用的 Team 空间');
  }

  private async localChild(workspaceId: number, userId: string, email?: string) {
    const byId = userId
      ? await this.prisma.account.findFirst({
          where: { workspaceId, userId, stockKind: 'team', teamStatus: { not: 'kicked' } },
        })
      : null;
    if (byId) return byId;
    const mother = await this.workspaceOrThrow(workspaceId);
    const remote = mother.openaiWorkspaceId || '';
    if (userId && remote) {
      const prior = await this.prisma.account.findFirst({
        where: {
          workspaceId: null,
          priorUserId: userId,
          priorRemoteWorkspaceId: remote,
          stockKind: 'team',
          teamStatus: { not: 'kicked' },
        },
      });
      if (prior) return prior;
    }
    const normalized = String(email || '').trim();
    if (!normalized) return null;
    const byEmail = await this.prisma.account.findFirst({
      where: {
        workspaceId,
        stockKind: 'team',
        teamStatus: { not: 'kicked' },
        email: { equals: normalized, mode: 'insensitive' },
      },
    });
    if (byEmail || !remote) return byEmail;
    return this.prisma.account.findFirst({
      where: {
        workspaceId: null,
        priorRemoteWorkspaceId: remote,
        stockKind: 'team',
        teamStatus: { not: 'kicked' },
        email: { equals: normalized, mode: 'insensitive' },
      },
    });
  }

  private async globalSocks(): Promise<string> {
    const settings = await this.settings.getAll();
    const value = String(settings.teamGlobalSocksProxy || '').trim();
    return value ? normalizeSocks(value) : '';
  }

  private async proxyFor(accountId: number | null, workspaceId: number): Promise<string> {
    const settings = await this.settings.getAll();
    const child = accountId
      ? await this.prisma.teamSecret.findUnique({ where: { accountId }, select: { socksCipher: true } })
      : null;
    const mother = await this.prisma.teamWorkspace.findUnique({ where: { id: workspaceId }, select: { socksCipher: true } });
    const resolved = resolveSocks(
      child?.socksCipher ? decryptSecret(child.socksCipher) : '',
      mother?.socksCipher ? decryptSecret(mother.socksCipher) : '',
      settings.teamGlobalSocksProxy,
    );
    if (!resolved) bizError('BAD_INPUT', '没有可用的 SOCKS 代理，已停止');
    return normalizeSocks(resolved);
  }

  private async runJob(workspaceId: number, kind: string, fn: () => Promise<string>) {
    const schemaRows = await this.prisma.$queryRaw<Array<{ schema: string }>>`SELECT current_schema() AS schema`;
    const schema = schemaRows[0]?.schema;
    if (!schema) bizError('UPSTREAM_ERROR', '读不到当前数据库 schema');
    const client = new Client({ connectionString: pgConnectionString(process.env.DATABASE_URL || '') });
    await client.connect();
    let locked = false;
    let lockKey = `row:${workspaceId}`;
    try {
      await client.query(`SET search_path TO ${quoteIdent(schema)}`);
      const owner = await this.prisma.teamWorkspace.findUnique({ where: { id: workspaceId }, select: { openaiWorkspaceId: true } });
      lockKey = owner?.openaiWorkspaceId ? `ws:${owner.openaiWorkspaceId}` : lockKey;
      const lockedRow = await client.query<{ locked: boolean }>('SELECT pg_try_advisory_lock(hashtext(current_schema()), hashtext($1)) AS locked', [lockKey]);
      locked = Boolean(lockedRow.rows[0]?.locked);
      if (!locked) bizError('CONFLICT', '这个母号已有任务在跑');
      await this.prisma.teamJob.updateMany({
        where: { workspaceRowId: workspaceId, status: 'running' },
        data: { status: 'failed', message: '上次任务已中断', updatedAt: new Date() },
      });
      const job = await this.prisma.teamJob.create({
        data: { workspaceRowId: workspaceId, kind, status: 'running', updatedAt: new Date() },
      });
      try {
        const message = await fn();
        await this.prisma.teamJob.update({ where: { id: job.id }, data: { status: 'done', message, updatedAt: new Date() } });
        return { ok: true, message };
      } catch (error) {
        const message = jobText(error);
        await this.prisma.teamJob.update({ where: { id: job.id }, data: { status: 'failed', message, updatedAt: new Date() } });
        throw error;
      }
    } finally {
      if (locked) {
        await client.query('SELECT pg_advisory_unlock(hashtext(current_schema()), hashtext($1))', [lockKey]).catch(() => undefined);
      }
      await client.end().catch(() => undefined);
    }
  }

  private async writeUsage(accountId: number, result: WorkerResponse) {
    const status = usageStatus(result);
    await this.prisma.teamUsage.upsert({
      where: { accountId },
      create: {
        accountId,
        pct5h: numberOrNull(result.pct5h),
        reset5h: numberOrNull(result.reset5h),
        pct7d: numberOrNull(result.pct7d),
        reset7d: numberOrNull(result.reset7d),
        limitReached: result.limitReached ?? null,
        allowed: result.allowed ?? null,
        status,
        probedAt: new Date(),
      },
      update: {
        pct5h: numberOrNull(result.pct5h),
        reset5h: numberOrNull(result.reset5h),
        pct7d: numberOrNull(result.pct7d),
        reset7d: numberOrNull(result.reset7d),
        limitReached: result.limitReached ?? null,
        allowed: result.allowed ?? null,
        status,
        probedAt: new Date(),
      },
    });
  }

  private usageView(usage: { status: string; pct5h: number | null; pct7d: number | null; reset5h: number | null; reset7d: number | null } | null) {
    if (!usage || usage.status === 'unprobed') return { label: '未探测', pct5h: null, pct7d: null };
    if (usage.status === 'exhausted') return { label: '额度用尽', pct5h: usage.pct5h, pct7d: usage.pct7d, reset5h: usage.reset5h, reset7d: usage.reset7d };
    if (usage.status === 'short_window') return { label: '短窗已满', pct5h: usage.pct5h, pct7d: usage.pct7d, reset5h: usage.reset5h, reset7d: usage.reset7d };
    if (usage.status === 'auth_error') return { label: '登录或出口失败', pct5h: null, pct7d: null };
    return { label: '已探测', pct5h: usage.pct5h, pct7d: usage.pct7d, reset5h: usage.reset5h, reset7d: usage.reset7d };
  }

  private childAccess(cipher?: string | null): string {
    if (!cipher) return '';
    try {
      const parsed = JSON.parse(decryptSecret(cipher)) as { accessToken?: string };
      return parsed.accessToken || '';
    } catch {
      return '';
    }
  }

  private sessionFields(session: string) {
    return { session, deviceId: deviceIdOf(session) };
  }

  private async ensureDevice(id: number, plain: string): Promise<string> {
    if (deviceIdOf(plain)) return plain;
    let stamped = plain;
    try {
      stamped = stampDevice(plain);
    } catch {
      return plain;
    }
    if (!deviceIdOf(stamped)) return plain;
    try {
      await this.prisma.teamWorkspace.update({
        where: { id },
        data: { sessionCipher: encryptSecret(stamped), updatedAt: new Date() },
      });
    } catch (error) {
      this.logger.warn(`母号设备号回写失败 id=${id} ${error instanceof Error ? error.name : 'error'}`);
      return plain;
    }
    return stamped;
  }

  private samePastedSession(cipher: string, paste: string): boolean {
    try {
      const stored = JSON.parse(decryptSecret(cipher)) as Record<string, unknown>;
      const pasted = JSON.parse(paste) as Record<string, unknown>;
      const storedSession = String(stored.sessionToken || stored.session_token || '').trim();
      const pastedSession = String(pasted.sessionToken || pasted.session_token || '').trim();
      if (storedSession || pastedSession) return Boolean(storedSession) && storedSession === pastedSession;
      const storedAccess = String(stored.accessToken || stored.access_token || '').trim();
      const pastedAccess = String(pasted.accessToken || pasted.access_token || '').trim();
      return Boolean(storedAccess) && storedAccess === pastedAccess;
    } catch {
      return false;
    }
  }

  private rotatedSession(plain: string, update?: WorkerResponse['sessionUpdate']): boolean {
    if (!plain || !update) return false;
    let parsed: { accessToken?: string; sessionToken?: string; session_token?: string } = {};
    try {
      parsed = JSON.parse(plain) as { accessToken?: string; sessionToken?: string; session_token?: string };
    } catch {
      return false;
    }
    const nextToken = String(update.sessionToken || '').trim();
    const prevToken = String(parsed.sessionToken || parsed.session_token || '').trim();
    return Boolean(nextToken && nextToken !== prevToken);
  }

  private async persistSession(id: number, plain: string, result: WorkerResponse) {
    const merged = mergeSession(plain, result.sessionUpdate);
    if (!merged) return;
    try {
      await this.prisma.teamWorkspace.update({
        where: { id },
        data: { sessionCipher: encryptSecret(merged), updatedAt: new Date() },
      });
    } catch (error) {
      this.logger.warn(`母号会话回写失败 id=${id} ${error instanceof Error ? error.name : 'error'}`);
    }
  }

  private async noteFailure(id: number, result: WorkerResponse) {
    if (result.ok) return;
    const expired = result.code === 'SESSION_EXPIRED' || /session 已失效/.test(result.message || '');
    if (expired) return;
    await this.prisma.teamWorkspace.update({
      where: { id },
      data: { lastError: result.message || '空间刷新失败', updatedAt: new Date() },
    });
  }

  private async refreshQuiet(id: number) {
    try {
      await this.refresh(id);
    } catch (error) {
      this.logger.warn(`母号空间刷新失败 id=${id} ${error instanceof Error ? error.name : 'error'}`);
    }
  }

  private async keepAlive() {
    const rows = await this.prisma.teamWorkspace.findMany({
      where: { sessionStatus: { not: 'expired' } },
      select: { id: true, sessionCipher: true, socksCipher: true, openaiWorkspaceId: true },
    });
    for (const row of rows) {
      if (!this.canAutoRenew(row.sessionCipher)) continue;
      if (!row.socksCipher && !await this.globalSocks()) continue;
      const release = await this.tryWorkspaceLock(row.id, row.openaiWorkspaceId);
      if (!release) continue;
      try {
        await this.snapshot(row);
      } catch (error) {
        this.logger.warn(`母号保活失败 id=${row.id} ${error instanceof Error ? error.name : 'error'}`);
      } finally {
        await release();
      }
    }
  }

  private async tryWorkspaceLock(id: number, remoteId: string | null): Promise<(() => Promise<void>) | null> {
    const schemaRows = await this.prisma.$queryRaw<Array<{ schema: string }>>`SELECT current_schema() AS schema`;
    const schema = schemaRows[0]?.schema;
    if (!schema) return null;
    const client = new Client({ connectionString: pgConnectionString(process.env.DATABASE_URL || '') });
    const lockKey = remoteId ? `ws:${remoteId}` : `row:${id}`;
    let locked = false;
    try {
      await client.connect();
      await client.query(`SET search_path TO ${quoteIdent(schema)}`);
      const lockedRow = await client.query<{ locked: boolean }>('SELECT pg_try_advisory_lock(hashtext(current_schema()), hashtext($1)) AS locked', [lockKey]);
      locked = Boolean(lockedRow.rows[0]?.locked);
      if (!locked) {
        await client.end().catch(() => undefined);
        return null;
      }
      return async () => {
        await client.query('SELECT pg_advisory_unlock(hashtext(current_schema()), hashtext($1))', [lockKey]).catch(() => undefined);
        await client.end().catch(() => undefined);
      };
    } catch (error) {
      if (locked) {
        await client.query('SELECT pg_advisory_unlock(hashtext(current_schema()), hashtext($1))', [lockKey]).catch(() => undefined);
      }
      await client.end().catch(() => undefined);
      this.logger.warn(`母号保活锁失败 id=${id} ${error instanceof Error ? error.name : 'error'}`);
      return null;
    }
  }

  private async markSnapshotIncomplete(id: number) {
    await this.prisma.teamWorkspace.update({
      where: { id },
      data: { snapshotComplete: false, updatedAt: new Date() },
    });
  }

  private async markSession(id: number, result: WorkerResponse, plain = '', rosterComplete?: boolean) {
    if (result.code === 'SESSION_EXPIRED' || /session 已失效/.test(result.message || '')) {
      if (this.rotatedSession(plain, result.sessionUpdate)) {
        await this.prisma.teamWorkspace.update({
          where: { id },
          data: { lastError: '这次调用失败，已保留换过的 session，下次会再用', updatedAt: new Date() },
        });
        return;
      }
      await this.prisma.teamWorkspace.update({
        where: { id },
        data: {
          sessionStatus: 'expired',
          lastError: '母号 session 已失效，请重新贴一次',
          snapshotComplete: false,
          updatedAt: new Date(),
        },
      });
      return;
    }
    if (result.ok) {
      await this.prisma.teamWorkspace.update({
        where: { id },
        data: {
          sessionStatus: 'valid',
          lastSuccessAt: new Date(),
          lastError: rosterComplete === false ? '成员名单不完整' : null,
          updatedAt: new Date(),
        },
      });
    }
  }

  private workspaceView(row: {
    id: number;
    motherEmail: string;
    displayName: string | null;
    openaiWorkspaceId: string | null;
    sessionStatus: string;
    lastSuccessAt: Date | null;
    lastError: string | null;
    socksCipher: string | null;
    seatsEntitled: number | null;
    memberCount: number | null;
    snapshotComplete: boolean;
    activeUntil: string | null;
    willRenew: boolean | null;
    inviteHold?: string | null;
    sessionCipher?: string | null;
  }, reveal: boolean) {
    return {
      id: row.id,
      email: row.motherEmail,
      displayName: row.displayName,
      workspaceId: row.openaiWorkspaceId,
      sessionStatus: row.sessionStatus === 'valid' ? '有效' : row.sessionStatus === 'expired' ? '已失效' : '未知',
      lastSuccessAt: row.lastSuccessAt,
      lastError: row.lastError,
      hasSocks: Boolean(row.socksCipher),
      seatsEntitled: row.seatsEntitled,
      memberCount: row.memberCount,
      emptySeats: row.snapshotComplete && row.seatsEntitled != null && row.memberCount != null
        ? Math.max(0, row.seatsEntitled - row.memberCount)
        : null,
      snapshotComplete: row.snapshotComplete,
      activeUntil: row.activeUntil,
      willRenew: row.willRenew,
      inviteHold: row.inviteHold || null,
      canAutoRenew: this.canAutoRenew('sessionCipher' in row ? row.sessionCipher : null),
      session: reveal ? undefined : undefined,
    };
  }

  private canAutoRenew(cipher?: string | null): boolean {
    if (!cipher) return false;
    try {
      const parsed = JSON.parse(decryptSecret(cipher)) as { cookies?: unknown; sessionToken?: unknown; session_token?: unknown };
      if (String(parsed?.sessionToken || parsed?.session_token || '').trim()) return true;
      return Array.isArray(parsed?.cookies) && parsed.cookies.some((item) => {
        if (!item || typeof item !== 'object') return false;
        const cookie = item as { name?: unknown; value?: unknown };
        return typeof cookie.name === 'string' && cookie.name.trim().length > 0
          && typeof cookie.value === 'string' && cookie.value.trim().length > 0;
      });
    } catch {
      return false;
    }
  }

  private async workspaceOrThrow(id: number) {
    const row = await this.prisma.teamWorkspace.findUnique({ where: { id } });
    if (!row) bizError('NOT_FOUND', '母号空间不存在', 404);
    return row;
  }

  private async assertRemoteWorkspaceFree(openaiWorkspaceId: string, exceptId?: number) {
    const existing = await this.prisma.teamWorkspace.findFirst({
      where: { openaiWorkspaceId, ...(exceptId ? { id: { not: exceptId } } : {}) },
      select: { id: true },
    });
    if (existing) bizError('CONFLICT', '这个 ChatGPT 空间已经绑定过，不能再开一行');
  }

  private async teamAccount(id: number) {
    const row = await this.prisma.account.findUnique({ where: { id } });
    if (!row || row.stockKind !== 'team') bizError('NOT_FOUND', '子号不存在', 404);
    return row;
  }

  private requireSecret() {
    if (!teamSecretReady()) bizError('UPSTREAM_ERROR', 'GPTCDK_SECRET 未配置，Team 功能已停用', 503);
  }

  private requireReady() {
    this.requireSecret();
    if (!workerConfigured()) bizError('UPSTREAM_ERROR', '协议服务未配置，Team 操作已停用', 503);
  }

  private readSession(session: string) {
    try {
      return sessionAccessAndEmail(session);
    } catch (error) {
      bizError('BAD_INPUT', error instanceof Error ? error.message : 'session 无效');
    }
  }

  private optionalSocks(value?: string): string {
    const text = String(value || '').trim();
    if (!text) return '';
    try {
      return normalizeSocks(text);
    } catch (error) {
      bizError('BAD_INPUT', error instanceof Error ? error.message : '代理无效');
    }
  }

  private readOptional(cipher?: string | null): string {
    return cipher ? decryptSecret(cipher) : '';
  }

  private async withAssignLock<T>(fn: () => Promise<T>): Promise<T> {
    const schemaRows = await this.prisma.$queryRaw<Array<{ schema: string }>>`SELECT current_schema() AS schema`;
    const schema = schemaRows[0]?.schema;
    if (!schema) bizError('UPSTREAM_ERROR', '读不到当前数据库 schema');
    const client = new Client({ connectionString: pgConnectionString(process.env.DATABASE_URL || '') });
    await client.connect();
    let locked = false;
    try {
      await client.query(`SET search_path TO ${quoteIdent(schema)}`);
      await client.query('SELECT pg_advisory_lock(hashtext(current_schema()), $1)', [ASSIGN_LOCK]);
      locked = true;
      return await fn();
    } finally {
      if (locked) {
        await client.query('SELECT pg_advisory_unlock(hashtext(current_schema()), $1)', [ASSIGN_LOCK]).catch(() => undefined);
      }
      await client.end().catch(() => undefined);
    }
  }

  private async claimWaiting(workspaceId: number, slots: number): Promise<Array<{ id: number; email: string | null }>> {
    await this.prisma.$executeRaw`
      UPDATE "Account"
      SET "workspaceId" = NULL, "updatedAt" = NOW()
      WHERE "stockKind" = 'team'
        AND "teamStatus" = 'waiting'
        AND "workspaceId" IS NOT NULL
    `;
    return this.prisma.$queryRaw<Array<{ id: number; email: string | null }>>`
      WITH picked AS (
        SELECT "id" FROM "Account"
        WHERE "stockKind" = 'team'
          AND "teamStatus" = 'waiting'
          AND "workspaceId" IS NULL
          AND "email" IS NOT NULL
        ORDER BY "id" ASC
        LIMIT ${slots}
        FOR UPDATE SKIP LOCKED
      )
      UPDATE "Account" AS account
      SET "workspaceId" = ${workspaceId}, "updatedAt" = NOW()
      FROM picked
      WHERE account."id" = picked."id"
      RETURNING account."id" AS id, account."email" AS email
    `;
  }

  private async releaseClaims(ids: number[], workspaceId: number): Promise<void> {
    if (!ids.length) return;
    await this.prisma.account.updateMany({
      where: { id: { in: ids }, stockKind: 'team', teamStatus: 'waiting', workspaceId },
      data: { workspaceId: null, updatedAt: new Date() },
    });
  }

  private async persistInvite(
    workspaceId: number,
    claimed: Array<{ id: number; email: string | null }>,
    invited: WorkerResponse,
  ): Promise<Set<string>> {
    const errored = new Set((invited.errored || []).map((item) => item.toLowerCase()));
    const successes = new Set(
      (invited.successes || []).map((item) => item.toLowerCase()).filter((item) => item && !errored.has(item)),
    );
    const successIds = claimed
      .filter((item) => successes.has((item.email || '').toLowerCase()))
      .map((item) => item.id);
    if (successIds.length) {
      await this.prisma.account.updateMany({
        where: { id: { in: successIds }, stockKind: 'team', teamStatus: 'waiting', workspaceId },
        data: { teamStatus: 'invited', updatedAt: new Date() },
      });
    }
    await this.releaseClaims(claimed.filter((item) => !successIds.includes(item.id)).map((item) => item.id), workspaceId);
    return successes;
  }

  private inviteSummary(
    claimed: Array<{ id: number; email: string | null }>,
    successes: Set<string>,
    invited: WorkerResponse,
  ): string {
    const errored = new Set((invited.errored || []).map((item) => item.toLowerCase()));
    const lines = claimed.map((item) => {
      const email = item.email || String(item.id);
      const key = (item.email || '').toLowerCase();
      if (successes.has(key)) return `${email}：已邀请`;
      if (errored.has(key)) return `${email}：邀请失败，仍在待分配`;
      if (invited.seatFull) return `${email}：席位已满，没有发送成功，仍在待分配`;
      if (invited.stopped) return `${email}：空间不可用，没有发送成功，仍在待分配`;
      return `${email}：没有出现在成功名单，仍在待分配`;
    });
    return [`本轮邀请成功 ${successes.size} 个，失败 ${claimed.length - successes.size} 个`, ...lines].join('\n');
  }

  private async uniqueCardKey(): Promise<string> {
    const prefix = process.env.CARD_PREFIX || 'CARD';
    for (let attempt = 0; attempt < 12; attempt += 1) {
      const candidate = generateCardKey(prefix, 3, 5);
      const exists = await this.prisma.account.findUnique({ where: { cardKey: candidate }, select: { id: true } });
      if (!exists) return candidate;
    }
    return `${generateCardKey(prefix, 3, 5)}-${Date.now().toString(36).toUpperCase()}`;
  }
}

function stripSecrets(value: Record<string, unknown>): Record<string, unknown> {
  const copy: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (SECRET_KEYS.has(key)) continue;
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      copy[key] = stripSecrets(item as Record<string, unknown>);
    } else {
      copy[key] = item;
    }
  }
  return copy;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function textField(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function credentialText(document: Record<string, unknown>, key: string): string {
  const credentials = document.credentials;
  if (!credentials || typeof credentials !== 'object' || Array.isArray(credentials)) return '';
  return textField((credentials as Record<string, unknown>)[key]);
}

function nestedAccount(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const accounts = (value as Record<string, unknown>).accounts;
  if (!Array.isArray(accounts) || !accounts[0] || typeof accounts[0] !== 'object' || Array.isArray(accounts[0])) return null;
  return accounts[0] as Record<string, unknown>;
}

function accountDocument(raw: Record<string, unknown>): Record<string, unknown> {
  return nestedAccount(raw) || nestedAccount(raw.sub2api) || raw;
}

function dateOrNull(value: unknown): Date | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function isUniqueViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') return true;
  return error instanceof Error && error.message.includes('Account_team_active_email_key');
}

function sessionPreview(plain: string): string {
  const text = plain.replace(/\s+/g, ' ').trim();
  if (text.length <= 16) return '••••';
  return `${text.slice(0, 8)}…${text.slice(-4)}`;
}

function quoteIdent(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

function pgConnectionString(raw: string): string {
  const url = new URL(raw);
  url.searchParams.delete('schema');
  return url.toString();
}

function usageStatus(result: WorkerResponse): string {
  if (result.code === 'RATE_LIMITED' || result.httpStatus === 429) return 'unprobed';
  if (result.code === 'AUTH' || result.code === 'EGRESS_BLOCKED' || result.usageStatus === 'auth_error') return 'auth_error';
  if (!result.ok) return 'unprobed';
  if (result.usageStatus === 'exhausted' || result.limitReached === true || result.allowed === false) return 'exhausted';
  if (typeof result.pct7d === 'number' && result.pct7d >= 100) return 'exhausted';
  if (typeof result.pct5h === 'number' && result.pct5h >= 100) return 'short_window';
  if (result.usageStatus) return result.usageStatus;
  if (result.pct5h == null && result.pct7d == null) return 'unprobed';
  return 'probed';
}

export function orderReadyMothers<T extends { empty: number; createdAt: Date }>(rows: T[]): T[] {
  return orderMothers(rows);
}
