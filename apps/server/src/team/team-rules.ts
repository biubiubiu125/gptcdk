/** 5x Team 的纯规则。不访问网络，也不读数据库。 */

const EMAIL_RE = /^[^\s@|]+@[^\s@|]+\.[^\s@|]+$/;
const FIELD_SPLIT_RE = /\s*-{2,}\s*|\s*\|\s*/;
const TOTP_BASE32_RE = /^[A-Z2-7]{8,128}$/;
const INVITE_GAP_MS = 10 * 60 * 1000;

export interface TeamLine {
  email: string;
  password: string;
  totp: string;
}

export type TeamLineResult = { ok: true; line: TeamLine } | { ok: false; message: string };

export function normalizeTotpSecret(value: string): string {
  let text = String(value || '').trim();
  if (!text) throw new Error('缺少 2FA 密钥');
  if (text.toLowerCase().startsWith('otpauth://') || text.toLowerCase().startsWith('otpauth:')) {
    const parsed = new URL(text);
    text = parsed.searchParams.get('secret') || '';
  }
  const normalized = text.replace(/[\s\-_=]/g, '').toUpperCase();
  if (!TOTP_BASE32_RE.test(normalized)) throw new Error('2FA 密钥不是有效的 base32');
  return normalized;
}

export function kickTargets(
  members: Array<{ id?: string | null; email?: string | null; role?: string | null }> | null | undefined,
  motherEmail?: string | null,
): Array<{ id: string; email: string; role: string }> {
  const mother = String(motherEmail || '').trim().toLowerCase();
  return (Array.isArray(members) ? members : []).flatMap((item) => {
    const id = String(item?.id || '').trim();
    const role = String(item?.role || '').trim();
    const email = String(item?.email || '').trim();
    if (role !== 'standard-user' || !id) return [];
    if (mother && email.toLowerCase() === mother) return [];
    return [{ id, email, role }];
  });
}

export function sameMemberIds(left: string[], right: string[]): boolean {
  const normalize = (values: string[]) => [...new Set(values.map((item) => String(item || '').trim()).filter(Boolean))].sort();
  const a = normalize(left);
  const b = normalize(right);
  return a.length === b.length && a.every((item, index) => item === b[index]);
}

export function parseTeamLine(raw: string): TeamLineResult {
  const text = String(raw || '').trim();
  if (!text) return { ok: false, message: '空行' };
  const fields = text.split(FIELD_SPLIT_RE).map((part) => part.trim());
  if (fields.length === 4) return { ok: false, message: '这是取件凭据，不能加入 Team' };
  if (fields.some((part) => !part)) return { ok: false, message: '格式应为 邮箱----ChatGPT密码----2FA密钥' };
  let email = '';
  let password = '';
  let secret = '';
  if (fields.length === 3) {
    [email, password, secret] = fields;
  } else if (fields.length === 6) {
    email = fields[0];
    password = fields[4];
    secret = fields[5];
  } else {
    return { ok: false, message: '格式应为 邮箱----ChatGPT密码----2FA密钥' };
  }
  if (!EMAIL_RE.test(email)) return { ok: false, message: `邮箱不合法：${email}` };
  if (!password) return { ok: false, message: '缺少 ChatGPT 密码' };
  try {
    return { ok: true, line: { email: email.toLowerCase(), password, totp: normalizeTotpSecret(secret) } };
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : '2FA 密钥无效' };
  }
}

export function parseTeamLines(raw: string): { lines: TeamLine[]; errors: string[] } {
  const source = String(raw || '').split(/\r?\n/);
  const lines: TeamLine[] = [];
  const errors: string[] = [];
  const seen = new Set<string>();
  let index = 0;
  for (const rawLine of source) {
    const text = rawLine.trim();
    if (!text || text.startsWith('#')) continue;
    index += 1;
    const parsed = parseTeamLine(text);
    if (parsed.ok === false) {
      errors.push(`第 ${index} 行：${parsed.message}`);
      continue;
    }
    if (seen.has(parsed.line.email)) {
      errors.push(`第 ${index} 行：重复邮箱 ${parsed.line.email}，已跳过`);
      continue;
    }
    seen.add(parsed.line.email);
    lines.push(parsed.line);
  }
  return { lines, errors };
}

export function countedMembers(members: Array<{ email?: string | null }> | null | undefined, motherEmail?: string | null): number {
  const list = Array.isArray(members) ? members : [];
  const mother = String(motherEmail || '').trim().toLowerCase();
  const present = Boolean(mother) && list.some((item) => String(item?.email || '').trim().toLowerCase() === mother);
  return list.length + (present ? 0 : 1);
}

export function emptySeats(entitled: number | null | undefined, memberCount: number | null | undefined, complete: boolean): number | null {
  if (!complete || entitled == null || memberCount == null) return null;
  if (!Number.isInteger(entitled) || entitled < 0 || !Number.isInteger(memberCount) || memberCount < 0) return null;
  return Math.max(0, entitled - memberCount);
}

export function inviteSlots(empty: number | null): number {
  if (empty == null) return 0;
  // 未接受的邀请不算成员。空位只按订阅席位减当前名单。
  return Math.max(0, Math.min(25, empty));
}

export function inviteAllowed(lastInviteAt: Date | null | undefined, now = new Date()): boolean {
  if (!lastInviteAt) return true;
  return now.getTime() - lastInviteAt.getTime() >= INVITE_GAP_MS;
}

export function orderMothers<T extends { empty: number; createdAt: Date }>(rows: T[]): T[] {
  return rows
    .filter((row) => row.empty > 0)
    .sort((left, right) => left.empty - right.empty || left.createdAt.getTime() - right.createdAt.getTime());
}

export function resolveSocks(child?: string | null, mother?: string | null, globalProxy?: string | null): string | null {
  for (const value of [child, mother, globalProxy]) {
    const text = String(value || '').trim();
    if (text) return text;
  }
  return null;
}

export function normalizeSocks(value: string): string {
  const text = String(value || '').trim();
  if (!text) throw new Error('没有可用的 SOCKS 代理');
  if (/^https?:\/\//i.test(text)) throw new Error('只接受 SOCKS 代理');
  if (text.startsWith('socks5://') || text.startsWith('socks5h://')) return text;
  const parts = text.split(':');
  if (parts.length === 4 && /^\d+$/.test(parts[1]) && parts[0] && parts[2] && parts[3]) {
    return `socks5://${encodeURIComponent(parts[2])}:${encodeURIComponent(parts[3])}@${parts[0]}:${parts[1]}`;
  }
  if (parts.length === 2 && /^\d+$/.test(parts[1]) && parts[0]) return `socks5://${parts[0]}:${parts[1]}`;
  throw new Error('SOCKS 代理格式应为 socks5:// 或 host:port:user:pass');
}

export function confirmedAbsent(beforeIds: string[], afterIds: string[], targetIds: string[]): string[] {
  const before = new Set(beforeIds);
  const after = new Set(afterIds);
  return targetIds.filter((id) => before.has(id) && !after.has(id));
}

export function sessionAccessAndEmail(raw: string): { accessToken: string; email: string | null } {
  const text = String(raw || '').trim();
  if (!text) throw new Error('请贴 ChatGPT session');
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('session 必须是 JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('session 必须是 JSON 对象');
  const record = parsed as Record<string, unknown>;
  const accessToken = firstText(record.accessToken, record.access_token);
  if (!accessToken) throw new Error('session 里没有 accessToken');
  return { accessToken, email: emailFromSession(record, accessToken) };
}

export function emailsMatch(bound: string | null | undefined, next: string | null | undefined): boolean {
  if (!bound) return Boolean(next);
  if (!next) return false;
  return bound.trim().toLowerCase() === next.trim().toLowerCase();
}

export interface RemoteMember {
  id: string;
  email: string;
  role: string;
}

export interface SessionUpdate {
  accessToken?: string;
  sessionToken?: string;
  deviceId?: string;
  cookies?: Array<{ name?: string; value?: string; domain?: string }>;
}

export function normalizeRemoteMembers(value: unknown): RemoteMember[] {
  if (!Array.isArray(value)) return [];
  const members: RemoteMember[] = [];
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const row = item as { id?: unknown; email?: unknown; role?: unknown };
    const id = typeof row.id === 'string' ? row.id.trim() : '';
    const email = typeof row.email === 'string' ? row.email.trim() : '';
    const role = typeof row.role === 'string' ? row.role.trim() : '';
    if (!id || (!email && !role)) continue;
    members.push({ id, email, role });
  }
  return members;
}

export function parseRemoteMembers(raw?: string | null): RemoteMember[] {
  if (!raw) return [];
  try {
    return normalizeRemoteMembers(JSON.parse(raw));
  } catch {
    return [];
  }
}

export function normalizeActiveUntil(value: unknown): string | null {
  if (typeof value === 'number' && Number.isFinite(value)) return activeUntilFromUnix(value);
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text) return null;
  if (/^\d{10,13}$/.test(text)) return activeUntilFromUnix(Number(text));
  if (/(?:Z|[+-]\d{2}:?\d{2})$/i.test(text)) {
    const date = new Date(text);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }
  return text;
}

function activeUntilFromUnix(value: number): string | null {
  if (!Number.isFinite(value) || value <= 0) return null;
  const ms = value > 10_000_000_000 ? value : value * 1000;
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function stampDevice(session: string): string {
  const parsed = JSON.parse(session) as Record<string, unknown>;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('session 不是 JSON');
  if (!String(parsed.oaiDeviceId || '').trim()) parsed.oaiDeviceId = randomDevice();
  return JSON.stringify(parsed);
}

export function deviceIdOf(session: string): string {
  try {
    const parsed = JSON.parse(session) as { oaiDeviceId?: unknown };
    return typeof parsed.oaiDeviceId === 'string' ? parsed.oaiDeviceId.trim() : '';
  } catch {
    return '';
  }
}

export function mergeSession(plain: string, update?: SessionUpdate | null): string | null {
  if (!update || typeof update !== 'object') return null;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(plain) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  let changed = false;
  const accessToken = String(update.accessToken || '').trim();
  const sessionToken = String(update.sessionToken || '').trim();
  const deviceId = String(update.deviceId || '').trim();
  if (accessToken && accessToken !== parsed.accessToken) {
    parsed.accessToken = accessToken;
    changed = true;
  }
  if (sessionToken && sessionToken !== parsed.sessionToken) {
    parsed.sessionToken = sessionToken;
    changed = true;
  }
  if (deviceId && deviceId !== parsed.oaiDeviceId) {
    parsed.oaiDeviceId = deviceId;
    changed = true;
  }
  if (Array.isArray(update.cookies) && update.cookies.length) {
    const current = Array.isArray(parsed.cookies) ? parsed.cookies : [];
    const merged = mergeCookies(current, update.cookies);
    if (JSON.stringify(merged) !== JSON.stringify(current)) {
      parsed.cookies = merged;
      changed = true;
    }
  }
  if (!changed) return null;
  const stillUsable = String(parsed.accessToken || parsed.sessionToken || '').trim()
    || (Array.isArray(parsed.cookies) && parsed.cookies.length > 0);
  if (!stillUsable) return null;
  return JSON.stringify(parsed);
}

function mergeCookies(
  current: unknown[],
  incoming: Array<{ name?: string; value?: string; domain?: string }>,
): Array<{ name: string; value: string; domain: string }> {
  const merged = current
    .filter((item) => item && typeof item === 'object' && !Array.isArray(item))
    .map((item) => {
      const row = item as { name?: unknown; value?: unknown; domain?: unknown };
      return {
        name: String(row.name || '').trim(),
        value: String(row.value || '').trim(),
        domain: String(row.domain || '.chatgpt.com').trim() || '.chatgpt.com',
      };
    })
    .filter((item) => item.name && item.value);
  for (const item of incoming) {
    const name = String(item?.name || '').trim();
    const value = String(item?.value || '').trim();
    if (!name || !value) continue;
    const domain = String(item.domain || '.chatgpt.com').trim() || '.chatgpt.com';
    const index = merged.findIndex((row) => row.name === name);
    if (index >= 0) merged[index] = { name, value, domain };
    else merged.push({ name, value, domain });
  }
  return merged;
}

function randomDevice(): string {
  const bytes = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.map((item) => item.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function firstText(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function emailFromSession(record: Record<string, unknown>, accessToken: string): string | null {
  const direct = firstText(record.email);
  if (direct.includes('@')) return direct.toLowerCase();
  const payload = jwtPayload(accessToken);
  const claim = firstText(payload.email);
  if (claim.includes('@')) return claim.toLowerCase();
  const auth = payload['https://api.openai.com/auth'];
  if (auth && typeof auth === 'object' && !Array.isArray(auth)) {
    const nested = firstText((auth as Record<string, unknown>).email);
    if (nested.includes('@')) return nested.toLowerCase();
  }
  return null;
}

function jwtPayload(token: string): Record<string, unknown> {
  const part = token.split('.')[1];
  if (!part) return {};
  try {
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}
