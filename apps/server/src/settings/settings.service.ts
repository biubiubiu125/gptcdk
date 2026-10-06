import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { isDeliverFormat } from '../common/error-codes';
import { bizError } from '../common/utils';
import { decryptSecret, encryptSecret, teamSecretReady } from '../team/team-crypto';
import { normalizeSocks } from '../team/team-rules';

export interface AppSettings {
  siteName: string;
  siteSubtitle: string;
  pickupConcurrency: number;
  pickupMaxMessages: number;
  defaultFormat: string;
  redeemLimitPerCard: number;
  announcement: string;
  teamGlobalSocksProxy: string;
}

export const DEFAULT_SETTINGS: AppSettings = {
  siteName: 'gptcdk',
  siteSubtitle: '卡密兑换',
  pickupConcurrency: 4,
  pickupMaxMessages: 30,
  defaultFormat: 'sub2api',
  redeemLimitPerCard: 1,
  announcement: '',
  teamGlobalSocksProxy: '',
};

@Injectable()
export class SettingsService {
  private cache: AppSettings | null = null;

  constructor(private readonly prisma: PrismaService) {}

  async getAll(): Promise<AppSettings> {
    if (this.cache) return this.cache;
    const rows = await this.prisma.setting.findMany();
    const merged = { ...DEFAULT_SETTINGS } as unknown as Record<string, string | number>;
    for (const row of rows) {
      if (!(row.key in DEFAULT_SETTINGS)) continue;
      const current = merged[row.key];
      if (typeof current === 'number') {
        const num = Number(row.value);
        if (Number.isFinite(num)) merged[row.key] = num;
      } else {
        merged[row.key] = row.value;
      }
    }
    merged.teamGlobalSocksProxy = await this.openGlobalSocks(String(merged.teamGlobalSocksProxy || ''));
    this.cache = merged as unknown as AppSettings;
    return this.cache;
  }

  async update(patch: Partial<AppSettings>): Promise<AppSettings> {
    const entries = Object.entries(patch || {}).filter(
      ([key, value]) => key in DEFAULT_SETTINGS && value !== undefined && value !== null,
    );
    for (const [key, value] of entries) {
      if (key === 'defaultFormat' && (!isDeliverFormat(value) || value === 'login')) {
        bizError('BAD_INPUT', '默认格式不能是账密');
      }
      if (key === 'teamGlobalSocksProxy') {
        await this.saveGlobalSocks(String(value));
        continue;
      }
      await this.prisma.setting.upsert({
        where: { key },
        create: { key, value: String(value) },
        update: { value: String(value) },
      });
    }
    this.cache = null;
    return this.getAll();
  }

  invalidate(): void {
    this.cache = null;
  }

  private async saveGlobalSocks(value: string): Promise<void> {
    const incoming = value.trim();
    if (!incoming) {
      const stored = await this.prisma.setting.findUnique({ where: { key: 'teamGlobalSocksProxy' } });
      if (stored?.value && !isPlainSocks(stored.value) && !teamSecretReady()) return;
      await this.prisma.setting.upsert({
        where: { key: 'teamGlobalSocksProxy' },
        create: { key: 'teamGlobalSocksProxy', value: '' },
        update: { value: '' },
      });
      return;
    }
    if (!teamSecretReady()) {
      bizError('BAD_INPUT', 'GPTCDK_SECRET 缺失或短于 32 字符，Team 功能已停用');
    }
    let normalized = '';
    try {
      normalized = normalizeSocks(incoming);
    } catch (error) {
      bizError('BAD_INPUT', error instanceof Error ? error.message : '只接受 SOCKS 代理');
    }
    const sealed = encryptSecret(normalized);
    await this.prisma.setting.upsert({
      where: { key: 'teamGlobalSocksProxy' },
      create: { key: 'teamGlobalSocksProxy', value: sealed },
      update: { value: sealed },
    });
  }

  private async openGlobalSocks(stored: string): Promise<string> {
    const text = stored.trim();
    if (!text) return '';
    if (isPlainSocks(text)) {
      if (!teamSecretReady()) return text;
      try {
        const normalized = normalizeSocks(text);
        await this.prisma.setting.update({
          where: { key: 'teamGlobalSocksProxy' },
          data: { value: encryptSecret(normalized) },
        });
        return normalized;
      } catch {
        return '';
      }
    }
    if (!teamSecretReady()) return '';
    try {
      return decryptSecret(text);
    } catch {
      return '';
    }
  }
}

function isPlainSocks(value: string): boolean {
  return /^socks5h?:\/\//i.test(value) || /^socks4a?:\/\//i.test(value);
}
