import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { isDeliverFormat } from '../common/error-codes';
import { bizError } from '../common/utils';

export interface AppSettings {
  siteName: string;
  siteSubtitle: string;
  defaultFormat: string;
  redeemLimitPerCard: number;
  announcement: string;
}

export const DEFAULT_SETTINGS: AppSettings = {
  siteName: 'gptcdk',
  siteSubtitle: '卡密兑换',
  defaultFormat: 'sub2api',
  redeemLimitPerCard: 1,
  announcement: '',
};

const RETIRED_SETTING_KEYS = new Set(['pickupConcurrency', 'pickupMaxMessages', 'teamGlobalSocksProxy']);

@Injectable()
export class SettingsService {
  private cache: AppSettings | null = null;

  constructor(private readonly prisma: PrismaService) {}

  async getAll(): Promise<AppSettings> {
    if (this.cache) return this.cache;
    const rows = await this.prisma.setting.findMany();
    const merged = { ...DEFAULT_SETTINGS } as unknown as Record<string, string | number>;
    for (const row of rows) {
      if (RETIRED_SETTING_KEYS.has(row.key) || !(row.key in DEFAULT_SETTINGS)) continue;
      const current = merged[row.key];
      if (typeof current === 'number') {
        const num = Number(row.value);
        if (Number.isFinite(num)) merged[row.key] = num;
      } else {
        merged[row.key] = row.value;
      }
    }
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
}
