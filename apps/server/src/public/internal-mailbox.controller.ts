import { timingSafeEqual } from 'crypto';
import { Body, Controller, Headers, Post, UnauthorizedException } from '@nestjs/common';
import { RedeemService } from './public.service';

function bearerMatches(header: string | undefined, token: string): boolean {
  if (!token) return false;
  const actual = Buffer.from(String(header || ''));
  const expected = Buffer.from(`Bearer ${token}`);
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}

@Controller('internal')
export class InternalMailboxController {
  constructor(private readonly service: RedeemService) {}

  @Post('mailbox/otp')
  otp(
    @Body() body: { accountId?: number; email?: string; excludeIds?: string[]; baseline?: boolean },
    @Headers('authorization') authorization?: string,
  ) {
    if (!bearerMatches(authorization, process.env.PROTOCOL_WORKER_TOKEN || '')) {
      throw new UnauthorizedException('协议服务未授权');
    }
    return this.service.readMailboxOtp({
      accountId: Number(body?.accountId) || 0,
      email: String(body?.email || ''),
      excludeIds: Array.isArray(body?.excludeIds) ? body.excludeIds.map((item) => String(item)) : [],
      baseline: body?.baseline === true,
    });
  }
}
