import { Module } from '@nestjs/common';
import { InternalMailboxController } from './internal-mailbox.controller';
import { PublicController } from './public.controller';
import { RedeemService } from './public.service';

@Module({
  controllers: [PublicController, InternalMailboxController],
  providers: [RedeemService],
  exports: [RedeemService],
})
export class PublicModule {}
