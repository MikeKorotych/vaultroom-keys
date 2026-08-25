import { Body, Controller, Get, Put, UseGuards } from '@nestjs/common';
import { AuthUser } from '../auth/auth-user';
import { ClerkAuthGuard } from '../auth/clerk-auth.guard';
import { PutVaultDto } from './dto/vault.dto';
import { VaultService } from './vault.service';

@Controller('vault')
@UseGuards(ClerkAuthGuard)
export class VaultController {
  constructor(private readonly vaults: VaultService) {}

  @Get()
  get(@AuthUser() ownerId: string) {
    return this.vaults.get(ownerId);
  }

  @Put()
  put(@AuthUser() ownerId: string, @Body() input: PutVaultDto) {
    return this.vaults.put(ownerId, input.expectedRevision, input.envelope);
  }
}
