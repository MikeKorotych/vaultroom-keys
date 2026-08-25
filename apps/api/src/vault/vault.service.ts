import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import type { Prisma } from '../../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';

const MAX_ENVELOPE_BYTES = 2 * 1024 * 1024;
const HISTORY_LIMIT = 5;

@Injectable()
export class VaultService {
  constructor(private readonly prisma: PrismaService) {}

  async get(ownerId: string) {
    const vault = await this.prisma.encryptedVault.findUnique({
      where: { ownerId },
      select: { revision: true, envelope: true, updatedAt: true },
    });
    return { vault };
  }

  async put(
    ownerId: string,
    expectedRevision: number,
    envelope: Record<string, unknown>,
  ) {
    this.validateEnvelope(envelope);
    const envelopeJson = envelope as Prisma.InputJsonValue;

    return this.prisma.$transaction(async (transaction) => {
      const existing = await transaction.encryptedVault.findUnique({
        where: { ownerId },
      });

      if (!existing) {
        if (expectedRevision !== 0)
          throw new ConflictException('Vault revision changed');
        const created = await transaction.encryptedVault.create({
          data: { ownerId, revision: 1, envelope: envelopeJson },
          select: { revision: true, envelope: true, updatedAt: true },
        });
        return { vault: created };
      }

      if (existing.revision !== expectedRevision) {
        throw new ConflictException('Vault revision changed');
      }

      await transaction.vaultRevision.create({
        data: {
          vaultId: existing.id,
          revision: existing.revision,
          envelope: existing.envelope as Prisma.InputJsonValue,
        },
      });

      const nextRevision = existing.revision + 1;
      const updated = await transaction.encryptedVault.update({
        where: { id: existing.id },
        data: { revision: nextRevision, envelope: envelopeJson },
        select: { revision: true, envelope: true, updatedAt: true },
      });

      const expiredHistory = await transaction.vaultRevision.findMany({
        where: { vaultId: existing.id },
        orderBy: { revision: 'desc' },
        skip: HISTORY_LIMIT,
        select: { id: true },
      });
      if (expiredHistory.length) {
        await transaction.vaultRevision.deleteMany({
          where: { id: { in: expiredHistory.map((item) => item.id) } },
        });
      }
      return { vault: updated };
    });
  }

  private validateEnvelope(envelope: Record<string, unknown>) {
    const size = Buffer.byteLength(JSON.stringify(envelope));
    if (size > MAX_ENVELOPE_BYTES)
      throw new BadRequestException('Encrypted vault is too large');
    if (
      envelope.format !== 'vaultroom-keys' ||
      envelope.version !== 1 ||
      typeof envelope.kdf !== 'object' ||
      typeof envelope.passphraseWrappedKey !== 'object' ||
      typeof envelope.recoveryWrappedKey !== 'object' ||
      typeof envelope.payload !== 'object'
    ) {
      throw new BadRequestException('Invalid encrypted vault envelope');
    }
  }
}
