import { BadRequestException, ConflictException } from '@nestjs/common';

jest.mock('../prisma/prisma.service', () => ({
  PrismaService: class PrismaService {},
}));

import { VaultService } from './vault.service';

const envelope = {
  format: 'vaultroom-keys',
  version: 1,
  kdf: { algorithm: 'argon2id13' },
  passphraseWrappedKey: { ciphertext: 'opaque' },
  recoveryWrappedKey: { ciphertext: 'opaque' },
  payload: { ciphertext: 'opaque' },
};

describe('VaultService', () => {
  function setup() {
    let current: {
      id: string;
      ownerId: string;
      revision: number;
      envelope: object;
      updatedAt: Date;
    } | null = null;
    const history: Array<{
      id: string;
      vaultId: string;
      revision: number;
      envelope: object;
    }> = [];
    const transaction = {
      encryptedVault: {
        findUnique: jest.fn(() => Promise.resolve(current)),
        create: jest.fn(
          ({
            data,
          }: {
            data: { ownerId: string; revision: number; envelope: object };
          }) => {
            current = { id: 'vault-1', ...data, updatedAt: new Date() };
            return Promise.resolve(current);
          },
        ),
        update: jest.fn(
          ({ data }: { data: { revision: number; envelope: object } }) => {
            current = { ...current!, ...data, updatedAt: new Date() };
            return Promise.resolve(current);
          },
        ),
      },
      vaultRevision: {
        create: jest.fn(
          ({ data }: { data: Omit<(typeof history)[number], 'id'> }) => {
            const item = { id: `history-${history.length + 1}`, ...data };
            history.push(item);
            return Promise.resolve(item);
          },
        ),
        findMany: jest.fn(() => Promise.resolve([])),
        deleteMany: jest.fn(),
      },
    };
    const prisma = {
      encryptedVault: { findUnique: jest.fn(() => Promise.resolve(current)) },
      $transaction: jest.fn(
        (callback: (value: typeof transaction) => unknown) =>
          callback(transaction),
      ),
    } as never;
    return { service: new VaultService(prisma), history };
  }

  it('creates and revisions opaque envelopes', async () => {
    const { service, history } = setup();
    const created = await service.put('owner-1', 0, envelope);
    const updated = await service.put('owner-1', 1, {
      ...envelope,
      payload: { ciphertext: 'next' },
    });

    expect(created.vault.revision).toBe(1);
    expect(updated.vault.revision).toBe(2);
    expect(history).toHaveLength(1);
    expect(JSON.stringify(updated)).not.toContain('secret-value');
  });

  it('rejects stale writes', async () => {
    const { service } = setup();
    await service.put('owner-1', 0, envelope);
    await expect(service.put('owner-1', 0, envelope)).rejects.toBeInstanceOf(
      ConflictException,
    );
  });

  it('rejects a non-vault object', async () => {
    const { service } = setup();
    await expect(
      service.put('owner-1', 0, { hello: 'world' }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });
});
