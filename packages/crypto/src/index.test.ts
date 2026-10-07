import { describe, expect, it } from "vitest";
import {
  VaultCryptoError,
  createVault,
  destroyVaultKey,
  encryptVaultPayload,
  recoverVault,
  rekeyVault,
  unlockVault,
  validateVaultEnvelope,
  type VaultItem,
} from "./index";

const passphrase = "correct horse battery staple";

function fakeItem(): VaultItem {
  const now = "2026-08-25T12:00:00.000Z";
  return {
    id: "item-1",
    service: "OpenRouter",
    label: "Development",
    environment: "development",
    secret: "sk-or-v1-fake-never-use",
    notes: "Test fixture only",
    expiresAt: null,
    createdAt: now,
    updatedAt: now,
  };
}

describe("vault envelope", () => {
  it("round-trips an encrypted payload", async () => {
    const created = await createVault(passphrase);
    const envelope = await encryptVaultPayload(created.envelope, created.vaultKey, {
      version: 1,
      sequence: 1,
      items: [fakeItem()],
    });
    const unlocked = await unlockVault(envelope, passphrase);

    expect(unlocked.payload.sequence).toBe(1);
    expect(unlocked.payload.items[0]?.secret).toBe("sk-or-v1-fake-never-use");
    expect(JSON.stringify(envelope)).not.toContain("sk-or-v1-fake-never-use");

    await destroyVaultKey(created.vaultKey);
    await destroyVaultKey(unlocked.vaultKey);
  });

  it("rejects the wrong passphrase", async () => {
    const created = await createVault(passphrase);
    await expect(unlockVault(created.envelope, "this passphrase is incorrect")).rejects.toBeInstanceOf(
      VaultCryptoError,
    );
    await destroyVaultKey(created.vaultKey);
  });

  it("rejects a tampered payload", async () => {
    const created = await createVault(passphrase);
    const tampered = structuredClone(created.envelope);
    const last = tampered.payload.ciphertext.at(-1);
    tampered.payload.ciphertext = `${tampered.payload.ciphertext.slice(0, -1)}${last === "A" ? "B" : "A"}`;

    await expect(unlockVault(tampered, passphrase)).rejects.toBeInstanceOf(VaultCryptoError);
    await destroyVaultKey(created.vaultKey);
  });

  it("recovers the same vault with the recovery key", async () => {
    const created = await createVault(passphrase);
    const envelope = await encryptVaultPayload(created.envelope, created.vaultKey, {
      version: 1,
      sequence: 1,
      items: [fakeItem()],
    });
    const recovered = await recoverVault(envelope, created.recoveryKey);

    expect(recovered.payload.items[0]?.service).toBe("OpenRouter");

    await destroyVaultKey(created.vaultKey);
    await destroyVaultKey(recovered.vaultKey);
  });

  it("rekeys on recovery so the old passphrase and recovery key stop working", async () => {
    const created = await createVault(passphrase);
    const envelope = await encryptVaultPayload(created.envelope, created.vaultKey, {
      version: 1,
      sequence: 1,
      items: [fakeItem()],
    });
    const recovered = await recoverVault(envelope, created.recoveryKey);
    const rekeyed = await rekeyVault(recovered, "a brand new passphrase");

    expect(rekeyed.recoveryKey).not.toBe(created.recoveryKey);
    expect(rekeyed.vaultKey).not.toEqual(recovered.vaultKey);
    expect(rekeyed.envelope.createdAt).toBe(created.envelope.createdAt);
    await expect(unlockVault(rekeyed.envelope, passphrase)).rejects.toBeInstanceOf(VaultCryptoError);
    await expect(recoverVault(rekeyed.envelope, created.recoveryKey)).rejects.toBeInstanceOf(VaultCryptoError);

    const unlocked = await unlockVault(rekeyed.envelope, "a brand new passphrase");
    expect(unlocked.payload).toEqual(recovered.payload);
    const viaNewRecovery = await recoverVault(rekeyed.envelope, rekeyed.recoveryKey);
    expect(viaNewRecovery.payload.items[0]?.secret).toBe("sk-or-v1-fake-never-use");

    // The old envelope cannot be opened with what the new vault hands out
    await expect(recoverVault(envelope, rekeyed.recoveryKey)).rejects.toBeInstanceOf(VaultCryptoError);

    for (const key of [created.vaultKey, recovered.vaultKey, rekeyed.vaultKey, unlocked.vaultKey, viaNewRecovery.vaultKey]) {
      await destroyVaultKey(key);
    }
  });

  it("validates a complete envelope before import", async () => {
    const created = await createVault(passphrase);
    await expect(validateVaultEnvelope(structuredClone(created.envelope))).resolves.toEqual(
      created.envelope,
    );

    const invalid = structuredClone(created.envelope) as unknown as Record<string, unknown>;
    invalid.payload = { algorithm: "xchacha20poly1305", nonce: "invalid", ciphertext: "invalid" };
    await expect(validateVaultEnvelope(invalid)).rejects.toBeInstanceOf(VaultCryptoError);
    await destroyVaultKey(created.vaultKey);
  });
});
