import * as sodiumModule from "libsodium-wrappers-sumo";

const sodium =
  (sodiumModule as typeof sodiumModule & { default?: typeof sodiumModule }).default ?? sodiumModule;

const FORMAT = "vaultroom-keys" as const;
const VERSION = 1 as const;
const PASSPHRASE_WRAP_CONTEXT = "vaultroom-keys:v1:passphrase-wrap";
const RECOVERY_WRAP_CONTEXT = "vaultroom-keys:v1:recovery-wrap";
const PAYLOAD_CONTEXT = "vaultroom-keys:v1:payload";
const RECOVERY_PREFIX = "vrk1_";

export type VaultEnvironment = "development" | "staging" | "production" | "personal";

export interface VaultItem {
  id: string;
  service: string;
  label: string;
  environment: VaultEnvironment;
  secret: string;
  notes: string;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface VaultPayload {
  version: 1;
  sequence: number;
  items: VaultItem[];
}

export interface EncryptedBox {
  algorithm: "xchacha20poly1305";
  nonce: string;
  ciphertext: string;
}

export interface VaultKdf {
  algorithm: "argon2id13";
  opsLimit: number;
  memLimit: number;
  salt: string;
}

export interface VaultEnvelope {
  format: typeof FORMAT;
  version: typeof VERSION;
  kdf: VaultKdf;
  passphraseWrappedKey: EncryptedBox;
  recoveryWrappedKey: EncryptedBox;
  payload: EncryptedBox;
  createdAt: string;
  updatedAt: string;
}

export interface UnlockedVault {
  envelope: VaultEnvelope;
  payload: VaultPayload;
  vaultKey: Uint8Array;
}

export class VaultCryptoError extends Error {
  constructor(message = "Vault authentication failed") {
    super(message);
    this.name = "VaultCryptoError";
  }
}

function encode(bytes: Uint8Array) {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}

function decode(value: string) {
  return sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
}

function kdfAad(kdf: VaultKdf) {
  return `${PASSPHRASE_WRAP_CONTEXT}:${kdf.algorithm}:${kdf.opsLimit}:${kdf.memLimit}:${kdf.salt}`;
}

function encryptBox(message: Uint8Array | string, key: Uint8Array, aad: string): EncryptedBox {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    aad,
    null,
    nonce,
    key,
  );
  return { algorithm: "xchacha20poly1305", nonce: encode(nonce), ciphertext: encode(ciphertext) };
}

function decryptBox(box: EncryptedBox, key: Uint8Array, aad: string) {
  if (box.algorithm !== "xchacha20poly1305") throw new VaultCryptoError();
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      decode(box.ciphertext),
      aad,
      decode(box.nonce),
      key,
    );
  } catch {
    throw new VaultCryptoError();
  }
}

function validatePassphrase(passphrase: string) {
  if (passphrase.length < 12) throw new VaultCryptoError("Use at least 12 characters");
  if (passphrase.length > 1024) throw new VaultCryptoError("Passphrase is too long");
}

function validateEnvelope(envelope: VaultEnvelope) {
  if (envelope.format !== FORMAT || envelope.version !== VERSION) {
    throw new VaultCryptoError("Unsupported vault format");
  }
  if (envelope.kdf.algorithm !== "argon2id13") throw new VaultCryptoError("Unsupported KDF");
  if (
    envelope.kdf.opsLimit < sodium.crypto_pwhash_OPSLIMIT_MIN ||
    envelope.kdf.opsLimit > sodium.crypto_pwhash_OPSLIMIT_MODERATE ||
    envelope.kdf.memLimit < sodium.crypto_pwhash_MEMLIMIT_MIN ||
    envelope.kdf.memLimit > sodium.crypto_pwhash_MEMLIMIT_MODERATE
  ) {
    throw new VaultCryptoError("Unsafe KDF parameters");
  }
  if (decode(envelope.kdf.salt).length !== sodium.crypto_pwhash_SALTBYTES) {
    throw new VaultCryptoError("Invalid vault salt");
  }
}

function validatePayload(value: unknown): asserts value is VaultPayload {
  if (!value || typeof value !== "object") throw new VaultCryptoError("Invalid vault payload");
  const payload = value as Partial<VaultPayload>;
  if (payload.version !== 1 || !Number.isSafeInteger(payload.sequence) || !Array.isArray(payload.items)) {
    throw new VaultCryptoError("Invalid vault payload");
  }
}

function derivePassphraseKey(passphrase: string, kdf: VaultKdf) {
  return sodium.crypto_pwhash(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    passphrase,
    decode(kdf.salt),
    kdf.opsLimit,
    kdf.memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

function parseRecoveryKey(value: string) {
  if (!value.startsWith(RECOVERY_PREFIX)) throw new VaultCryptoError("Invalid recovery key");
  const [encodedKey, encodedChecksum] = value.slice(RECOVERY_PREFIX.length).split(".");
  if (!encodedKey || !encodedChecksum) throw new VaultCryptoError("Invalid recovery key");
  const key = decode(encodedKey);
  const checksum = decode(encodedChecksum);
  const expected = sodium.crypto_generichash(4, key, null);
  if (
    key.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES ||
    checksum.length !== expected.length ||
    !sodium.memcmp(checksum, expected)
  ) {
    sodium.memzero(key);
    throw new VaultCryptoError("Invalid recovery key");
  }
  return key;
}

function formatRecoveryKey(key: Uint8Array) {
  return `${RECOVERY_PREFIX}${encode(key)}.${encode(sodium.crypto_generichash(4, key, null))}`;
}

export async function createVault(passphrase: string): Promise<UnlockedVault & { recoveryKey: string }> {
  validatePassphrase(passphrase);
  await sodium.ready;

  const now = new Date().toISOString();
  const vaultKey = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  const recoveryBytes = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  const kdf: VaultKdf = {
    algorithm: "argon2id13",
    opsLimit: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    memLimit: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    salt: encode(sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)),
  };
  const passphraseKey = derivePassphraseKey(passphrase, kdf);
  const payload: VaultPayload = { version: 1, sequence: 0, items: [] };

  try {
    const envelope: VaultEnvelope = {
      format: FORMAT,
      version: VERSION,
      kdf,
      passphraseWrappedKey: encryptBox(vaultKey, passphraseKey, kdfAad(kdf)),
      recoveryWrappedKey: encryptBox(vaultKey, recoveryBytes, RECOVERY_WRAP_CONTEXT),
      payload: encryptBox(JSON.stringify(payload), vaultKey, PAYLOAD_CONTEXT),
      createdAt: now,
      updatedAt: now,
    };
    return { envelope, payload, vaultKey, recoveryKey: formatRecoveryKey(recoveryBytes) };
  } finally {
    sodium.memzero(passphraseKey);
    sodium.memzero(recoveryBytes);
  }
}

export async function unlockVault(envelope: VaultEnvelope, passphrase: string): Promise<UnlockedVault> {
  await sodium.ready;
  validateEnvelope(envelope);
  const passphraseKey = derivePassphraseKey(passphrase, envelope.kdf);
  try {
    const vaultKey = decryptBox(envelope.passphraseWrappedKey, passphraseKey, kdfAad(envelope.kdf));
    const payload = JSON.parse(
      sodium.to_string(decryptBox(envelope.payload, vaultKey, PAYLOAD_CONTEXT)),
    ) as unknown;
    validatePayload(payload);
    return { envelope, payload, vaultKey };
  } catch (error) {
    if (error instanceof VaultCryptoError) throw error;
    throw new VaultCryptoError();
  } finally {
    sodium.memzero(passphraseKey);
  }
}

export async function recoverVault(envelope: VaultEnvelope, recoveryKey: string): Promise<UnlockedVault> {
  await sodium.ready;
  validateEnvelope(envelope);
  const recoveryBytes = parseRecoveryKey(recoveryKey);
  try {
    const vaultKey = decryptBox(envelope.recoveryWrappedKey, recoveryBytes, RECOVERY_WRAP_CONTEXT);
    const payload = JSON.parse(
      sodium.to_string(decryptBox(envelope.payload, vaultKey, PAYLOAD_CONTEXT)),
    ) as unknown;
    validatePayload(payload);
    return { envelope, payload, vaultKey };
  } catch (error) {
    if (error instanceof VaultCryptoError) throw error;
    throw new VaultCryptoError();
  } finally {
    sodium.memzero(recoveryBytes);
  }
}

export async function encryptVaultPayload(
  envelope: VaultEnvelope,
  vaultKey: Uint8Array,
  payload: Omit<VaultPayload, "sequence"> & { sequence?: number },
): Promise<VaultEnvelope> {
  await sodium.ready;
  validateEnvelope(envelope);
  if (vaultKey.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
    throw new VaultCryptoError("Invalid vault key");
  }
  const nextPayload: VaultPayload = {
    version: 1,
    sequence: payload.sequence ?? 0,
    items: payload.items,
  };
  validatePayload(nextPayload);
  return {
    ...envelope,
    payload: encryptBox(JSON.stringify(nextPayload), vaultKey, PAYLOAD_CONTEXT),
    updatedAt: new Date().toISOString(),
  };
}

export async function changePassphrase(
  unlocked: UnlockedVault,
  newPassphrase: string,
): Promise<VaultEnvelope> {
  validatePassphrase(newPassphrase);
  await sodium.ready;
  const kdf: VaultKdf = {
    algorithm: "argon2id13",
    opsLimit: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    memLimit: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    salt: encode(sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)),
  };
  const passphraseKey = derivePassphraseKey(newPassphrase, kdf);
  try {
    return {
      ...unlocked.envelope,
      kdf,
      passphraseWrappedKey: encryptBox(unlocked.vaultKey, passphraseKey, kdfAad(kdf)),
      updatedAt: new Date().toISOString(),
    };
  } finally {
    sodium.memzero(passphraseKey);
  }
}

export async function destroyVaultKey(key: Uint8Array) {
  await sodium.ready;
  sodium.memzero(key);
}
