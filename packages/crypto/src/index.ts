import * as sodiumModule from "libsodium-wrappers-sumo";

const sodium =
  (sodiumModule as typeof sodiumModule & { default?: typeof sodiumModule }).default ?? sodiumModule;

const FORMAT = "vaultroom-keys" as const;
const VERSION = 1 as const;
const PASSPHRASE_WRAP_CONTEXT = "vaultroom-keys:v1:passphrase-wrap";
const RECOVERY_WRAP_CONTEXT = "vaultroom-keys:v1:recovery-wrap";
const PAYLOAD_CONTEXT = "vaultroom-keys:v1:payload";
const RECOVERY_PREFIX = "vrk1_";

export type VaultEnvironment = string;

export const MAX_FILE_BYTES = 5 * 1024 * 1024;
export const MAX_VAULT_FILE_BYTES = 10 * 1024 * 1024;
export const MAX_ENVELOPE_BYTES = 20 * 1024 * 1024;

export interface VaultAttachment {
  name: string;
  size: number;
  data: string; // URL-safe base64, inside the authenticated encrypted payload only.
}

export interface VaultItem {
  id: string;
  service: string;
  label: string;
  environment: VaultEnvironment;
  secret: string;
  attachment?: VaultAttachment;
  notes: string;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface VaultPayload {
  version: 1 | 2;
  sequence: number;
  items: VaultItem[];
  environments?: string[];
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

function validateBox(value: unknown): asserts value is EncryptedBox {
  if (!value || typeof value !== "object") throw new VaultCryptoError("Invalid encrypted box");
  const box = value as Partial<EncryptedBox>;
  if (
    box.algorithm !== "xchacha20poly1305" ||
    typeof box.nonce !== "string" ||
    typeof box.ciphertext !== "string"
  ) {
    throw new VaultCryptoError("Invalid encrypted box");
  }
  try {
    if (decode(box.nonce).length !== sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
      throw new VaultCryptoError("Invalid encrypted nonce");
    }
    if (decode(box.ciphertext).length < sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES) {
      throw new VaultCryptoError("Invalid encrypted payload");
    }
  } catch (error) {
    if (error instanceof VaultCryptoError) throw error;
    throw new VaultCryptoError("Invalid encrypted encoding");
  }
}

function validateEnvelope(value: unknown): asserts value is VaultEnvelope {
  if (!value || typeof value !== "object") throw new VaultCryptoError("Invalid vault envelope");
  if (new TextEncoder().encode(JSON.stringify(value)).length > MAX_ENVELOPE_BYTES) {
    throw new VaultCryptoError("Encrypted vault is too large");
  }
  const envelope = value as Partial<VaultEnvelope>;
  if (envelope.format !== FORMAT || envelope.version !== VERSION) {
    throw new VaultCryptoError("Unsupported vault format");
  }
  if (!envelope.kdf || envelope.kdf.algorithm !== "argon2id13") {
    throw new VaultCryptoError("Unsupported KDF");
  }
  if (
    !Number.isSafeInteger(envelope.kdf.opsLimit) ||
    !Number.isSafeInteger(envelope.kdf.memLimit) ||
    envelope.kdf.opsLimit < sodium.crypto_pwhash_OPSLIMIT_MIN ||
    envelope.kdf.opsLimit > sodium.crypto_pwhash_OPSLIMIT_MODERATE ||
    envelope.kdf.memLimit < sodium.crypto_pwhash_MEMLIMIT_MIN ||
    envelope.kdf.memLimit > sodium.crypto_pwhash_MEMLIMIT_MODERATE
  ) {
    throw new VaultCryptoError("Unsafe KDF parameters");
  }
  try {
    if (decode(envelope.kdf.salt).length !== sodium.crypto_pwhash_SALTBYTES) {
      throw new VaultCryptoError("Invalid vault salt");
    }
  } catch (error) {
    if (error instanceof VaultCryptoError) throw error;
    throw new VaultCryptoError("Invalid vault salt");
  }
  validateBox(envelope.passphraseWrappedKey);
  validateBox(envelope.recoveryWrappedKey);
  validateBox(envelope.payload);
  if (
    typeof envelope.createdAt !== "string" ||
    typeof envelope.updatedAt !== "string" ||
    !Number.isFinite(Date.parse(envelope.createdAt)) ||
    !Number.isFinite(Date.parse(envelope.updatedAt))
  ) throw new VaultCryptoError("Invalid vault timestamps");
}

function validatePayload(value: unknown): asserts value is VaultPayload {
  if (!value || typeof value !== "object") throw new VaultCryptoError("Invalid vault payload");
  const payload = value as Partial<VaultPayload>;
  if ((payload.version !== 1 && payload.version !== 2) || !Number.isSafeInteger(payload.sequence) || !Array.isArray(payload.items)) {
    throw new VaultCryptoError("Invalid vault payload");
  }
  if (payload.environments !== undefined &&
      (!Array.isArray(payload.environments) || payload.environments.length < 1 || payload.environments.length > 50 ||
       payload.environments.some((name) => typeof name !== "string" || !name.trim() || name !== name.trim() || name.length > 60 || name === "all") ||
       new Set(payload.environments).size !== payload.environments.length)) {
    throw new VaultCryptoError("Invalid environments");
  }
  let total = 0;
  for (const item of payload.items) {
    if (!item || typeof item !== "object") throw new VaultCryptoError("Invalid vault item");
    if (payload.environments && !payload.environments.includes(item.environment)) throw new VaultCryptoError("Unknown environment");
    if (item.attachment !== undefined) {
      validateAttachment(item.attachment);
      total += item.attachment.size;
      if (total > MAX_VAULT_FILE_BYTES) throw new VaultCryptoError("Files exceed the 10 MiB vault limit");
    }
  }
}

/** No file type is rendered or executed. Names are download basenames only. */
export function safeAttachmentName(name: string) {
  return name.replace(/[\\/\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/g, "_").slice(0, 180).replace(/^\.+$/, "file") || "file";
}

function validateAttachment(file: VaultAttachment) {
  if (!file || typeof file.name !== "string" || file.name !== safeAttachmentName(file.name) ||
      !Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_FILE_BYTES ||
      typeof file.data !== "string" || file.data.length > Math.ceil(MAX_FILE_BYTES * 4 / 3)) {
    throw new VaultCryptoError("Invalid file (maximum 5 MiB)");
  }
  let bytes: Uint8Array | undefined;
  try {
    bytes = decode(file.data);
    if (bytes.length !== file.size) throw new VaultCryptoError("Invalid file size");
  } catch {
    throw new VaultCryptoError("Invalid file encoding or size");
  } finally {
    if (bytes) sodium.memzero(bytes);
  }
}

export async function createVaultAttachment(name: string, bytes: Uint8Array): Promise<VaultAttachment> {
  if (bytes.length > MAX_FILE_BYTES) throw new VaultCryptoError("File exceeds 5 MiB");
  await sodium.ready;
  return { name: safeAttachmentName(name), size: bytes.length, data: encode(bytes) };
}

export async function readVaultAttachment(file: VaultAttachment): Promise<Uint8Array> {
  await sodium.ready;
  validateAttachment(file);
  return decode(file.data);
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

/** Fresh vault data key, recovery key and passphrase salt around a payload. */
function sealVault(
  passphrase: string,
  payload: VaultPayload,
  createdAt: string,
): UnlockedVault & { recoveryKey: string } {
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

  try {
    const envelope: VaultEnvelope = {
      format: FORMAT,
      version: VERSION,
      kdf,
      passphraseWrappedKey: encryptBox(vaultKey, passphraseKey, kdfAad(kdf)),
      recoveryWrappedKey: encryptBox(vaultKey, recoveryBytes, RECOVERY_WRAP_CONTEXT),
      payload: encryptBox(JSON.stringify(payload), vaultKey, PAYLOAD_CONTEXT),
      createdAt,
      updatedAt: now,
    };
    return { envelope, payload, vaultKey, recoveryKey: formatRecoveryKey(recoveryBytes) };
  } finally {
    sodium.memzero(passphraseKey);
    sodium.memzero(recoveryBytes);
  }
}

export async function createVault(passphrase: string): Promise<UnlockedVault & { recoveryKey: string }> {
  validatePassphrase(passphrase);
  await sodium.ready;
  return sealVault(passphrase, { version: 1, sequence: 0, items: [] }, new Date().toISOString());
}

export async function validateVaultEnvelope(value: unknown): Promise<VaultEnvelope> {
  await sodium.ready;
  validateEnvelope(value);
  return value;
}

function openPayload(envelope: VaultEnvelope, vaultKey: Uint8Array): VaultPayload {
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = decryptBox(envelope.payload, vaultKey, PAYLOAD_CONTEXT);
    const payload: unknown = JSON.parse(sodium.to_string(plaintext));
    validatePayload(payload);
    return payload;
  } catch (error) {
    sodium.memzero(vaultKey);
    throw error;
  } finally {
    if (plaintext) sodium.memzero(plaintext);
  }
}

export async function unlockVault(envelope: VaultEnvelope, passphrase: string): Promise<UnlockedVault> {
  await sodium.ready;
  validateEnvelope(envelope);
  const passphraseKey = derivePassphraseKey(passphrase, envelope.kdf);
  try {
    const vaultKey = decryptBox(envelope.passphraseWrappedKey, passphraseKey, kdfAad(envelope.kdf));
    const payload = openPayload(envelope, vaultKey);
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
    const payload = openPayload(envelope, vaultKey);
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
    version: 2,
    sequence: payload.sequence ?? 0,
    items: payload.items,
    ...(payload.environments ? { environments: payload.environments } : {}),
  };
  validatePayload(nextPayload);
  const result: VaultEnvelope = {
    ...envelope,
    payload: encryptBox(JSON.stringify(nextPayload), vaultKey, PAYLOAD_CONTEXT),
    updatedAt: new Date().toISOString(),
  };
  validateEnvelope(result);
  return result;
}

/**
 * Re-encrypts the vault under a new passphrase with a new data key and a new recovery key.
 * Rewrapping the old data key would leave every earlier envelope (server history, other
 * devices) readable with the old passphrase or recovery key, so neither is reused. Exports
 * made before still open with the old secrets. The caller destroys `unlocked.vaultKey`.
 */
export async function rekeyVault(
  unlocked: UnlockedVault,
  newPassphrase: string,
): Promise<UnlockedVault & { recoveryKey: string }> {
  validatePassphrase(newPassphrase);
  await sodium.ready;
  validateEnvelope(unlocked.envelope);
  validatePayload(unlocked.payload);
  return sealVault(newPassphrase, unlocked.payload, unlocked.envelope.createdAt);
}

export async function destroyVaultKey(key: Uint8Array) {
  await sodium.ready;
  sodium.memzero(key);
}
