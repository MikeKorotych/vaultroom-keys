import type { VaultEnvelope } from "@vaultroom/crypto";

const DB_NAME = "vaultroom-keys";
const STORE_NAME = "vault";
const recordKey = (ownerId: string) => `primary:${ownerId}`;

export interface LocalVaultRecord {
  envelope: VaultEnvelope;
  cloudRevision: number;
}

function openDatabase() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open local vault"));
  });
}

export async function loadLocalVault(ownerId: string) {
  const database = await openDatabase();
  try {
    return await new Promise<LocalVaultRecord | null>((resolve, reject) => {
      const request = database.transaction(STORE_NAME).objectStore(STORE_NAME).get(recordKey(ownerId));
      request.onsuccess = () => {
        const value = request.result as LocalVaultRecord | VaultEnvelope | undefined;
        if (!value) return resolve(null);
        if ("envelope" in value) return resolve(value);
        resolve({ envelope: value, cloudRevision: 0 });
      };
      request.onerror = () => reject(request.error ?? new Error("Could not read local vault"));
    });
  } finally {
    database.close();
  }
}

export async function saveLocalVault(ownerId: string, record: LocalVaultRecord) {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).put(record, recordKey(ownerId));
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("Could not save local vault"));
    });
  } finally {
    database.close();
  }
}

export async function clearLocalEnvelope(ownerId: string) {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).delete(recordKey(ownerId));
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("Could not clear local vault"));
    });
  } finally {
    database.close();
  }
}
