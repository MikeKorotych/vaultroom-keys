# Roadmap

## Phase 0: security design

Status: complete.

- Agree on the threat model and explicit non-goals
- Decide the first encrypted payload format
- Benchmark the KDF on target hardware
- Define recovery and irreversible-loss UX
- Remove inherited product claims that imply secret safety

Exit criteria: the key hierarchy, metadata leakage, recovery policy and web-client limitation are written and reviewable.

## Phase 1: local encrypted vault

Status: complete for private beta.

- Create, edit and delete API-key entries
- Lock and unlock with a master passphrase
- Encrypt one versioned vault blob in the browser
- Store ciphertext in IndexedDB
- Export and import an encrypted `.vaultroom` file
- Timed reveal, inactivity lock and clipboard auto-clear
- Golden test vectors, tamper tests and wrong-passphrase tests

Exit criteria: the application works offline and no network request contains vault plaintext.

## Phase 2: encrypted backup and sync

Status: core flow complete; conflict-resolution UI remains.

- Replace inherited room endpoints with opaque vault blob endpoints
- Optimistic revision checks and encrypted history
- Clerk account ownership without server-side decryption
- Restore on a second browser using passphrase or recovery key
- Explicit conflict UI instead of last-write-wins

Exit criteria: a clean browser can recover the same vault while a database dump reveals no item metadata or values.

## Phase 3: device trust

- Passkey-backed device enrollment
- Device list and remote session revocation
- Secure local key storage where the platform supports it
- Recovery drill and emergency lock
- Signed release manifest

Exit criteria: a user can add and remove devices without exposing the vault data key to the server.

## Phase 4: broader password-manager features

Only after the vault passes external review:

- Password and passphrase generator
- TOTP seeds
- Browser extension and autofill
- Secure sharing between identified users
- Native macOS and mobile clients

Browser extension and autofill are separate security projects, not small UI additions.

## Immediate backlog

1. Add an explicit conflict-resolution screen with local/cloud ciphertext choices.
2. Add deterministic golden vectors and Chromium/Firefox/WebKit coverage.
3. Remove dormant inherited data-room source and database models in a dedicated migration.
4. Add a passphrase-change screen for an already unlocked vault.
5. Add encrypted revision restore UI.
6. Commission an independent cryptographic and XSS review.
