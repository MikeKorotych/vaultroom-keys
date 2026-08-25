# Threat model

Status: open-source beta 0.3. Core controls are implemented and smoke-tested; independent cryptographic review remains a release gate for high-value credentials.

## Security goal

A compromise of the API database, object storage or routine server logs must not reveal stored API keys. The server may authenticate an account and synchronize ciphertext, but it must not receive the master passphrase, vault data key or plaintext entries.

## Assets

- API keys, access tokens, recovery codes and secret notes
- Master passphrase and recovery key
- Vault data key
- Decrypted vault state in browser memory
- Encrypted backup history
- Account identity and limited sync metadata

## Trust boundaries

### Trusted for the first release

- The user's unlocked device and browser process
- The reviewed client bundle delivered for that release
- The audited cryptographic implementation and browser random generator

### Not trusted with plaintext

- Nest API
- PostgreSQL
- Railway, Vercel and their operators
- Clerk session infrastructure
- Network intermediaries

Clerk proves which account may read or replace a ciphertext blob. It is not part of the encryption key hierarchy.

## Attackers in scope

1. An attacker who obtains a database or bucket dump.
2. An operator who can inspect server logs and stored objects.
3. An attacker who steals an authenticated but locked browser session.
4. An attacker who modifies, replays or rolls back encrypted blobs.
5. An attacker who obtains one encrypted export file.
6. A dependency or XSS payload running in the unlocked vault page.
7. Accidental disclosure through logs, analytics, crash reports or clipboard history.

## Out of scope for the first release

- Malware with control of an unlocked operating system
- Hardware keyloggers or screen capture
- Coercion of the user
- Revoking plaintext that a user already copied or exported
- Team sharing and organisation recovery
- Browser autofill and extension attack surfaces

## Implemented key hierarchy

1. Generate a random 256-bit vault data key in the browser.
2. Derive a key-encryption key from the master passphrase with a memory-hard KDF and a random salt.
3. Wrap the vault data key with the key-encryption key.
4. Encrypt the versioned vault payload with authenticated encryption and a fresh nonce.
5. Generate a high-entropy recovery key and create a second wrapped copy of the same vault data key.
6. Upload only ciphertext, salts, nonces, KDF parameters, format version and wrapped keys.

Format v1 uses Argon2id for passphrase derivation and XChaCha20-Poly1305 authenticated encryption through `libsodium-wrappers-sumo`. Interactive libsodium KDF parameters are stored in the envelope and bounded during validation. The implementation still requires independent review before a broader security claim.

## Recovery policy

- The service cannot reset the master passphrase.
- The recovery key is shown once and can be exported or printed.
- A recovery operation unwraps the vault data key and allows creation of a new passphrase wrapper.
- Losing both passphrase and recovery key permanently loses the vault.
- Support staff must never request a passphrase, recovery key or decrypted export.

## Metadata leakage

The server may see Clerk user id, blob size, format version, update timestamps, revision numbers and access patterns. It must not see service names, environments, labels, notes, secret values or per-item timestamps. The first cloud format encrypts the whole vault payload to reduce metadata leakage.

## Web-client risk

Zero-knowledge claims are limited when the server delivers mutable JavaScript. A malicious deployment can capture plaintext after unlock. Required mitigations:

- Strict CSP and Trusted Types
- No analytics, tag managers or third-party scripts on the vault route
- Pinned dependencies and lockfile review
- Reproducible build artifacts and release hashes
- Short unlocked lifetime and memory cleanup on lock
- Long-term signed desktop client for stronger code integrity

## Sync and rollback

- Every encrypted blob has a monotonically increasing revision and authenticated format metadata.
- The client sends the expected previous revision when writing.
- The API rejects stale writes instead of silently overwriting them.
- The server keeps a bounded encrypted revision history for recovery.
- The client warns if the server presents a revision older than the last locally observed revision.

## Clipboard and UI

- Secret values are masked by default.
- Reveal expires automatically.
- Copy requires an explicit action and clears the clipboard after a short interval when the platform permits it.
- Secret values never enter URLs, query strings, analytics or DOM attributes.
- The application locks after ten minutes of inactivity and on explicit user action. Closing the tab discards the in-memory React state; IndexedDB contains ciphertext only.

## Logging rules

No request body, decrypted payload, passphrase, recovery key, secret value or exported vault contents may be logged. Errors use fixed codes and safe metadata. Development fixtures must use unmistakably fake values.

## Release gate

High-value credentials should wait until:

- [x] Crypto format and KDF parameters are versioned
- [x] Wrong passphrase and tampering tests pass
- [x] Export/import, recovery and clean-browser cloud restore drills pass
- [x] Production requests and stored database envelopes were checked for a fake plaintext marker
- [x] CSP and defensive response headers are enabled
- [ ] Deterministic golden vectors and broader cross-browser coverage
- [ ] Dedicated XSS and dependency review
- An independent reviewer examines the design and implementation
