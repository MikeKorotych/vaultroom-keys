# Changelog

## 2026-08-25

- Created the private Vaultroom Keys product fork from the completed Vaultroom assignment.
- Narrowed the first release to encrypted API-key backup rather than a full password manager.
- Added the first threat model, phased roadmap and living product manual.
- Implemented a versioned Argon2id + XChaCha20-Poly1305 envelope in an isolated crypto package.
- Added one-time recovery keys, passphrase rewrapping, tamper rejection and key-memory cleanup.
- Replaced the active product UI with a local-first API-key vault, masked reveal, timed clipboard clearing, encrypted import/export and inactivity locking.
- Added authenticated opaque ciphertext sync with optimistic revisions and five encrypted history snapshots.
- Deployed the independent beta to Vercel, Railway and a dedicated PostgreSQL service.
- Completed production smoke tests for create, lock/unlock, clean-browser cloud restore, recovery, export/import and plaintext absence.
- Added import-envelope validation, CSP and defensive response headers.
