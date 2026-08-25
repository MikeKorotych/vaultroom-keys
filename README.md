# Vaultroom Keys

Vaultroom Keys is a private, encrypted backup vault for API keys and developer secrets. It is a product fork of the Vaultroom data-room assignment, but it has a different trust model: the browser must encrypt every secret before it reaches the API.

The first private beta is deployed and end-to-end tested. It is suitable for personal evaluation with non-critical credentials; keep an independent encrypted backup while the crypto design is still awaiting an external review.

## First useful release

- Store API keys, tokens and secret notes
- Service, environment, label, expiry and notes per item
- One master passphrase unlocks a random vault data key
- Client-side authenticated encryption before persistence
- Encrypted cloud backup plus encrypted file export/import
- Timed reveal and clipboard auto-clear
- Local search only after unlock
- No server-side plaintext, plaintext logs or password reset

This release is intentionally not a full password manager. Browser autofill, password capture, teams and public sharing are out of scope.

## Security position

Clerk authenticates the account, but it does not decrypt the vault. The API stores opaque encrypted blobs and minimal sync metadata. Losing both the master passphrase and recovery key means losing the data. See [THREAT_MODEL.md](THREAT_MODEL.md) before changing encryption, recovery or sync behavior.

The biggest limitation of a web zero-knowledge vault is still the delivered JavaScript: a compromised deployment can capture plaintext after unlock. Phase 1 therefore removes third-party scripts from the vault surface, adds a strict Content Security Policy and pins the crypto implementation. A signed desktop client is the stronger long-term trust boundary.

## Architecture target

```text
master passphrase
      |
      v
memory-hard KDF + random salt
      |
      v
key-encryption key ---- unwraps ---- random vault data key
                                      |
                                      v
                              encrypts vault payload
                                      |
                                      v
browser / IndexedDB -> ciphertext -> Nest API -> PostgreSQL / object storage
```

Format v1 uses Argon2id and XChaCha20-Poly1305 through libsodium. The encrypted envelope stores its KDF parameters, salts, nonces and format version so future clients can reject unsupported or unsafe input.

## Repository

- `apps/web`: Next.js locked/unlocked vault UI and local encrypted storage
- `apps/api`: NestJS / Prisma opaque ciphertext sync service
- `packages/crypto`: isolated key derivation, wrapping, encryption and recovery logic
- `THREAT_MODEL.md`: assets, attackers, boundaries and recovery policy
- `ROADMAP.md`: implementation phases and acceptance criteria
- `docs/plan.html`: interactive living product manual

## Commands

```bash
pnpm install
pnpm dev
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm plan
```

`pnpm plan` opens the private product manual on macOS.

## Status

Production beta: <https://vaultroom-keys.vercel.app>

API health: <https://vaultroom-keys-api-production.up.railway.app/health>

The original Vaultroom assignment remains available at <https://github.com/MikeKorotych/vaultroom-data-room>. This repository is private and independent. Never commit passphrases, recovery keys, exported vaults or real API keys to Git.
