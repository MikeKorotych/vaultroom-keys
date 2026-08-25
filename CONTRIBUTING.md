# Contributing

Vaultroom Keys accepts focused bug fixes, tests and security improvements. Please open an issue before proposing a new product feature or changing the encrypted envelope format.

## Local checks

```bash
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Use fake credentials in fixtures and screenshots. Never commit a real API key, passphrase, recovery key, Clerk secret, database URL or exported `.vaultroom` file.

Changes to `packages/crypto`, the recovery flow, sync revisions or Content Security Policy need matching tests and a threat-model update. Do not describe the project as independently audited unless that review has actually happened.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
