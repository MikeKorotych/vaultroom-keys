# Security policy

Vaultroom Keys is an experimental open-source beta. The encryption design has automated tests and production smoke coverage, but it has not had an independent security audit. Do not use it as the only copy of high-value production credentials.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Please do not open a public issue with exploit details, real credentials or an exported vault.

Include the affected revision, reproduction steps, impact and any suggested mitigation. You can use an unmistakably fake secret when a proof of concept needs sample data.

## Supported version

Only the latest commit on `main` receives security fixes during the beta.

The documented trust boundaries and known limitations live in [THREAT_MODEL.md](THREAT_MODEL.md).
