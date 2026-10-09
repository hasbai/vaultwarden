# Vaultwarden personal Worker

Rust Workers (`workers-rs`) + D1 + pinned Vaultwarden Web Vault. The original native server is unchanged.

Identity belongs to 北极小站 Auth0: `auth.hasbai.xyz`, shared public client and organization, shared API audience with the dedicated `access:vaultwarden` permission. Local identity registration, password login, API-key login and email recovery are disabled. Each Auth0 subject owns a separate personal vault; matching email addresses never link accounts. Auth0 credentials are encrypted in D1 with a Workers Secret and never returned to Bitwarden clients. The Bitwarden compatibility JWT references the server-side session and carries client profile metadata; it contains no upstream Auth0 credentials. Each API request verifies the stored upstream access JWT and permission. RBAC changes take effect on refresh or token expiry (the shared API currently issues 1-hour access tokens).

SSO authenticates the user; the vault master password encrypts and unlocks the vault. First SSO opens the stock Web Vault's initial master-password screen. No initial-registration credential is needed. The stored KDF salt is stable even if the identity email later changes; email/salt changes require a future encryption-key migration.

## First-release scope

- Web Vault and Bitwarden SSO authorization-code/PKCE protocol.
- Personal encrypted items and folders, manual/startup sync, import, favorites, trash and restore.
- Master-password/KDF changes and device-session revocation.
- Auth0 manages account login, identity, MFA and RBAC.

Organizations, collections, attachments, Send, emergency access, native account management, account encryption-key rotation and real-time WebSocket notifications are not implemented. Requests fail explicitly. This is a personal Worker port, not a full Vaultwarden deployment. Native Vaultwarden databases are not compatible with this independent schema.

## Reproduce

Requirements: Rust 1.95.0, `wasm32-unknown-unknown`, `worker-build 0.8.7`, Node/npm, GitHub CLI for the pinned Web Vault release, authenticated Wrangler/Auth0 CLI.

```sh
npm ci
cargo install worker-build --version 0.8.7 --locked
npm run web-vault
node scripts/init-secrets.mjs
node scripts/auth0-setup.mjs          # read-only plan
node scripts/auth0-setup.mjs --apply  # append callback and dedicated permission
npm run check
npm run build
npx wrangler d1 migrations apply vaultwarden --local --persist-to test-results/d1-live
npx wrangler dev --local --local-protocol https --persist-to test-results/d1-live --var DOMAIN:https://localhost:8787
```

Generated credentials, tokens, local data and Web Vault downloads are ignored. Production secrets are `JWT_JWK` (protocol signing) and `TOKEN_ENCRYPTION_KEY` (AES-GCM encryption of upstream credentials). Changing the encryption key invalidates stored Auth0 sessions. Never commit or log `.secrets/` or `.dev.vars`.

`scripts/auth0-setup.mjs` preserves existing callbacks, scopes and permissions, adds only this application's callback and `access:vaultwarden`, and grants it to the existing `superadmin` role. The application checks the permission, not role names.

## Deployment and backups

The target is `https://bw.hasbai.xyz`. Configure the actual D1 database ID in `wrangler.jsonc`, apply the D1 migrations, upload `.secrets/production.json` through Wrangler's protected secrets file mechanism, then deploy the built Worker and assets with `npx wrangler deploy --secrets-file .secrets/production.json`. Validate the remote API and SSO before using real passwords.

```sh
npx wrangler d1 export vaultwarden --remote --output=.secrets/vault-backup.sql
```

Restore only to an isolated database first. Keep the backup confidential: it contains encrypted vault data and credential verifiers, even though it does not contain plaintext vault passwords. Worker rollback does not roll back D1. The scheduled cleanup removes items after 30 days in trash and expired sessions/SSO transactions.


## Acceptance

Validated on 2026-10-09 with local workerd/D1 and real 北极小站 Auth0:

- Rust formatting and Clippy with warnings denied; Wasm build and Wrangler dry run.
- Auth0 signed-token acceptance and rejection for permission/org/client/audience/issuer/expiry/signature.
- SSO redirect allowlist, cookie binding, callback/code replay and incorrect PKCE.
- Real Web Vault SSO, initial encrypted vault setup, later unlock, encrypted item save and reload/decryption.
- Official CLI 2026.7.0 SSO through a real browser loopback callback, separate `bw unlock`, encrypted item/folder CRUD and sync/decryption.
- D1 optimistic concurrency, restore/archive response contracts, permanent delete, import rollback, refresh competition, master-password change and session revocation.
- A second subject's D1 fixture with the same email cannot be read/mutated; mixed-owner bulk rolls back. This is not a second live Auth0 login.
- Local SQLite export restored into an isolated database with matching vault/session counts and successful integrity check.

Desktop, mobile and browser extension apps have not been manually exercised. Native-client server URL is `https://bw.hasbai.xyz`; select SSO identifier `hasbai`. CLI login and vault unlock are separate commands. First vault-key initialization requires the Web Vault.

Browser tests use existing test credentials from `AUTH0_TEST_ENV_FILE` (local default is the North Station checkout `.env`); never commit these credentials. Local test master passwords and session tokens are written only to ignored `.secrets/` files. Local HTTPS uses Wrangler's development certificate; the following TLS exception is restricted to these local tests. Production tests use normal certificate verification and stop before setting a master password.

```sh
node tests/crypto.mjs
node tests/auth0.mjs
NODE_TLS_REJECT_UNAUTHORIZED=0 node tests/sso-protocol.mjs
node tests/web-vault.mjs
NODE_TLS_REJECT_UNAUTHORIZED=0 node tests/integration.mjs
node tests/web-vault.mjs # verify changed password decrypts existing data
NODE_TLS_REJECT_UNAUTHORIZED=0 node tests/cli.mjs
node tests/production.mjs
```
