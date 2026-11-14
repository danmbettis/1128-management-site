# 1128 Management website and portal

Firebase-free first implementation. Existing marketing content is preserved, the truncated HTML ending is repaired, and `/portal` serves customer and owner dashboards.

## Implemented

- Intake-first workflow; only owners create customer accounts.
- Password hashing with salted scrypt; opaque, hashed server-side sessions; HttpOnly/SameSite cookies; production Secure cookies; eight-hour expiry and logout revocation.
- Customer isolation enforced by server queries; owner-only intake review, client activation and service updates.
- Durable SQLite service records, next steps, messages and audit events.
- Same-origin write checks, bounded JSON bodies and process-local request throttling.

## Run locally

Use Node 24 or newer. No npm dependencies are required.

1. Set OWNER_EMAIL and OWNER_PASSWORD in a private environment, then run `npm run owner`. Password must have at least 14 characters. Never commit credentials.
2. Run `npm start` and open http://localhost:3000/portal.
3. Run `npm test` for real HTTP login, customer-isolation, permissions, message, intake, CSRF-origin and logout coverage.

## Hosting and launch requirements

This server cannot execute on GitHub Pages. Run it on Node-capable hosting with a persistent disk, HTTPS reverse proxy, `NODE_ENV=production`, `PUBLIC_ORIGIN=https://1128management.website`, and `DB_PATH` on that persistent disk. Forward all website requests to the application. Set PORT as needed. Keep database files private and back them up with SQLite-aware backups. Use one application instance; process-local throttling must be replaced or supplemented at the proxy before scaling. Configure request timeouts and request limiting at the proxy. The public intake endpoint needs production abuse monitoring.

Do not point the live domain to this candidate until deployment and migration have been tested. Do not remove Firebase yet.

## Migration and remaining work

No Firebase customer data, credentials, configuration, or exports are in this repository. The console link alone does not provide access to data. Obtain a private export of Firebase Auth account metadata and Firestore clientStatus/intake records. Inventory storage files too if any exist. Map records to customers, validate counts and sample histories, establish new credentials privately, test both roles, back up both systems, then switch the domain. Import/export tooling must be built against the actual export schema; do not guess customer relationships from email alone or put private exports in Git.

This first implementation has no document uploads/downloads, billing/credit ledger, email delivery, password-reset flow, forced first-login password change, MFA, customer suspension, or migration importer. Initial credentials are provisioned by an owner; a production reset/invitation flow is required before general launch. Existing payments are external marketing links and are not synchronized with the portal. No payments are recorded as verified by this implementation.

Browser visual QA, production deployment, domain routing and real customer migration have not been completed. Automated API checks passing does not establish production readiness.
