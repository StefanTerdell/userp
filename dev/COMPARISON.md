# Feature comparison: authery vs. the field

Snapshot 2026-07-17, researched against live docs. Chosen comparisons:
[better-auth](https://better-auth.com) (the TS reference point — Auth.js/NextAuth
is now maintained under its umbrella), [Auth.js](https://authjs.dev),
[axum-login](https://github.com/maxcountryman/axum-login) (closest Rust
neighbour), [Ory Kratos](https://github.com/ory/kratos) (self-hosted identity
*service*), and [Clerk](https://clerk.com) (hosted SaaS) as the managed
reference.

Legend: ✅ built-in · 🧩 plugin/opt-in feature · 🧱 primitive provided, you
assemble it · ❌ not offered · — not applicable

| | **authery** (Rust) | **better-auth** (TS) | **Auth.js** (TS) | **axum-login** (Rust) | **Ory Kratos** (Go) | **Clerk** (SaaS) |
|---|---|---|---|---|---|---|
| Ships as | library (crate) | library | library | library (middleware) | standalone service | hosted service |
| Framework | Axum | most JS frameworks | Next.js, SvelteKit, Express… | Axum/tower | any (HTTP API) | JS/React-first + API |
| Storage | your `AutheryStore` impl, generic IDs | managed schema + migrations, many DBs | 20+ adapters | your `AuthnBackend` impl | its own DB (Postgres etc.) | theirs |
| Email + password | ✅ argon2, enumeration-resistant | ✅ | ✅ (credentials, DIY hashing) | 🧱 (backend trait) | ✅ | ✅ |
| Magic links | ✅ | 🧩 | ✅ | ❌ | ✅ | ✅ |
| Email OTP codes | ✅ (`otp`) | 🧩 | ❌ | ❌ | ✅ | ✅ |
| SMS / phone | ✅ (`sms`, sender trait + 5 built-in gateways) | 🧩 | ❌ | ❌ | ✅ | ✅ |
| OAuth providers | ✅ 11 built-in + custom + any OIDC | ✅ many + generic OAuth | ✅ 80+ | ❌ (pair with `oauth2` crate) | ✅ social sign-in | ✅ |
| OIDC id_token validation (JWKS + nonce) | ✅ | ✅ | ✅ | — | ✅ | ✅ |
| PKCE everywhere | ✅ | ✅ | ✅ | — | ✅ | ✅ |
| Runtime / per-tenant SSO providers | ✅ resolver primitive | 🧩 SSO plugin (incl. SAML) | ❌ (static config) | ❌ | 🧩 (Ory Network B2B orgs) | ✅ per-org enterprise SSO |
| Passkeys / WebAuthn | ✅ usernameless login + registration | 🧩 | 🔬 experimental | ❌ | ✅ | ✅ |
| MFA / 2FA | ✅ policy layer; factors: passkey, TOTP, email code, SMS code | 🧩 TOTP, OTP, backup codes | ❌ (DIY) | ❌ | ✅ TOTP, WebAuthn, lookup codes | ✅ |
| TOTP (authenticator apps) | ✅ QR enrollment, replay-guarded | 🧩 | ❌ | ❌ | ✅ | ✅ |
| Server-side sessions | ✅ expiry, eviction, caps, listing, opt-in bearer tokens | ✅ (+ multi-session 🧩) | ✅ or JWT | ✅ (tower-sessions) | ✅ | ✅ |
| Account linking | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| OAuth token storage + refresh for API integrations | ✅ ownership-checked | ✅ | partial | ❌ | ❌ (different scope) | ✅ |
| Organizations / teams | 🧱 recipe on resolver + store + `LoginMethodRules` | 🧩 orgs, roles, teams, invites, dynamic AC | ❌ | ❌ | 🧩 (Ory Network) | ✅ built-in |
| Authorization / RBAC | 🧱 (your app; method-rules util) | 🧩 admin + access control | ❌ | ✅ `AuthzBackend` perms | via Ory Keto | ✅ roles |
| Rate limiting | 🧱 hook (you supply the limiter) | ✅ built-in + custom rules | ❌ | ❌ | ✅ | ✅ |
| Prebuilt UI | ✅ templated pages, replaceable via `Pages` trait | ❌ headless (community UIs) | ✅ basic pages | ❌ | ❌ headless (reference UI) | ✅ polished components |
| Admin panel / user-management API | ❌ (your store *is* the API) | 🧩 admin plugin | ❌ | ❌ | ✅ admin API | ✅ dashboard |
| SAML / SCIM / directory sync | ❌ | 🧩 | ❌ | ❌ | SAML ✅ | ✅ |
| Bring-your-own everything (no schema imposed) | ✅ core design | ❌ (manages your schema) | partial (adapters) | ✅ | ❌ (owns identities) | ❌ |
| License / cost | ISC, free | MIT, free (+ paid infra add-ons) | ISC, free | MIT, free | Apache-2 (+ paid network/enterprise) | per-MAU pricing |

## Where authery stands

**Differentiators** (things nobody else in the table combines):

1. **Rust/Axum native with batteries.** axum-login gives you traits and
   sessions; everything else here is TS, Go-service or SaaS. Authery is
   currently the only Rust library offering passkeys + MFA + OIDC validation +
   pages out of the box.
2. **Storage inversion.** better-auth manages your schema and migrations;
   Kratos owns the identity database; Clerk owns your users. Authery's
   trait-store means your models, your IDs, your migrations — and the store
   doubles as the extension point (every login/token event passes through
   your code).
3. **The resolver primitive.** Per-tenant SSO resolved at request time from
   app code, with the context handed back to your store — better-auth needs
   its SSO plugin + managed tables for this; Auth.js can't do it at all.
4. **Replaceable-but-present UI.** better-auth and Kratos are headless;
   Clerk's UI is theirs. Authery ships working pages *and* a trait to swap
   the rendering.

**Honest gaps** (candidates for the roadmap, roughly by impact):

1. ~~**TOTP**~~ — done: RFC 6238 with QR enrollment and a matched-step replay
   guard, slotted into the MFA factor model.
2. ~~**SMS/phone OTP**~~ — done: vendor-neutral `SmsSender` trait, five
   built-in gateway senders included with the feature, login/signup/MFA flows.
3. ~~**Bearer session mode**~~ — done: opaque session ids via
   `Authorization: Bearer` + `X-Auth-Token`, opt-in. (A stateless *JWT* mode
   remains deliberately unbuilt — server-side revocable tokens only.)
4. **SAML / SCIM** — enterprise SSO checkboxes; big lift, likely never-list
   or separate crate.
5. **Framework breadth** — Axum only (Leptos was the original ambition);
   the core/axum split keeps the door open.
6. **Maturity** — everyone else has years of production use and audits;
   authery has a fresh security review and a young test suite. Time and
   users fix this one.

**Non-goals** (by design, after the orgs decision): built-in organizations,
admin panels, RBAC — authery provides primitives (`LoginMethodRules`,
resolver, store hooks) and the book documents the recipes.

Sources: [better-auth docs](https://better-auth.com/docs/introduction) ·
[better-auth plugins](https://better-auth.com/docs/plugins) ·
[org plugin](https://better-auth.com/docs/plugins/organization) ·
[Auth.js getting started](https://authjs.dev/getting-started) ·
[axum-login](https://github.com/maxcountryman/axum-login) ·
[Ory Kratos](https://github.com/ory/kratos) · [ory.com/kratos](https://www.ory.com/kratos)
