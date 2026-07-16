# Introduction

Authery is a batteries-included authentication crate for Axum. It handles
sessions, passwords, email links and one-time codes, OAuth2/OIDC, passkeys
and MFA behind one composable API, on top of whatever storage you bring.

Three design decisions shape everything else:

**You own the storage.** Authery never talks to a database. You implement the
[`AutheryStore`] trait over your backend, and every entity (users, sessions,
email challenges, oauth tokens, passkeys) is defined by a trait with generic
ID types — your existing models and id scheme stay yours. This also means the
store is a natural extension point: it *is* your application code, and it
observes every user creation, login and token exchange.

**Everything is a feature flag.** `password`, `email`, `otp`, `oauth`,
`webauthn`, `mfa`, `user`, `pages`, `axum` — enable only what you need, and
the store trait only asks for the methods those features use.

**Complement, don't restrict.** Authery deliberately stops at
authentication. Authorization, tenancy and domain roles belong to your app —
but authery hands you the primitives to build them: a runtime provider
resolver for per-tenant SSO, a context string that rides the oauth flow into
your store, login-method rules for gating routes, and a rate-limiter hook.
The [organizations chapter](organizations.md) shows a complete multi-tenant
setup built this way.

[`AutheryStore`]: store.md
