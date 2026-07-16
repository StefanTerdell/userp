//! Batteries-included authentication for Axum: sessions, passwords, email
//! links and one-time codes, OAuth2/OIDC, passkeys and MFA - composable via
//! feature flags, on top of storage you bring.
//!
//! Start with [the book](https://github.com/StefanTerdell/userp/tree/main/docs)
//! or the quick tour below:
//!
//! - Implement [`store::AutheryStore`] over your database. Entities are
//!   trait-defined ([`models`]) with generic id types - your models stay
//!   yours.
//! - Build an [`config::AutheryConfig`] with the configs for the method
//!   features you enabled (`password`, `email`, `otp`, `oauth`, `webauthn`,
//!   `mfa`).
//! - Mount `auth.router::<YourStore, YourState>()` (the `axum` feature) and
//!   you have login/signup/account pages (the `pages` feature, replaceable
//!   via [`pages::Pages`]) plus all the action and callback endpoints.
//! - In your own handlers, extract [`Authery`] and gate on
//!   `auth.user_session()`, or apply [`models::LoginMethodRules`] for
//!   method-sensitive routes.
//!
//! Multi-tenant SSO is supported through runtime provider resolution
//! ([`oauth::OAuthProviderResolver`]) rather than a built-in tenancy model -
//! the book's *organizations* chapter shows the full recipe.
//!
//! Everything user-visible is exported through [`prelude`].

#![cfg_attr(not(feature = "default"), allow(unused))]

pub mod config;
pub mod constants;
pub mod core;
pub mod models;
#[cfg(feature = "mfa")]
pub mod mfa;
pub mod prelude;
pub mod ratelimit;
#[cfg(feature = "webauthn")]
pub mod webauthn;
pub mod reexports;
pub mod routes;
pub mod store;

#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "password")]
pub mod password;

#[cfg(feature = "pages")]
pub mod pages;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "axum")]
pub use axum::AxumAuthery as Authery;
#[cfg(not(feature = "axum"))]
pub use core::CoreAuthery as Authery;
