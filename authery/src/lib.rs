#![cfg_attr(not(feature = "default"), allow(unused))]

pub mod config;
pub mod constants;
pub mod core;
pub mod models;
#[cfg(feature = "mfa")]
pub mod mfa;
#[cfg(feature = "organizations")]
pub mod org;
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
