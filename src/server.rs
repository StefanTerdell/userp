#![cfg_attr(not(feature = "default"), allow(unused))]

pub mod config;
pub mod constants;
pub mod core;
pub mod prelude;
pub mod reexports;
pub mod store;

#[cfg(feature = "axum-extract")]
pub mod axum;
#[cfg(feature = "server-email")]
pub mod email;
#[cfg(feature = "server-oauth")]
pub mod oauth;
#[cfg(feature = "server-pages")]
pub mod pages;
#[cfg(feature = "server-password")]
pub mod password;

#[cfg(feature = "axum-extract")]
pub use axum::AxumUserp as Userp;
#[cfg(not(feature = "axum-extract"))]
pub use core::CoreUserp as Userp;
