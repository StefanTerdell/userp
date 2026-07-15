//! Includes all external dependencies used in the crate.
//! Something missing? This is a bug. Please file an issue in the project repo.

pub use async_trait;
pub use serde;
pub use thiserror;
pub use uuid;

#[cfg(feature = "oauth")]
pub use anyhow;
#[cfg(feature = "oauth")]
pub use base64;
#[cfg(any(feature = "email", feature = "oauth"))]
pub use chrono;
#[cfg(feature = "email")]
pub use lettre;
#[cfg(feature = "oauth")]
pub use oauth2;
#[cfg(feature = "password")]
pub use password_auth;
#[cfg(feature = "oauth")]
pub use reqwest;
#[cfg(feature = "password")]
pub use tokio;
#[cfg(any(feature = "email", feature = "oauth"))]
pub use url;

#[cfg(feature = "pages")]
pub use askama;
#[cfg(feature = "axum")]
pub use axum;
#[cfg(feature = "axum")]
pub use axum_extra;
