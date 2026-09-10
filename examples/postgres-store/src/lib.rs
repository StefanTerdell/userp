//! The reference [`authery::store::AutheryStore`]: Postgres via sqlx.
//!
//! Start from this (and `schema.sql`) when implementing your own store. The
//! `cfg` gates mirror the store trait's own feature gates, so enable only
//! the features your app uses.

pub mod models;
pub mod store;

pub use store::{PgStore, PgStoreError};
