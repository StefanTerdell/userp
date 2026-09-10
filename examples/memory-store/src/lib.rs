//! An in-memory [`authery::store::AutheryStore`] for the example apps.
//!
//! Everything is feature-gated the way a real store implementation would be:
//! the `cfg` attributes here mirror the gates on the store trait itself, so
//! an app that enables only `password` compiles only the password methods.

pub mod models;
pub mod store;

pub use store::{MemoryStore, MemoryStoreError};
