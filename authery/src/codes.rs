//! Shared six-digit code generation for the `otp` and `sms` features.

use uuid::Uuid;

/// Generate a six-digit code from the CSPRNG behind UUIDv4. The modulo bias on
/// 122 random bits is on the order of 1e-31 - negligible.
pub(crate) fn generate_code() -> String {
    format!("{:06}", Uuid::new_v4().as_u128() % 1_000_000)
}
