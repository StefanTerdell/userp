//! Trait-only entities for the `sms` feature.

use super::Id;

/// A phone number attached to a user. Mirrors
/// [`crate::models::email::UserEmail`]: the store owns the concrete type.
pub trait UserPhone: Send + Sync {
    type UserId: Id;

    fn get_user_id(&self) -> Self::UserId;
    /// The number in the form it is dialled/stored (E.164 recommended).
    fn get_number(&self) -> &str;
    /// Whether possession of this number has been proven. Numbers attached by
    /// the SMS login/signup flows are verified by construction.
    fn get_verified(&self) -> bool;
    /// Whether this number may be used to log in.
    fn get_allow_login(&self) -> bool;
}
