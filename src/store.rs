#[cfg(any(feature = "email", feature = "sms"))]
use crate::models::email::EmailChallenge;
#[cfg(feature = "email")]
use crate::models::email::UserEmail;
#[cfg(feature = "oauth")]
use crate::models::oauth::{OAuthToken, UnmatchedOAuthToken};
use crate::models::{Id, LoginMethod, LoginSession, User};
use chrono::{DateTime, Utc};
use std::future::Future;

#[allow(clippy::type_complexity)]
pub trait AutheryStore: Send + Sync {
    type Error: std::error::Error + Send;

    type UserId: Id;
    type SessionId: Id;
    #[cfg(feature = "oauth")]
    type OAuthTokenId: Id;

    type User: User<Id = Self::UserId>;
    type LoginSession: LoginSession<Id = Self::SessionId, UserId = Self::UserId>;
    #[cfg(feature = "email")]
    type UserEmail: UserEmail<UserId = Self::UserId>;
    #[cfg(any(feature = "email", feature = "sms"))]
    type EmailChallenge: EmailChallenge;
    #[cfg(feature = "sms")]
    type UserPhone: crate::models::sms::UserPhone<UserId = Self::UserId>;
    #[cfg(feature = "oauth")]
    type OAuthToken: OAuthToken<Id = Self::OAuthTokenId, UserId = Self::UserId>;

    // basic store
    fn get_user(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;
    fn create_session(
        &self,
        user_id: &Self::UserId,
        method: LoginMethod,
        expires: DateTime<Utc>,
    ) -> impl Future<Output = Result<Self::LoginSession, Self::Error>> + Send;
    fn get_session(
        &self,
        session_id: &Self::SessionId,
    ) -> impl Future<Output = Result<Option<Self::LoginSession>, Self::Error>> + Send;
    fn delete_session(
        &self,
        user_id: &Self::UserId,
        session_id: &Self::SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn get_user_sessions(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Vec<Self::LoginSession>, Self::Error>> + Send;

    // totp store
    /// The user's TOTP enrollment, if any (confirmed or not).
    #[cfg(feature = "totp")]
    fn get_totp(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Option<crate::models::TotpCredential>, Self::Error>> + Send;
    /// Create or replace the user's TOTP enrollment (used for enrollment,
    /// confirmation, and replay-guard updates).
    #[cfg(feature = "totp")]
    fn upsert_totp(
        &self,
        user_id: &Self::UserId,
        credential: crate::models::TotpCredential,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Remove the user's TOTP enrollment.
    #[cfg(feature = "totp")]
    fn delete_totp(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // webauthn store
    //
    // Passkeys are stored as opaque `webauthn_rs::prelude::Passkey` blobs
    // (serde-serializable) keyed by their credential id and owning user.
    /// Persist a newly registered passkey for the user.
    #[cfg(feature = "webauthn")]
    fn create_passkey(
        &self,
        user_id: &Self::UserId,
        passkey: webauthn_rs::prelude::Passkey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// All of the user's passkeys (used to exclude re-registration and for
    /// listing on the account page).
    #[cfg(feature = "webauthn")]
    fn get_passkeys(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Vec<webauthn_rs::prelude::Passkey>, Self::Error>> + Send;
    /// Look up a passkey - and the user owning it - by raw credential id.
    #[cfg(feature = "webauthn")]
    fn get_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> impl Future<
        Output = Result<Option<(Self::UserId, webauthn_rs::prelude::Passkey)>, Self::Error>,
    > + Send;
    /// Replace the stored passkey blob (called after logins to persist
    /// counter updates and backup-state changes).
    #[cfg(feature = "webauthn")]
    fn update_passkey(
        &self,
        user_id: &Self::UserId,
        passkey: webauthn_rs::prelude::Passkey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Delete a passkey owned by the user.
    #[cfg(all(feature = "webauthn", feature = "user"))]
    fn delete_passkey(
        &self,
        user_id: &Self::UserId,
        credential_id: &[u8],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // password store
    #[cfg(feature = "password")]
    fn get_user_by_password_id(
        &self,
        password_id: &str,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;
    #[cfg(feature = "password")]
    fn create_user_by_password_id(
        &self,
        password_id: &str,
        password_hash: &str,
    ) -> impl Future<Output = Result<Self::User, Self::Error>> + Send;

    // email store
    #[cfg(feature = "email")]
    fn get_user_by_email_address(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<Option<(Self::User, Self::UserEmail)>, Self::Error>> + Send;
    #[cfg(feature = "email")]
    fn create_user_by_email_address(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<(Self::User, Self::UserEmail), Self::Error>> + Send;
    #[cfg(feature = "email")]
    fn set_email_verified(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Shared challenge store, used by email links, email OTP and SMS codes
    /// (keys are namespaced per flow).
    #[cfg(any(feature = "email", feature = "sms"))]
    fn create_challenge(
        &self,
        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> impl Future<Output = Result<Self::EmailChallenge, Self::Error>> + Send;
    /// Fetch AND delete - challenges are single-use.
    #[cfg(any(feature = "email", feature = "sms"))]
    fn consume_challenge(
        &self,
        code: String,
    ) -> impl Future<Output = Result<Option<Self::EmailChallenge>, Self::Error>> + Send;

    // sms store
    #[cfg(feature = "sms")]
    fn get_user_by_phone(
        &self,
        number: &str,
    ) -> impl Future<Output = Result<Option<(Self::User, Self::UserPhone)>, Self::Error>> + Send;
    #[cfg(feature = "sms")]
    fn create_user_by_phone(
        &self,
        number: &str,
    ) -> impl Future<Output = Result<(Self::User, Self::UserPhone), Self::Error>> + Send;
    /// The user's phone numbers (used by the MFA factor discovery).
    #[cfg(feature = "sms")]
    fn get_user_phones(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Vec<Self::UserPhone>, Self::Error>> + Send;

    // oauth store
    #[cfg(feature = "oauth")]
    fn update_token_by_unmatched_token(
        &self,
        token_id: &Self::OAuthTokenId,
        unmatched_token: UnmatchedOAuthToken,
    ) -> impl Future<Output = Result<Self::OAuthToken, Self::Error>> + Send;
    #[cfg(feature = "oauth")]
    fn get_oauth_token_by_id(
        &self,
        token_id: &Self::OAuthTokenId,
    ) -> impl Future<Output = Result<Option<Self::OAuthToken>, Self::Error>> + Send;
    #[cfg(feature = "oauth")]
    fn get_token_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> impl Future<Output = Result<Option<Self::OAuthToken>, Self::Error>> + Send;
    #[cfg(feature = "oauth")]
    fn create_user_token_from_unmatched_token(
        &self,
        user_id: &Self::UserId,
        unmatched_token: UnmatchedOAuthToken,
    ) -> impl Future<Output = Result<Self::OAuthToken, Self::Error>> + Send;
    #[cfg(feature = "oauth")]
    fn create_user_from_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> impl Future<Output = Result<(Self::User, Self::OAuthToken), Self::Error>> + Send;
    #[cfg(feature = "oauth")]
    fn get_user_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> impl Future<Output = Result<Option<(Self::User, Self::OAuthToken)>, Self::Error>> + Send;

    // user store
    #[cfg(all(feature = "user", feature = "oauth"))]
    fn get_user_oauth_tokens(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Vec<Self::OAuthToken>, Self::Error>> + Send;
    #[cfg(all(feature = "user", feature = "oauth"))]
    fn delete_oauth_token(
        &self,
        user_id: &Self::UserId,
        token_id: &Self::OAuthTokenId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    #[cfg(feature = "user")]
    fn delete_user(
        &self,
        id: &Self::UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    #[cfg(all(feature = "user", feature = "password"))]
    fn clear_user_password_hash(
        &self,
        user_id: &Self::UserId,
        session_id: &Self::SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    #[cfg(feature = "email")]
    fn get_user_emails(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Vec<Self::UserEmail>, Self::Error>> + Send;

    #[cfg(all(any(feature = "user", feature = "email"), feature = "password"))]
    fn set_user_password_hash(
        &self,
        user_id: &Self::UserId,
        password_hash: String,
        session_id: &Self::SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    #[cfg(all(feature = "user", feature = "email"))]
    fn set_user_email_allow_link_login(
        &self,
        user_id: &Self::UserId,
        address: String,
        allow_login: bool,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    #[cfg(all(feature = "user", feature = "email"))]
    fn add_user_email(
        &self,
        user_id: &Self::UserId,
        address: String,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    #[cfg(all(feature = "user", feature = "email"))]
    fn delete_user_email(
        &self,
        user_id: &Self::UserId,
        address: String,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
