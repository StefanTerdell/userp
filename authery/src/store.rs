#[cfg(feature = "email")]
use crate::models::email::{EmailChallenge, UserEmail};
#[cfg(feature = "oauth")]
use crate::models::oauth::{OAuthToken, UnmatchedOAuthToken};
use crate::models::{Id, LoginMethod, LoginSession, User};
#[cfg(feature = "email")]
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
    #[cfg(feature = "email")]
    type EmailChallenge: EmailChallenge;
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

    // password store
    #[cfg(feature = "password")]
    fn password_get_user_by_password_id(
        &self,
        password_id: &str,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;
    #[cfg(feature = "password")]
    fn password_create_user(
        &self,
        password_id: &str,
        password_hash: &str,
    ) -> impl Future<Output = Result<Self::User, Self::Error>> + Send;

    // email store
    #[cfg(feature = "email")]
    fn email_get_user_by_email_address(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<Option<(Self::User, Self::UserEmail)>, Self::Error>> + Send;
    #[cfg(feature = "email")]
    fn email_create_user_by_email_address(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<(Self::User, Self::UserEmail), Self::Error>> + Send;
    #[cfg(feature = "email")]
    fn email_set_verified(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    #[cfg(feature = "email")]
    fn email_create_challenge(
        &self,
        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> impl Future<Output = Result<Self::EmailChallenge, Self::Error>> + Send;
    #[cfg(feature = "email")]
    fn email_consume_challenge(
        &self,
        code: String,
    ) -> impl Future<Output = Result<Option<Self::EmailChallenge>, Self::Error>> + Send;

    // oauth store
    #[cfg(feature = "oauth")]
    fn update_token_by_unmatched_token(
        &self,
        token_id: &Self::OAuthTokenId,
        unmatched_token: UnmatchedOAuthToken,
    ) -> impl Future<Output = Result<Self::OAuthToken, Self::Error>> + Send;
    #[cfg(feature = "oauth")]
    fn oauth_get_token_by_id(
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
    #[cfg(feature = "user")]
    fn get_user_sessions(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Vec<Self::LoginSession>, Self::Error>> + Send;
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
    #[cfg(all(feature = "user", feature = "email"))]
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
