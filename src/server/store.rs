#[cfg(feature = "server-email")]
use crate::models::email::{EmailChallenge, UserEmail};
#[cfg(feature = "server-oauth")]
use crate::models::oauth::{OAuthToken, UnmatchedOAuthToken};
use crate::models::{LoginMethod, LoginSession, User};
use async_trait::async_trait;
#[cfg(feature = "server-email")]
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
pub trait UserpStore: Send + Sync {
    type User: User;
    type LoginSession: LoginSession;
    type Error: std::error::Error + Send;

    #[cfg(feature = "server-email")]
    type UserEmail: UserEmail;
    #[cfg(feature = "server-email")]
    type EmailChallenge: EmailChallenge;
    #[cfg(feature = "server-oauth")]
    type OAuthToken: OAuthToken;

    // basic store
    async fn get_user(&self, user_id: Uuid) -> Result<Option<Self::User>, Self::Error>;
    async fn create_session(
        &self,
        user_id: Uuid,
        method: LoginMethod,
    ) -> Result<Self::LoginSession, Self::Error>;
    async fn get_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<Self::LoginSession>, Self::Error>;
    async fn delete_session(&self, user_id: Uuid, session_id: Uuid) -> Result<(), Self::Error>;

    // password store
    #[cfg(feature = "server-password")]
    async fn password_get_user_by_password_id(
        &self,
        password_id: &str,
    ) -> Result<Option<Self::User>, Self::Error>;
    #[cfg(feature = "server-password")]
    async fn password_create_user(
        &self,
        password_id: &str,
        password_hash: &str,
    ) -> Result<Self::User, Self::Error>;

    // email store
    #[cfg(feature = "server-email")]
    async fn email_get_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<Option<(Self::User, Self::UserEmail)>, Self::Error>;
    #[cfg(feature = "server-email")]
    async fn email_create_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<(Self::User, Self::UserEmail), Self::Error>;
    #[cfg(feature = "server-email")]
    async fn email_set_verified(&self, address: &str) -> Result<(), Self::Error>;
    #[cfg(feature = "server-email")]
    async fn email_create_challenge(
        &self,
        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> Result<Self::EmailChallenge, Self::Error>;
    #[cfg(feature = "server-email")]
    async fn email_consume_challenge(
        &self,
        code: String,
    ) -> Result<Option<Self::EmailChallenge>, Self::Error>;

    // oauth store
    #[cfg(feature = "server-oauth")]
    async fn update_token_by_unmatched_token(
        &self,
        token_id: Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error>;
    #[cfg(feature = "server-oauth")]
    async fn oauth_get_token_by_id(
        &self,
        token_id: Uuid,
    ) -> Result<Option<Self::OAuthToken>, Self::Error>;
    #[cfg(feature = "server-oauth")]
    async fn get_token_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Option<Self::OAuthToken>, Self::Error>;
    #[cfg(feature = "server-oauth")]
    async fn create_user_token_from_unmatched_token(
        &self,
        user_id: Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error>;
    #[cfg(feature = "server-oauth")]
    async fn create_user_from_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<(Self::User, Self::OAuthToken), Self::Error>;
    #[cfg(feature = "server-oauth")]
    async fn get_user_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Option<(Self::User, Self::OAuthToken)>, Self::Error>;

    // account store
    #[cfg(feature = "server-account")]
    async fn get_user_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Self::LoginSession>, Self::Error>;
    #[cfg(all(feature = "server-account", feature = "server-oauth"))]
    async fn get_user_oauth_tokens(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Self::OAuthToken>, Self::Error>;
    #[cfg(all(feature = "server-account", feature = "server-oauth"))]
    async fn delete_oauth_token(&self, user_id: Uuid, token_id: Uuid) -> Result<(), Self::Error>;
    #[cfg(feature = "server-account")]
    async fn delete_user(&self, id: Uuid) -> Result<(), Self::Error>;
    #[cfg(all(feature = "server-account", feature = "server-password"))]
    async fn clear_user_password_hash(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<(), Self::Error>;
    #[cfg(all(feature = "server-account", feature = "server-email"))]
    async fn get_user_emails(&self, user_id: Uuid) -> Result<Vec<Self::UserEmail>, Self::Error>;

    #[cfg(all(any(feature = "server-account", feature = "server-email"), feature = "server-password"))]
    async fn set_user_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
        session_id: Uuid,
    ) -> Result<(), Self::Error>;

    #[cfg(all(feature = "server-account", feature = "server-email"))]
    async fn set_user_email_allow_link_login(
        &self,
        user_id: Uuid,
        address: String,
        allow_login: bool,
    ) -> Result<(), Self::Error>;
    #[cfg(all(feature = "server-account", feature = "server-email"))]
    async fn add_user_email(&self, user_id: Uuid, address: String) -> Result<(), Self::Error>;
    #[cfg(all(feature = "server-account", feature = "server-email"))]
    async fn delete_user_email(&self, user_id: Uuid, address: String) -> Result<(), Self::Error>;
}
