#[cfg(feature = "email")]
use crate::models::email::{EmailChallenge, UserEmail};
#[cfg(feature = "oauth")]
use crate::models::oauth::{OAuthToken, UnmatchedOAuthToken};
#[cfg(feature = "organizations")]
use crate::models::org::{Organization, OrgMember};
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

    #[cfg(feature = "organizations")]
    type OrgId: Id;

    type User: User<Id = Self::UserId>;
    type LoginSession: LoginSession<Id = Self::SessionId, UserId = Self::UserId>;
    #[cfg(feature = "organizations")]
    type Organization: Organization<Id = Self::OrgId>;
    #[cfg(feature = "organizations")]
    type OrgMember: OrgMember<UserId = Self::UserId, OrgId = Self::OrgId>;
    #[cfg(feature = "organizations")]
    type OrgInvite: crate::models::org::OrgInvite<OrgId = Self::OrgId>;
    #[cfg(all(feature = "organizations", feature = "oauth"))]
    type OrgOidcProvider: crate::models::org::OrgOidcProvider<OrgId = Self::OrgId>;
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

    // organizations store
    /// Create an organization. `slug` is unique across all organizations;
    /// creation fails (store error) on collision.
    #[cfg(feature = "organizations")]
    fn org_create(
        &self,
        name: &str,
        slug: &str,
        parent: Option<&Self::OrgId>,
    ) -> impl Future<Output = Result<Self::Organization, Self::Error>> + Send;
    #[cfg(feature = "organizations")]
    fn org_get(
        &self,
        org_id: &Self::OrgId,
    ) -> impl Future<Output = Result<Option<Self::Organization>, Self::Error>> + Send;
    #[cfg(feature = "organizations")]
    fn org_get_by_slug(
        &self,
        slug: &str,
    ) -> impl Future<Output = Result<Option<Self::Organization>, Self::Error>> + Send;
    /// Direct sub-organizations.
    #[cfg(feature = "organizations")]
    fn org_get_children(
        &self,
        org_id: &Self::OrgId,
    ) -> impl Future<Output = Result<Vec<Self::Organization>, Self::Error>> + Send;
    /// Update the mutable parts of an organization.
    #[cfg(feature = "organizations")]
    fn org_update(
        &self,
        org_id: &Self::OrgId,
        name: &str,
        login_rules: crate::models::org::OrgLoginRules,
        role_inheritance: Vec<(String, String)>,
        privilege_inheritance: Vec<(
            crate::models::org::OrgPrivilege,
            crate::models::org::OrgPrivilege,
        )>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Delete an organization and its memberships. Sub-organizations are the
    /// store's concern (cascade or reject).
    #[cfg(feature = "organizations")]
    fn org_delete(
        &self,
        org_id: &Self::OrgId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Add a user to an organization, or replace their privilege and roles if
    /// already a member.
    #[cfg(feature = "organizations")]
    fn org_upsert_member(
        &self,
        org_id: &Self::OrgId,
        user_id: &Self::UserId,
        privilege: Option<crate::models::org::OrgPrivilege>,
        roles: Vec<String>,
    ) -> impl Future<Output = Result<Self::OrgMember, Self::Error>> + Send;
    #[cfg(feature = "organizations")]
    fn org_remove_member(
        &self,
        org_id: &Self::OrgId,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    #[cfg(feature = "organizations")]
    fn org_get_member(
        &self,
        org_id: &Self::OrgId,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Option<Self::OrgMember>, Self::Error>> + Send;
    #[cfg(feature = "organizations")]
    fn org_get_members(
        &self,
        org_id: &Self::OrgId,
    ) -> impl Future<Output = Result<Vec<Self::OrgMember>, Self::Error>> + Send;
    /// All organizations the user is a direct member of.
    #[cfg(feature = "organizations")]
    fn org_get_user_memberships(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Vec<Self::OrgMember>, Self::Error>> + Send;

    /// Persist an invite under its (unique, unguessable) code.
    #[cfg(feature = "organizations")]
    fn org_invite_create(
        &self,
        org_id: &Self::OrgId,
        code: &str,
        privilege: Option<crate::models::org::OrgPrivilege>,
        roles: Vec<String>,
        expires: DateTime<Utc>,
    ) -> impl Future<Output = Result<Self::OrgInvite, Self::Error>> + Send;
    /// Fetch AND delete the invite with this code - invites are single-use.
    #[cfg(feature = "organizations")]
    fn org_invite_consume(
        &self,
        code: &str,
    ) -> impl Future<Output = Result<Option<Self::OrgInvite>, Self::Error>> + Send;

    /// Create or replace (by name) an org-attached OIDC provider.
    #[cfg(all(feature = "organizations", feature = "oauth"))]
    fn org_oidc_upsert(
        &self,
        org_id: &Self::OrgId,
        provider: crate::models::org::NewOrgOidcProvider,
    ) -> impl Future<Output = Result<Self::OrgOidcProvider, Self::Error>> + Send;
    #[cfg(all(feature = "organizations", feature = "oauth"))]
    fn org_oidc_delete(
        &self,
        org_id: &Self::OrgId,
        name: &str,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    #[cfg(all(feature = "organizations", feature = "oauth"))]
    fn org_oidc_get(
        &self,
        org_id: &Self::OrgId,
        name: &str,
    ) -> impl Future<Output = Result<Option<Self::OrgOidcProvider>, Self::Error>> + Send;
    #[cfg(all(feature = "organizations", feature = "oauth"))]
    fn org_oidc_list(
        &self,
        org_id: &Self::OrgId,
    ) -> impl Future<Output = Result<Vec<Self::OrgOidcProvider>, Self::Error>> + Send;

    // webauthn store
    //
    // Passkeys are stored as opaque `webauthn_rs::prelude::Passkey` blobs
    // (serde-serializable) keyed by their credential id and owning user.
    /// Persist a newly registered passkey for the user.
    #[cfg(feature = "webauthn")]
    fn webauthn_create_credential(
        &self,
        user_id: &Self::UserId,
        passkey: webauthn_rs::prelude::Passkey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// All of the user's passkeys (used to exclude re-registration and for
    /// listing on the account page).
    #[cfg(feature = "webauthn")]
    fn webauthn_get_credentials(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<Vec<webauthn_rs::prelude::Passkey>, Self::Error>> + Send;
    /// Look up a passkey - and the user owning it - by raw credential id.
    #[cfg(feature = "webauthn")]
    fn webauthn_get_credential_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> impl Future<Output = Result<Option<(Self::UserId, webauthn_rs::prelude::Passkey)>, Self::Error>>
           + Send;
    /// Replace the stored passkey blob (called after logins to persist
    /// counter updates and backup-state changes).
    #[cfg(feature = "webauthn")]
    fn webauthn_update_credential(
        &self,
        user_id: &Self::UserId,
        passkey: webauthn_rs::prelude::Passkey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Delete a passkey owned by the user.
    #[cfg(all(feature = "webauthn", feature = "user"))]
    fn webauthn_delete_credential(
        &self,
        user_id: &Self::UserId,
        credential_id: &[u8],
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
