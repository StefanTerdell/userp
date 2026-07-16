//! Trait-only entities for the `organizations` feature. Like the other
//! entities, the store owns the concrete types and authery interacts through
//! these traits with generic id types.

use super::Id;
use serde::{Deserialize, Serialize};

/// The member role that is always allowed to manage an organization: its
/// settings, members, sub-organizations, providers and invites.
pub const ORG_OWNER_ROLE: &str = "owner";

/// How members of an organization are allowed to log in when accessing it.
/// Checked by [`crate::core::CoreAuthery::org_session`]; an app enforces the
/// rules by gating its org-scoped routes on that call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgLoginRules {
    /// Only sessions created with two factors ([`crate::models::LoginMethod::Mfa`])
    /// count as logged in for this org.
    pub require_mfa: bool,
    /// Whether password sessions count as logged in for this org.
    pub allow_password: bool,
    /// Whether emailed link/code sessions count as logged in for this org.
    pub allow_email: bool,
}

impl Default for OrgLoginRules {
    fn default() -> Self {
        Self {
            require_mfa: false,
            allow_password: true,
            allow_email: true,
        }
    }
}

/// An organization: a live sub-configuration of the auth stack. May have a
/// parent, forming a tree; role inheritance maps a member's roles in the
/// parent onto roles in this organization.
pub trait Organization: Send + Sync + Sized {
    type Id: Id;

    fn get_id(&self) -> Self::Id;
    /// The parent organization, if this is a sub-organization.
    fn get_parent_id(&self) -> Option<Self::Id>;
    /// URL-safe handle used in org-scoped routes like `/login/{slug}`.
    /// Unique across all organizations.
    fn get_slug(&self) -> &str;
    fn get_name(&self) -> &str;
    /// How members must be logged in when accessing this organization.
    fn get_login_rules(&self) -> OrgLoginRules;
    /// Role inheritance from the parent: `(parent_role, role_here)` pairs.
    /// A user holding `parent_role` in the parent organization effectively
    /// holds `role_here` in this one, without a membership row.
    fn get_role_inheritance(&self) -> Vec<(String, String)>;
}

/// A user's membership in an organization, carrying their roles there. Role
/// names are app-defined strings; [`ORG_OWNER_ROLE`] is the only one authery
/// itself interprets.
pub trait OrgMember: Send + Sync + Sized {
    type UserId: Id;
    type OrgId: Id;

    fn get_user_id(&self) -> Self::UserId;
    fn get_org_id(&self) -> Self::OrgId;
    fn get_roles(&self) -> Vec<String>;
}

/// The configuration of an org-attached OIDC provider, as passed to the store
/// on creation. SaaS mode: org owners register their own SSO here.
#[cfg(feature = "oauth")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrgOidcProvider {
    /// Unique within the organization; used in routes and forms.
    pub name: String,
    pub display_name: String,
    pub client_id: String,
    pub client_secret: String,
    /// OIDC issuer URL; its discovery document/JWKS validate id_tokens.
    pub issuer: String,
    pub auth_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    /// Whether this provider may be used to log in to the org (as opposed to
    /// integration-only token access).
    pub allow_login: bool,
    /// Roles granted to anyone who logs in through this provider.
    pub default_roles: Vec<String>,
    /// `(claim, value, role)` rows: when the validated id_token has `claim`
    /// equal to (or an array containing) `value`, the member gets `role`.
    pub claim_role_mapping: Vec<(String, String, String)>,
}

/// A stored org-attached OIDC provider. See [`NewOrgOidcProvider`] for field
/// semantics.
#[cfg(feature = "oauth")]
pub trait OrgOidcProvider: Send + Sync + Sized {
    type OrgId: Id;

    fn get_org_id(&self) -> Self::OrgId;
    fn get_name(&self) -> &str;
    fn get_display_name(&self) -> &str;
    fn get_client_id(&self) -> &str;
    fn get_client_secret(&self) -> &str;
    fn get_issuer(&self) -> &str;
    fn get_auth_url(&self) -> &str;
    fn get_token_url(&self) -> &str;
    fn get_scopes(&self) -> Vec<String>;
    fn get_allow_login(&self) -> bool;
    fn get_default_roles(&self) -> Vec<String>;
    fn get_claim_role_mapping(&self) -> Vec<(String, String, String)>;
}
