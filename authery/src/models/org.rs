//! Trait-only entities for the `organizations` feature. Like the other
//! entities, the store owns the concrete types and authery interacts through
//! these traits with generic id types.
//!
//! # Privileges vs roles
//!
//! Two separate axes live on a membership:
//!
//! - **[`OrgPrivilege`]** - the only thing authery itself interprets. It gates
//!   the built-in management surface (settings, members, invites, providers,
//!   sub-orgs) and nothing else.
//! - **Roles** - opaque, app-defined strings. Authery stores and transports
//!   them (invites, SSO claim mapping, inheritance) and hands them back from
//!   [`crate::core::CoreAuthery::org_session`], but never interprets them.
//!
//! Because the axes are separate types, app roles can never accidentally (or
//! maliciously, via an IdP claim or invite) grant management access: a
//! privilege is only ever granted as an explicit, typed act.

use super::Id;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::str::FromStr;

/// What a member may do with the organization itself, in strictly increasing
/// order - [`OrgPrivilege::Owner`] can do everything a
/// [`OrgPrivilege::Manager`] can. This is deliberately a short ladder rather
/// than a permission matrix: anything finer belongs to your app's own roles.
///
/// There is no canonical storage representation - stores persist it however
/// they like (the serde derives exist so authery-owned config structs that
/// embed it, like [`NewOrgOidcProvider`], stay serializable as a convenience).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OrgPrivilege {
    /// Day-to-day administration: managing members and invites. Managers can
    /// not grant or revoke privileges, remove privileged members, or touch
    /// settings, providers, sub-orgs or the org itself.
    Manager,
    /// Full control, including settings, login rules, SSO providers (and
    /// their secrets), sub-organizations, privilege assignment and deletion.
    Owner,
}

impl Display for OrgPrivilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OrgPrivilege::Manager => "manager",
            OrgPrivilege::Owner => "owner",
        })
    }
}

impl FromStr for OrgPrivilege {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "manager" => Ok(OrgPrivilege::Manager),
            "owner" => Ok(OrgPrivilege::Owner),
            _ => Err(()),
        }
    }
}

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
/// parent, forming a tree; inheritance maps a member's roles and privilege in
/// the parent onto this organization.
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
    /// holds `role_here` in this one, without a membership row. App roles
    /// only - privileges inherit via
    /// [`Organization::get_privilege_inheritance`].
    fn get_role_inheritance(&self) -> Vec<(String, String)>;
    /// Privilege inheritance from the parent: `(parent_privilege,
    /// privilege_here)` pairs. E.g. `(Owner, Manager)` lets the parent's
    /// owners administer this org's members without being owners here.
    /// Empty by default: parent privileges grant nothing below.
    fn get_privilege_inheritance(&self) -> Vec<(OrgPrivilege, OrgPrivilege)>;
}

/// A user's membership in an organization: an optional authery-interpreted
/// [`OrgPrivilege`] plus app-owned role strings authery never interprets.
pub trait OrgMember: Send + Sync + Sized {
    type UserId: Id;
    type OrgId: Id;

    fn get_user_id(&self) -> Self::UserId;
    fn get_org_id(&self) -> Self::OrgId;
    /// The member's management privilege, if any.
    fn get_privilege(&self) -> Option<OrgPrivilege>;
    /// App-defined roles. Authery stores and returns these but attaches no
    /// meaning to them.
    fn get_roles(&self) -> Vec<String>;
}

/// A single-use, expiring invite into an organization. The code is embedded
/// in a link (`{signup}?invite={code}`); whoever completes any signup or
/// login flow holding it becomes a member with the invite's privilege and
/// roles.
pub trait OrgInvite: Send + Sync + Sized {
    type OrgId: Id;

    fn get_org_id(&self) -> Self::OrgId;
    fn get_code(&self) -> &str;
    /// The privilege the joiner receives. Only owners can create
    /// privilege-carrying invites.
    fn get_privilege(&self) -> Option<OrgPrivilege>;
    fn get_roles(&self) -> Vec<String>;
    fn get_expires(&self) -> chrono::DateTime<chrono::Utc>;
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
    /// Dotted claim paths reach into nested objects.
    pub claim_role_mapping: Vec<(String, String, String)>,
    /// `(claim, value, privilege)` rows granting management privileges from
    /// IdP claims - e.g. map an admins group onto [`OrgPrivilege::Manager`].
    /// A matched privilege upgrades the membership but never downgrades it,
    /// so org owners can't be locked out by their own IdP mapping.
    pub claim_privilege_mapping: Vec<(String, String, OrgPrivilege)>,
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
    fn get_claim_privilege_mapping(&self) -> Vec<(String, String, OrgPrivilege)>;
}
