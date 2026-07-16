//! Organizations: live sub-configurations of the auth stack.
//!
//! Memberships carry two separate axes (see [`crate::models::org`]):
//! a typed [`OrgPrivilege`] gating authery's own management surface, and
//! app-defined role strings that authery stores and transports but never
//! interprets. Inheritance maps both axes from parent orgs onto sub-orgs,
//! each through its own typed mapping.
//!
//! Management is tiered: [`OrgPrivilege::Owner`] controls everything,
//! [`OrgPrivilege::Manager`] handles day-to-day members and invites but can
//! neither grant privileges, touch privileged members, nor reach settings,
//! providers or deletion.
//!
//! Access is enforced through [`CoreAuthery::org_session`]: it returns the
//! current session only when the user is an (effective) member AND the
//! session's login method satisfies the org's [`OrgLoginRules`] - gate your
//! org-scoped routes on it.

#[cfg(feature = "oauth")]
pub mod oauth;

use crate::{
    core::CoreAuthery,
    models::{
        org::{OrgLoginRules, OrgMember, OrgPrivilege, Organization},
        AutheryCookies, LoginMethod, LoginSession, User,
    },
    store::AutheryStore,
};
use thiserror::Error;

/// Maximum organization tree depth walked when resolving inherited roles and
/// privileges; also guards against parent cycles in a buggy store.
const MAX_ORG_DEPTH: usize = 32;

/// Cookie holding a pending invite code while the user completes a signup or
/// login flow.
const ORG_INVITE_KEY: &str = "authery-org-invite";

/// Configuration for the organizations feature.
#[derive(Debug, Clone, Default)]
pub struct OrgConfig {
    /// SaaS mode: create a private organization (owned by the user) the first
    /// time a user without any membership is created. Off by default, which
    /// suits on-prem setups where orgs are provisioned by the app.
    pub create_private_org_on_signup: bool,
}

/// A member's effective standing in an organization: their direct membership
/// combined with whatever the ancestor chain's inheritance mappings grant.
#[derive(Debug, Clone, Default)]
pub struct OrgMembership {
    pub privilege: Option<OrgPrivilege>,
    /// App-defined roles; authery attaches no meaning to them.
    pub roles: Vec<String>,
}

impl OrgMembership {
    /// Whether this constitutes membership at all.
    pub fn is_member(&self) -> bool {
        self.privilege.is_some() || !self.roles.is_empty()
    }

    /// Whether the membership carries at least this privilege.
    pub fn has_privilege(&self, min: OrgPrivilege) -> bool {
        self.privilege.is_some_and(|p| p >= min)
    }
}

#[derive(Debug, Error)]
pub enum OrgError<StoreError: std::error::Error> {
    #[error("Not logged in")]
    NotLoggedIn,
    #[error("Organization not found")]
    NotFound,
    #[error("Requires the '{0}' privilege in this organization")]
    MissingPrivilege(OrgPrivilege),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Create an organization owned by the logged-in user.
    pub async fn org_create(
        &self,
        name: &str,
        slug: &str,
    ) -> Result<S::Organization, OrgError<S::Error>> {
        let Some((user, _session)) = self.user_session().await? else {
            return Err(OrgError::NotLoggedIn);
        };

        let org = self.store.org_create(name, slug, None).await?;
        self.store
            .org_upsert_member(
                &org.get_id(),
                &user.get_id(),
                Some(OrgPrivilege::Owner),
                Vec::new(),
            )
            .await?;

        Ok(org)
    }

    /// Create a sub-organization. Requires the owner privilege (direct or
    /// inherited) in the parent; the creator becomes an owner of the child.
    pub async fn org_create_sub(
        &self,
        parent_id: &S::OrgId,
        name: &str,
        slug: &str,
    ) -> Result<S::Organization, OrgError<S::Error>> {
        let user_id = self.org_require(parent_id, OrgPrivilege::Owner).await?;

        let org = self.store.org_create(name, slug, Some(parent_id)).await?;
        self.store
            .org_upsert_member(&org.get_id(), &user_id, Some(OrgPrivilege::Owner), Vec::new())
            .await?;

        Ok(org)
    }

    /// Update an organization's settings. Requires the owner privilege.
    pub async fn org_update(
        &self,
        org_id: &S::OrgId,
        name: &str,
        login_rules: OrgLoginRules,
        role_inheritance: Vec<(String, String)>,
        privilege_inheritance: Vec<(OrgPrivilege, OrgPrivilege)>,
    ) -> Result<(), OrgError<S::Error>> {
        self.org_require(org_id, OrgPrivilege::Owner).await?;

        self.store
            .org_update(
                org_id,
                name,
                login_rules,
                role_inheritance,
                privilege_inheritance,
            )
            .await?;

        Ok(())
    }

    /// Delete an organization. Requires the owner privilege.
    pub async fn org_delete(&self, org_id: &S::OrgId) -> Result<(), OrgError<S::Error>> {
        self.org_require(org_id, OrgPrivilege::Owner).await?;

        self.store.org_delete(org_id).await?;

        Ok(())
    }

    /// Add a member or replace an existing member's privilege and roles.
    /// Requires the manager privilege; granting a privilege, or touching a
    /// member who holds one, requires owner (so managers can neither escalate
    /// themselves nor demote/strip the privileged).
    pub async fn org_upsert_member(
        &self,
        org_id: &S::OrgId,
        user_id: &S::UserId,
        privilege: Option<OrgPrivilege>,
        roles: Vec<String>,
    ) -> Result<S::OrgMember, OrgError<S::Error>> {
        let target_privileged = self
            .store
            .org_get_member(org_id, user_id)
            .await?
            .and_then(|m| m.get_privilege())
            .is_some();

        let required = if privilege.is_some() || target_privileged {
            OrgPrivilege::Owner
        } else {
            OrgPrivilege::Manager
        };
        self.org_require(org_id, required).await?;

        Ok(self
            .store
            .org_upsert_member(org_id, user_id, privilege, roles)
            .await?)
    }

    /// Remove a member. Members may remove themselves; otherwise the manager
    /// privilege is required, or owner if the target holds a privilege.
    pub async fn org_remove_member(
        &self,
        org_id: &S::OrgId,
        user_id: &S::UserId,
    ) -> Result<(), OrgError<S::Error>> {
        let acting = match self.user_session().await? {
            Some((user, _)) => user.get_id(),
            None => return Err(OrgError::NotLoggedIn),
        };

        if acting != *user_id {
            let target_privileged = self
                .store
                .org_get_member(org_id, user_id)
                .await?
                .and_then(|m| m.get_privilege())
                .is_some();

            let required = if target_privileged {
                OrgPrivilege::Owner
            } else {
                OrgPrivilege::Manager
            };
            self.org_require(org_id, required).await?;
        }

        self.store.org_remove_member(org_id, user_id).await?;

        Ok(())
    }

    /// The user's effective membership in the organization: their direct
    /// privilege and roles, combined with whatever the ancestor chain grants
    /// through each level's role- and privilege-inheritance mappings.
    pub async fn org_effective_membership(
        &self,
        org_id: &S::OrgId,
        user_id: &S::UserId,
    ) -> Result<OrgMembership, OrgError<S::Error>> {
        // Collect the chain from this org up to the root.
        let mut chain = Vec::new();
        let mut cursor = Some(org_id.clone());

        while let Some(id) = cursor {
            if chain.len() >= MAX_ORG_DEPTH {
                break;
            }

            let Some(org) = self.store.org_get(&id).await? else {
                return Err(OrgError::NotFound);
            };
            cursor = org.get_parent_id();
            chain.push(org);
        }

        // Fold back down from the root: each level combines the direct
        // membership with the parent's effective standing mapped through this
        // level's inheritance pairs.
        let mut effective = OrgMembership::default();

        for org in chain.iter().rev() {
            let direct = self.store.org_get_member(&org.get_id(), user_id).await?;

            let inherited_privilege = org
                .get_privilege_inheritance()
                .into_iter()
                .filter(|(parent_privilege, _)| {
                    effective.privilege.is_some_and(|p| p >= *parent_privilege)
                })
                .map(|(_, privilege_here)| privilege_here)
                .max();

            let inherited_roles: Vec<String> = org
                .get_role_inheritance()
                .into_iter()
                .filter(|(parent_role, _)| effective.roles.contains(parent_role))
                .map(|(_, role_here)| role_here)
                .collect();

            let mut next = OrgMembership {
                privilege: direct.as_ref().and_then(|m| m.get_privilege()),
                roles: direct.map(|m| m.get_roles()).unwrap_or_default(),
            };

            next.privilege = next.privilege.max(inherited_privilege);
            for role in inherited_roles {
                if !next.roles.contains(&role) {
                    next.roles.push(role);
                }
            }

            effective = next;
        }

        Ok(effective)
    }

    /// The user's effective app roles in the organization. See
    /// [`CoreAuthery::org_effective_membership`].
    pub async fn org_effective_roles(
        &self,
        org_id: &S::OrgId,
        user_id: &S::UserId,
    ) -> Result<Vec<String>, OrgError<S::Error>> {
        Ok(self
            .org_effective_membership(org_id, user_id)
            .await?
            .roles)
    }

    /// The user's effective privilege in the organization. See
    /// [`CoreAuthery::org_effective_membership`].
    pub async fn org_effective_privilege(
        &self,
        org_id: &S::OrgId,
        user_id: &S::UserId,
    ) -> Result<Option<OrgPrivilege>, OrgError<S::Error>> {
        Ok(self
            .org_effective_membership(org_id, user_id)
            .await?
            .privilege)
    }

    /// The current session, if its user is an effective member of the
    /// organization and the login method satisfies the org's login rules.
    /// Returns the session together with the user's effective membership.
    pub async fn org_session(
        &self,
        org_id: &S::OrgId,
    ) -> Result<Option<(S::LoginSession, OrgMembership)>, OrgError<S::Error>> {
        let Some(session) = self.session().await? else {
            return Ok(None);
        };

        let Some(org) = self.store.org_get(org_id).await? else {
            return Err(OrgError::NotFound);
        };

        if !method_satisfies_rules(&session.get_method(), &org.get_login_rules()) {
            return Ok(None);
        }

        let membership = self
            .org_effective_membership(org_id, &session.get_user_id())
            .await?;

        if !membership.is_member() {
            return Ok(None);
        }

        Ok(Some((session, membership)))
    }

    /// Create a single-use invite into the organization, carrying the
    /// privilege and roles the joiner will receive. Role-only invites require
    /// the manager privilege; privilege-carrying invites require owner.
    /// Returns the invite; embed its code in a link like
    /// `{signup_page}?invite={code}`.
    pub async fn org_invite_create(
        &self,
        org_id: &S::OrgId,
        privilege: Option<OrgPrivilege>,
        roles: Vec<String>,
        lifetime: chrono::Duration,
    ) -> Result<S::OrgInvite, OrgError<S::Error>> {
        let required = if privilege.is_some() {
            OrgPrivilege::Owner
        } else {
            OrgPrivilege::Manager
        };
        self.org_require(org_id, required).await?;

        let code = uuid::Uuid::new_v4().to_string().replace('-', "");

        Ok(self
            .store
            .org_invite_create(org_id, &code, privilege, roles, chrono::Utc::now() + lifetime)
            .await?)
    }

    /// Stash an invite code in the cookie jar so it survives whichever
    /// signup/login flow the user completes. Typically called by the
    /// login/signup page handlers when an `invite` query parameter arrives.
    pub fn org_set_invite_cookie(&mut self, code: &str) {
        self.cookies.add(ORG_INVITE_KEY, code);
    }

    /// Login hook: consume a pending invite, if any, and add the user to its
    /// organization. Runs before private-org provisioning so invited users
    /// don't get a private org (they already have a membership).
    pub(crate) async fn org_apply_invite(&mut self, user_id: &S::UserId) -> Result<(), S::Error> {
        use crate::models::org::OrgInvite;

        let Some(code) = self.cookies.get(ORG_INVITE_KEY) else {
            return Ok(());
        };
        // Single-use either way: a bad invite shouldn't stick around.
        self.cookies.remove(ORG_INVITE_KEY);

        let Some(invite) = self.store.org_invite_consume(&code).await? else {
            return Ok(());
        };

        if invite.get_expires() < chrono::Utc::now() {
            return Ok(());
        }

        self.store
            .org_upsert_member(
                &invite.get_org_id(),
                user_id,
                invite.get_privilege(),
                invite.get_roles(),
            )
            .await?;

        Ok(())
    }

    /// SaaS-mode hook, called after a fresh user is created by any signup
    /// flow: give membership-less users a private organization they own.
    pub(crate) async fn org_ensure_private_org(
        &self,
        user_id: &S::UserId,
    ) -> Result<(), S::Error> {
        if !self.org_config.create_private_org_on_signup {
            return Ok(());
        }

        if !self
            .store
            .org_get_user_memberships(user_id)
            .await?
            .is_empty()
        {
            return Ok(());
        }

        let slug = format!("user-{user_id}");
        let org = self.store.org_create("Private", &slug, None).await?;
        self.store
            .org_upsert_member(&org.get_id(), user_id, Some(OrgPrivilege::Owner), Vec::new())
            .await?;

        Ok(())
    }

    /// The acting user's id, if they hold at least this privilege (directly
    /// or inherited) in the organization.
    pub(crate) async fn org_require(
        &self,
        org_id: &S::OrgId,
        min: OrgPrivilege,
    ) -> Result<S::UserId, OrgError<S::Error>> {
        let Some((user, _session)) = self.user_session().await? else {
            return Err(OrgError::NotLoggedIn);
        };

        let user_id = user.get_id();
        let membership = self.org_effective_membership(org_id, &user_id).await?;

        if membership.has_privilege(min) {
            Ok(user_id)
        } else {
            Err(OrgError::MissingPrivilege(min))
        }
    }
}

/// Whether a session's login method satisfies the org's rules. The `allow_*`
/// rules judge the first factor; `require_mfa` accepts two-factor sessions and
/// single-factor passkeys (possession + user verification).
fn method_satisfies_rules(method: &LoginMethod, rules: &OrgLoginRules) -> bool {
    #[cfg(feature = "mfa")]
    let (first, is_mfa) = match method {
        LoginMethod::Mfa { first, .. } => (first.as_ref(), true),
        method => (method, false),
    };
    #[cfg(not(feature = "mfa"))]
    let (first, is_mfa) = (method, false);

    if rules.require_mfa {
        #[cfg(feature = "webauthn")]
        let strong_single = matches!(first, LoginMethod::Webauthn { .. });
        #[cfg(not(feature = "webauthn"))]
        let strong_single = false;

        if !is_mfa && !strong_single {
            return false;
        }
    }

    match first {
        #[cfg(feature = "password")]
        LoginMethod::Password => rules.allow_password,
        #[cfg(feature = "email")]
        LoginMethod::Email { .. } => rules.allow_email,
        #[cfg(feature = "otp")]
        LoginMethod::Otp { .. } => rules.allow_email,
        _ => true,
    }
}
