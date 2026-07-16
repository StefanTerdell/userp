//! Organizations: live sub-configurations of the auth stack.
//!
//! An organization tree carries memberships with app-defined string roles.
//! Only [`ORG_OWNER_ROLE`] is interpreted by authery: owners manage the org.
//! Role inheritance maps a member's roles in a parent org onto roles in a
//! sub-org without a membership row there.
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
        org::{OrgLoginRules, OrgMember, Organization, ORG_OWNER_ROLE},
        AutheryCookies, LoginMethod, LoginSession, User,
    },
    store::AutheryStore,
};
use thiserror::Error;

/// Maximum organization tree depth walked when resolving inherited roles;
/// also guards against parent cycles in a buggy store.
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

#[derive(Debug, Error)]
pub enum OrgError<StoreError: std::error::Error> {
    #[error("Not logged in")]
    NotLoggedIn,
    #[error("Organization not found")]
    NotFound,
    #[error("Requires the '{ORG_OWNER_ROLE}' role in this organization")]
    NotOwner,
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
            .org_upsert_member(&org.get_id(), &user.get_id(), vec![ORG_OWNER_ROLE.into()])
            .await?;

        Ok(org)
    }

    /// Create a sub-organization. Requires the owner role (direct or
    /// inherited) in the parent; the creator becomes an owner of the child.
    pub async fn org_create_sub(
        &self,
        parent_id: &S::OrgId,
        name: &str,
        slug: &str,
    ) -> Result<S::Organization, OrgError<S::Error>> {
        let user_id = self.org_require_owner(parent_id).await?;

        let org = self.store.org_create(name, slug, Some(parent_id)).await?;
        self.store
            .org_upsert_member(&org.get_id(), &user_id, vec![ORG_OWNER_ROLE.into()])
            .await?;

        Ok(org)
    }

    /// Update an organization's settings. Requires the owner role.
    pub async fn org_update(
        &self,
        org_id: &S::OrgId,
        name: &str,
        login_rules: OrgLoginRules,
        role_inheritance: Vec<(String, String)>,
    ) -> Result<(), OrgError<S::Error>> {
        self.org_require_owner(org_id).await?;

        self.store
            .org_update(org_id, name, login_rules, role_inheritance)
            .await?;

        Ok(())
    }

    /// Delete an organization. Requires the owner role.
    pub async fn org_delete(&self, org_id: &S::OrgId) -> Result<(), OrgError<S::Error>> {
        self.org_require_owner(org_id).await?;

        self.store.org_delete(org_id).await?;

        Ok(())
    }

    /// Add a member or replace an existing member's roles. Requires the owner
    /// role.
    pub async fn org_upsert_member(
        &self,
        org_id: &S::OrgId,
        user_id: &S::UserId,
        roles: Vec<String>,
    ) -> Result<S::OrgMember, OrgError<S::Error>> {
        self.org_require_owner(org_id).await?;

        Ok(self.store.org_upsert_member(org_id, user_id, roles).await?)
    }

    /// Remove a member. Requires the owner role (members may also remove
    /// themselves).
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
            self.org_require_owner(org_id).await?;
        }

        self.store.org_remove_member(org_id, user_id).await?;

        Ok(())
    }

    /// The user's effective roles in the organization: their direct roles
    /// plus roles inherited from ancestors via each level's role-inheritance
    /// mapping.
    pub async fn org_effective_roles(
        &self,
        org_id: &S::OrgId,
        user_id: &S::UserId,
    ) -> Result<Vec<String>, OrgError<S::Error>> {
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

        // Fold back down from the root: effective roles at each level are the
        // direct membership roles plus the parent's effective roles mapped
        // through this level's inheritance pairs.
        let mut effective: Vec<String> = Vec::new();

        for org in chain.iter().rev() {
            let direct = self
                .store
                .org_get_member(&org.get_id(), user_id)
                .await?
                .map(|m| m.get_roles())
                .unwrap_or_default();

            let inherited = org
                .get_role_inheritance()
                .into_iter()
                .filter(|(parent_role, _)| effective.contains(parent_role))
                .map(|(_, role_here)| role_here);

            let mut next: Vec<String> = direct;
            for role in inherited {
                if !next.contains(&role) {
                    next.push(role);
                }
            }

            effective = next;
        }

        Ok(effective)
    }

    /// The current session, if its user is an effective member of the
    /// organization and the login method satisfies the org's login rules.
    /// Returns the session together with the user's effective roles.
    pub async fn org_session(
        &self,
        org_id: &S::OrgId,
    ) -> Result<Option<(S::LoginSession, Vec<String>)>, OrgError<S::Error>> {
        let Some(session) = self.session().await? else {
            return Ok(None);
        };

        let Some(org) = self.store.org_get(org_id).await? else {
            return Err(OrgError::NotFound);
        };

        if !method_satisfies_rules(&session.get_method(), &org.get_login_rules()) {
            return Ok(None);
        }

        let roles = self
            .org_effective_roles(org_id, &session.get_user_id())
            .await?;

        if roles.is_empty() {
            return Ok(None);
        }

        Ok(Some((session, roles)))
    }

    /// Create a single-use invite into the organization, carrying the roles
    /// the joiner will receive. Requires the owner role. Returns the invite;
    /// embed its code in a link like `{signup_page}?invite={code}`.
    pub async fn org_invite_create(
        &self,
        org_id: &S::OrgId,
        roles: Vec<String>,
        lifetime: chrono::Duration,
    ) -> Result<S::OrgInvite, OrgError<S::Error>> {
        self.org_require_owner(org_id).await?;

        let code = uuid::Uuid::new_v4().to_string().replace('-', "");

        Ok(self
            .store
            .org_invite_create(org_id, &code, roles, chrono::Utc::now() + lifetime)
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
            .org_upsert_member(&invite.get_org_id(), user_id, invite.get_roles())
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
            .org_upsert_member(&org.get_id(), user_id, vec![ORG_OWNER_ROLE.into()])
            .await?;

        Ok(())
    }

    /// The acting user's id, if they hold the owner role (directly or
    /// inherited) in the organization.
    pub(crate) async fn org_require_owner(
        &self,
        org_id: &S::OrgId,
    ) -> Result<S::UserId, OrgError<S::Error>> {
        let Some((user, _session)) = self.user_session().await? else {
            return Err(OrgError::NotLoggedIn);
        };

        let user_id = user.get_id();
        let roles = self.org_effective_roles(org_id, &user_id).await?;

        if roles.iter().any(|r| r == ORG_OWNER_ROLE) {
            Ok(user_id)
        } else {
            Err(OrgError::NotOwner)
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
