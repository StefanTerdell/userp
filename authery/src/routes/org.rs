//! Routes for the organization pages and management actions. Paths containing
//! `{slug}` are axum path captures resolving the organization.

use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OrgRoutes<T = &'static str> {
    /// Get - lists the user's organizations, with a create form
    pub orgs: T,
    /// Post - creates an organization ({name, slug})
    pub org_create: T,
    /// Get - the management page for one organization
    pub org: T,
    /// Post - updates settings ({name, require_mfa, allow_password, allow_email, role_inheritance})
    pub org_update: T,
    /// Post - deletes the organization
    pub org_delete: T,
    /// Post - adds a member or replaces their roles ({user_id, roles})
    pub org_member_upsert: T,
    /// Post - removes a member ({user_id})
    pub org_member_remove: T,
    /// Post - creates a sub-organization ({name, slug})
    pub org_sub_create: T,
    /// Post - creates an invite ({roles, hours}); the link appears in the redirect message
    pub org_invite_create: T,
    #[cfg(feature = "oauth")]
    /// Post - registers or replaces an org OIDC provider
    pub org_provider_upsert: T,
    #[cfg(feature = "oauth")]
    /// Post - deletes an org OIDC provider ({name})
    pub org_provider_delete: T,
}

impl Default for OrgRoutes {
    fn default() -> Self {
        Self {
            orgs: "/orgs",
            org_create: "/orgs/create",
            org: "/orgs/{slug}",
            org_update: "/orgs/{slug}/update",
            org_delete: "/orgs/{slug}/delete",
            org_member_upsert: "/orgs/{slug}/members/upsert",
            org_member_remove: "/orgs/{slug}/members/remove",
            org_sub_create: "/orgs/{slug}/suborgs/create",
            org_invite_create: "/orgs/{slug}/invites/create",
            #[cfg(feature = "oauth")]
            org_provider_upsert: "/orgs/{slug}/providers/upsert",
            #[cfg(feature = "oauth")]
            org_provider_delete: "/orgs/{slug}/providers/delete",
        }
    }
}

impl<'a> From<&'a OrgRoutes<String>> for OrgRoutes<&'a str> {
    fn from(value: &'a OrgRoutes<String>) -> Self {
        Self {
            orgs: &value.orgs,
            org_create: &value.org_create,
            org: &value.org,
            org_update: &value.org_update,
            org_delete: &value.org_delete,
            org_member_upsert: &value.org_member_upsert,
            org_member_remove: &value.org_member_remove,
            org_sub_create: &value.org_sub_create,
            org_invite_create: &value.org_invite_create,
            #[cfg(feature = "oauth")]
            org_provider_upsert: &value.org_provider_upsert,
            #[cfg(feature = "oauth")]
            org_provider_delete: &value.org_provider_delete,
        }
    }
}

impl From<OrgRoutes<&str>> for OrgRoutes<String> {
    fn from(value: OrgRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<OrgRoutes<T>> for OrgRoutes<T> {
    fn as_ref(&self) -> &OrgRoutes<T> {
        self
    }
}

impl<T: Display> OrgRoutes<T> {
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> OrgRoutes<String> {
        OrgRoutes {
            orgs: format!("{prefix}{}", self.orgs),
            org_create: format!("{prefix}{}", self.org_create),
            org: format!("{prefix}{}", self.org),
            org_update: format!("{prefix}{}", self.org_update),
            org_delete: format!("{prefix}{}", self.org_delete),
            org_member_upsert: format!("{prefix}{}", self.org_member_upsert),
            org_member_remove: format!("{prefix}{}", self.org_member_remove),
            org_sub_create: format!("{prefix}{}", self.org_sub_create),
            org_invite_create: format!("{prefix}{}", self.org_invite_create),
            #[cfg(feature = "oauth")]
            org_provider_upsert: format!("{prefix}{}", self.org_provider_upsert),
            #[cfg(feature = "oauth")]
            org_provider_delete: format!("{prefix}{}", self.org_provider_delete),
        }
    }
}

impl OrgRoutes<String> {
    /// Substitute the `{slug}` placeholder to get a concrete path.
    pub fn for_slug(&self, route: &str, slug: &str) -> String {
        route.replace("{slug}", slug)
    }
}
