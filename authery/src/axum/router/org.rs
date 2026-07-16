use crate::{
    axum::AxumAuthery,
    models::org::{OrgLoginRules, OrgMember, Organization},
    models::User,
    org::OrgError,
    store::AutheryStore,
};
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Form,
};
use serde::Deserialize;

/// Resolve an org page path for a slug.
fn slugged(route: &str, slug: &str) -> String {
    route.replace("{slug}", slug)
}

fn split_csv(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Redirect to the org page with an outcome message or error.
fn org_redirect(routes: &crate::routes::Routes<String>, slug: &str, key: &str, text: &str) -> Redirect {
    Redirect::to(&format!(
        "{}?{key}={}",
        slugged(&routes.org.org, slug),
        urlencoding::encode(text)
    ))
}

/// Map an org action outcome to a redirect (store errors propagate).
fn org_action_response<St: AutheryStore>(
    routes: &crate::routes::Routes<String>,
    slug: &str,
    result: Result<(), OrgError<St::Error>>,
    success: &str,
) -> Result<axum::response::Response, St::Error>
where
    St::Error: IntoResponse,
{
    match result {
        Ok(()) => Ok(org_redirect(routes, slug, "message", success).into_response()),
        Err(OrgError::Store(err)) => Err(err),
        Err(err) => Ok(org_redirect(routes, slug, "error", &err.to_string()).into_response()),
    }
}

#[cfg(feature = "pages")]
pub(crate) use pages_handlers::{get_org, get_orgs};

#[cfg(feature = "pages")]
mod pages_handlers {
    use super::*;
    use crate::axum::router::pages::NextMessageErrorQuery;
    use crate::models::org::ORG_OWNER_ROLE;
    use crate::pages::{
        OrgTemplate, OrgTemplateChild, OrgTemplateMember, OrgTemplateProvider, OrgsTemplate,
        OrgsTemplateItem,
    };
    use axum::response::Html;

    pub(crate) async fn get_orgs<St>(
        auth: AxumAuthery<St>,
        Query(query): Query<NextMessageErrorQuery>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let Some(user) = auth.user().await? else {
            return Ok(Redirect::to(&auth.routes.pages.login).into_response());
        };

        let mut orgs = Vec::new();
        for membership in auth
            .store
            .org_get_user_memberships(&user.get_id())
            .await?
        {
            let Some(org) = auth.store.org_get(&membership.get_org_id()).await? else {
                continue;
            };

            orgs.push(OrgsTemplateItem {
                page_route: slugged(&auth.routes.org.org, org.get_slug()),
                slug: org.get_slug().to_string(),
                name: org.get_name().to_string(),
                roles: membership.get_roles().join(", "),
            });
        }

        let view = OrgsTemplate {
            message: query.message.as_deref(),
            error: query.error.as_deref(),
            orgs,
            create_action_route: &auth.routes.org.org_create,
            home_route: &auth.routes.pages.home,
        };

        Ok(Html(auth.pages.render_orgs(&view)).into_response())
    }

    pub(crate) async fn get_org<St>(
        auth: AxumAuthery<St>,
        Path(slug): Path<String>,
        Query(query): Query<NextMessageErrorQuery>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let Some(user) = auth.user().await? else {
            return Ok(Redirect::to(&auth.routes.pages.login).into_response());
        };

        let Some(org) = auth.store.org_get_by_slug(&slug).await? else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };

        let roles = match auth.org_effective_roles(&org.get_id(), &user.get_id()).await {
            Ok(roles) => roles,
            Err(OrgError::Store(err)) => return Err(err),
            Err(_) => Vec::new(),
        };

        if roles.is_empty() {
            return Ok(StatusCode::NOT_FOUND.into_response());
        }

        let members = auth
            .store
            .org_get_members(&org.get_id())
            .await?
            .into_iter()
            .map(|m| OrgTemplateMember {
                user_id: m.get_user_id().to_string(),
                roles: m.get_roles().join(", "),
            })
            .collect();

        let children = auth
            .store
            .org_get_children(&org.get_id())
            .await?
            .into_iter()
            .map(|c| OrgTemplateChild {
                page_route: slugged(&auth.routes.org.org, c.get_slug()),
                slug: c.get_slug().to_string(),
                name: c.get_name().to_string(),
            })
            .collect();

        #[cfg(feature = "oauth")]
        let providers = {
            use crate::models::org::OrgOidcProvider;

            auth.store
                .org_oidc_list(&org.get_id())
                .await?
                .into_iter()
                .map(|p| OrgTemplateProvider {
                    name: p.get_name().to_string(),
                    display_name: p.get_display_name().to_string(),
                    issuer: p.get_issuer().to_string(),
                })
                .collect()
        };
        #[cfg(not(feature = "oauth"))]
        let providers = Vec::new();

        let role_inheritance = org
            .get_role_inheritance()
            .into_iter()
            .map(|(parent, here)| format!("{parent}={here}"))
            .collect::<Vec<_>>()
            .join("\n");

        let view = OrgTemplate {
            message: query.message.as_deref(),
            error: query.error.as_deref(),
            slug: &slug,
            name: org.get_name(),
            is_owner: roles.iter().any(|r| r == ORG_OWNER_ROLE),
            roles: roles.join(", "),
            rules: org.get_login_rules(),
            role_inheritance,
            members,
            children,
            providers,
            login_route: format!("{}/{slug}", auth.routes.pages.login),
            orgs_route: &auth.routes.org.orgs,
            update_action_route: slugged(&auth.routes.org.org_update, &slug),
            delete_action_route: slugged(&auth.routes.org.org_delete, &slug),
            member_upsert_action_route: slugged(&auth.routes.org.org_member_upsert, &slug),
            member_remove_action_route: slugged(&auth.routes.org.org_member_remove, &slug),
            sub_create_action_route: slugged(&auth.routes.org.org_sub_create, &slug),
            invite_create_action_route: slugged(&auth.routes.org.org_invite_create, &slug),
            #[cfg(feature = "oauth")]
            provider_upsert_action_route: slugged(&auth.routes.org.org_provider_upsert, &slug),
            #[cfg(not(feature = "oauth"))]
            provider_upsert_action_route: String::new(),
            #[cfg(feature = "oauth")]
            provider_delete_action_route: slugged(&auth.routes.org.org_provider_delete, &slug),
            #[cfg(not(feature = "oauth"))]
            provider_delete_action_route: String::new(),
        };

        Ok(Html(auth.pages.render_org(&view)).into_response())
    }
}

#[derive(Deserialize)]
pub(crate) struct NameSlugForm {
    pub name: String,
    pub slug: String,
}

pub(crate) async fn post_org_create<St>(
    auth: AxumAuthery<St>,
    Form(form): Form<NameSlugForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let orgs_route = auth.routes.org.orgs.clone();

    match auth.org_create(&form.name, &form.slug).await {
        Ok(org) => Ok(Redirect::to(&slugged(&auth.routes.org.org, org.get_slug())).into_response()),
        Err(OrgError::Store(err)) => Err(err),
        Err(err) => Ok(Redirect::to(&format!(
            "{orgs_route}?error={}",
            urlencoding::encode(&err.to_string())
        ))
        .into_response()),
    }
}

pub(crate) async fn post_org_sub_create<St>(
    auth: AxumAuthery<St>,
    Path(slug): Path<String>,
    Form(form): Form<NameSlugForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(parent) = auth.store.org_get_by_slug(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let result = auth
        .org_create_sub(&parent.get_id(), &form.name, &form.slug)
        .await
        .map(|_| ());
    org_action_response::<St>(&auth.routes, &slug, result, "Sub-organization created")
}

#[derive(Deserialize)]
pub(crate) struct OrgUpdateForm {
    pub name: String,
    pub require_mfa: Option<String>,
    pub allow_password: Option<String>,
    pub allow_email: Option<String>,
    #[serde(default)]
    pub role_inheritance: String,
}

pub(crate) async fn post_org_update<St>(
    auth: AxumAuthery<St>,
    Path(slug): Path<String>,
    Form(form): Form<OrgUpdateForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(org) = auth.store.org_get_by_slug(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let rules = OrgLoginRules {
        require_mfa: form.require_mfa.is_some(),
        allow_password: form.allow_password.is_some(),
        allow_email: form.allow_email.is_some(),
    };

    let role_inheritance = form
        .role_inheritance
        .lines()
        .filter_map(|line| {
            line.split_once('=')
                .map(|(a, b)| (a.trim().to_string(), b.trim().to_string()))
        })
        .filter(|(a, b)| !a.is_empty() && !b.is_empty())
        .collect();

    let result = auth
        .org_update(&org.get_id(), &form.name, rules, role_inheritance)
        .await;
    org_action_response::<St>(&auth.routes, &slug, result, "Settings saved")
}

pub(crate) async fn post_org_delete<St>(
    auth: AxumAuthery<St>,
    Path(slug): Path<String>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(org) = auth.store.org_get_by_slug(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let orgs_route = auth.routes.org.orgs.clone();

    match auth.org_delete(&org.get_id()).await {
        Ok(()) => {
            Ok(Redirect::to(&format!("{orgs_route}?message=Organization deleted")).into_response())
        }
        Err(OrgError::Store(err)) => Err(err),
        Err(err) => Ok(org_redirect(&auth.routes, &slug, "error", &err.to_string()).into_response()),
    }
}

#[derive(Deserialize)]
pub(crate) struct MemberForm {
    pub user_id: String,
    #[serde(default)]
    pub roles: String,
}

pub(crate) async fn post_org_member_upsert<St>(
    auth: AxumAuthery<St>,
    Path(slug): Path<String>,
    Form(form): Form<MemberForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(org) = auth.store.org_get_by_slug(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let Ok(user_id) = form.user_id.parse::<St::UserId>() else {
        return Ok(org_redirect(&auth.routes, &slug, "error", "Bad user id").into_response());
    };

    let result = auth
        .org_upsert_member(&org.get_id(), &user_id, split_csv(&form.roles))
        .await
        .map(|_| ());
    org_action_response::<St>(&auth.routes, &slug, result, "Member saved")
}

pub(crate) async fn post_org_member_remove<St>(
    auth: AxumAuthery<St>,
    Path(slug): Path<String>,
    Form(form): Form<MemberForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let Some(org) = auth.store.org_get_by_slug(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let Ok(user_id) = form.user_id.parse::<St::UserId>() else {
        return Ok(org_redirect(&auth.routes, &slug, "error", "Bad user id").into_response());
    };

    let result = auth.org_remove_member(&org.get_id(), &user_id).await;
    org_action_response::<St>(&auth.routes, &slug, result, "Member removed")
}

#[derive(Deserialize)]
pub(crate) struct InviteForm {
    #[serde(default)]
    pub roles: String,
    pub hours: i64,
}

pub(crate) async fn post_org_invite_create<St>(
    auth: AxumAuthery<St>,
    Path(slug): Path<String>,
    Form(form): Form<InviteForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    use crate::models::org::OrgInvite;
    use crate::reexports::chrono::Duration;

    let Some(org) = auth.store.org_get_by_slug(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    match auth
        .org_invite_create(
            &org.get_id(),
            split_csv(&form.roles),
            Duration::hours(form.hours.max(1)),
        )
        .await
    {
        Ok(invite) => {
            let link = format!("{}?invite={}", auth.routes.pages.signup, invite.get_code());
            Ok(org_redirect(
                &auth.routes,
                &slug,
                "message",
                &format!("Invite link: {link}"),
            )
            .into_response())
        }
        Err(OrgError::Store(err)) => Err(err),
        Err(err) => Ok(org_redirect(&auth.routes, &slug, "error", &err.to_string()).into_response()),
    }
}

#[cfg(feature = "oauth")]
pub(crate) use provider_handlers::{post_org_provider_delete, post_org_provider_upsert};

#[cfg(feature = "oauth")]
mod provider_handlers {
    use super::*;
    use crate::models::org::NewOrgOidcProvider;

    #[derive(Deserialize)]
    pub(crate) struct ProviderForm {
        pub name: String,
        pub display_name: String,
        pub client_id: String,
        pub client_secret: String,
        pub issuer: String,
        pub auth_url: String,
        pub token_url: String,
        #[serde(default)]
        pub scopes: String,
        #[serde(default)]
        pub default_roles: String,
        #[serde(default)]
        pub claim_role_mapping: String,
        pub allow_login: Option<String>,
    }

    pub(crate) async fn post_org_provider_upsert<St>(
        auth: AxumAuthery<St>,
        Path(slug): Path<String>,
        Form(form): Form<ProviderForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let Some(org) = auth.store.org_get_by_slug(&slug).await? else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };

        let claim_role_mapping = form
            .claim_role_mapping
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(3, '=').map(|s| s.trim().to_string());
                Some((parts.next()?, parts.next()?, parts.next()?))
            })
            .filter(|(a, b, c)| !a.is_empty() && !b.is_empty() && !c.is_empty())
            .collect();

        let provider = NewOrgOidcProvider {
            name: form.name,
            display_name: form.display_name,
            client_id: form.client_id,
            client_secret: form.client_secret,
            issuer: form.issuer,
            auth_url: form.auth_url,
            token_url: form.token_url,
            scopes: form
                .scopes
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
            allow_login: form.allow_login.is_some(),
            default_roles: split_csv(&form.default_roles),
            claim_role_mapping,
        };

        let result = auth
            .org_oidc_upsert(&org.get_id(), provider)
            .await
            .map(|_| ());
        org_action_response::<St>(&auth.routes, &slug, result, "Provider saved")
    }

    #[derive(Deserialize)]
    pub(crate) struct ProviderDeleteForm {
        pub name: String,
    }

    pub(crate) async fn post_org_provider_delete<St>(
        auth: AxumAuthery<St>,
        Path(slug): Path<String>,
        Form(form): Form<ProviderDeleteForm>,
    ) -> Result<impl IntoResponse, St::Error>
    where
        St: AutheryStore,
        St::Error: IntoResponse,
    {
        let Some(org) = auth.store.org_get_by_slug(&slug).await? else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };

        let result = auth.org_oidc_delete(&org.get_id(), &form.name).await;
        org_action_response::<St>(&auth.routes, &slug, result, "Provider deleted")
    }
}
