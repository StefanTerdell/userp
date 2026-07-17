mod models;
mod ratelimit;
mod store;
mod templates;

use self::ratelimit::FixedWindowRateLimiter;
use self::store::MemoryStore;
use self::templates::{IndexTemplate, ProtectedTemplate};

use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    serve, Router,
};
use axum::response::Redirect;
use axum_macros::FromRef;
use dotenv::var;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use authery::prelude::*;
use authery::reexports::url::Url;

#[derive(Clone, FromRef)]
struct AppState {
    store: MemoryStore,
    auth: AutheryConfig,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let base_url = Url::parse("http://localhost:3000").unwrap();

    let key = String::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let store = MemoryStore::default();

    // --- App-level organizations (see the book chapter) ---
    //
    // Orgs live entirely in the app's own tables. Authery's part is the
    // provider resolver below plus the `context` string that rides the oauth
    // flow; membership upserts happen in the store's token methods.
    let acme = AppOrg {
        id: authery::reexports::uuid::Uuid::new_v4(),
        slug: "acme".into(),
        name: "ACME".into(),
        login_rules: LoginMethodRules::default(),
    };
    store.org_providers.write().await.push(AppOrgProvider {
        org_id: acme.id,
        name: "keycloak".into(),
        display_name: "ACME SSO (Keycloak)".into(),
        client_id: var("KEYCLOAK_CLIENT_ID").unwrap_or_else(|_| "authery-example".into()),
        client_secret: var("KEYCLOAK_CLIENT_SECRET").unwrap_or_else(|_| "authery-secret".into()),
        issuer: var("KEYCLOAK_ISSUER")
            .unwrap_or_else(|_| "http://localhost:8080/realms/authery".into()),
        auth_url: var("KEYCLOAK_AUTH_URL").unwrap_or_else(|_| {
            "http://localhost:8080/realms/authery/protocol/openid-connect/auth".into()
        }),
        token_url: var("KEYCLOAK_TOKEN_URL").unwrap_or_else(|_| {
            "http://localhost:8080/realms/authery/protocol/openid-connect/token".into()
        }),
    });
    store.orgs.write().await.insert(acme.id, acme);

    // Each provider is added only when its credentials are present, so you
    // can live-test any one of them by exporting {NAME}_CLIENT_ID and
    // {NAME}_CLIENT_SECRET and restarting. See dev/PROVIDERS.md.
    type ProviderBuilder = fn(String, String) -> OAuthCustomProvider;
    let providers: [(&str, ProviderBuilder); 11] = [
        ("SPOTIFY", SpotifyOAuthProvider::new),
        ("GITHUB", GitHubOAuthProvider::new),
        ("GITLAB", GitLabOAuthProvider::new),
        ("GOOGLE", GoogleOAuthProvider::new),
        ("MICROSOFT", MicrosoftOAuthProvider::new),
        ("DISCORD", DiscordOAuthProvider::new),
        ("FACEBOOK", FacebookOAuthProvider::new),
        ("TWITCH", TwitchOAuthProvider::new),
        ("SLACK", SlackOAuthProvider::new),
        ("LINKEDIN", LinkedInOAuthProvider::new),
        ("X", XOAuthProvider::new),
    ];

    let mut oauth = OAuthConfig::new(base_url.clone());
    for (name, build) in providers {
        if let (Ok(id), Ok(secret)) = (
            var(format!("{name}_CLIENT_ID")),
            var(format!("{name}_CLIENT_SECRET")),
        ) {
            println!("oauth provider enabled: {name}");
            oauth = oauth.with_client(build(id, secret));
        }
    }

    // Per-org providers are resolved from the app's tables at request time.
    oauth = oauth.with_provider_resolver(AppProviderResolver {
        store: store.clone(),
    });

    let auth = AutheryConfig::new(
        key,
        Routes::default(),
        PasswordConfig::new().with_allow_reset(PasswordReset::AnyUserEmail),
        EmailConfig::new(
            base_url.clone(),
            SmtpSettings {
                server_url: var("SMTP_URL").unwrap_or_else(|_| "smtp://localhost:1025".into()),
                from: var("SMTP_FROM").unwrap_or_else(|_| "auth@example.com".into()),
            },
        ),
        oauth,
        WebauthnConfig::new(base_url, "Authery example").expect("valid webauthn config"),
        TotpConfig::new("Authery example"),
    )
    .expect("valid auth config")
    .with_https_only(false)
    .with_rate_limiter(FixedWindowRateLimiter::default())
    .with_max_concurrent_sessions(3);

    let auth_router = auth.router::<MemoryStore, AppState>();

    let state = AppState { store, auth };

    let app = Router::new()
        .merge(auth_router)
        .route("/store", get(get_store))
        .route("/", get(get_index))
        .route("/protected", get(get_protected))
        .route(
            "/login/{org}",
            get(get_org_login).post(post_org_login),
        )
        .route("/orgs/{org}/protected", get(get_org_protected))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    println!("Authery example listening at http://localhost:3000 :)");
    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

async fn get_index(auth: Authery<MemoryStore>) -> impl IntoResponse {
    let logged_in = auth.logged_in().await.unwrap();

    Html(IndexTemplate { logged_in }.render().unwrap())
}

async fn get_store(State(state): State<AppState>) -> impl IntoResponse {
    format!("{:#?}", state.store).into_response()
}

async fn get_protected(auth: Authery<MemoryStore>) -> impl IntoResponse {
    let Some((user, session)) = auth.user_session().await.unwrap() else {
        return Redirect::to(&format!(
            "/login?next={}",
            urlencoding::encode("/protected")
        ))
        .into_response();
    };

    Html(
        ProtectedTemplate {
            user: format!("{user:#?}"),
            session: format!("{session:#?}"),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

// --- App-level organizations ---
//
// Everything below is plain app code built on two authery primitives: the
// provider resolver (per-org IdPs from app tables) and the `context` string
// that rides the oauth flow into the store's token methods.

use crate::models::{AppOrg, AppOrgProvider};
use std::sync::Arc;

#[derive(Debug, Clone)]
struct AppProviderResolver {
    store: MemoryStore,
}

impl OAuthProviderResolver for AppProviderResolver {
    fn resolve<'a>(
        &'a self,
        context: &'a str,
        provider_name: &'a str,
    ) -> ProviderResolverFuture<'a> {
        Box::pin(async move {
            let Some(org_id) = self
                .store
                .orgs
                .read()
                .await
                .values()
                .find(|o| o.slug == context)
                .map(|o| o.id)
            else {
                return Ok(None);
            };

            let providers = self.store.org_providers.read().await;
            let Some(p) = providers
                .iter()
                .find(|p| p.org_id == org_id && p.name == provider_name)
            else {
                return Ok(None);
            };

            // The org's IdP is authoritative: anyone it authenticates gets an
            // account, so login and signup are interchangeable here.
            Ok(Some(Arc::new(
                OAuthOidcProvider::new(
                    p.name.clone(),
                    p.display_name.clone(),
                    p.client_id.clone(),
                    p.client_secret.clone(),
                    p.issuer.clone(),
                    p.auth_url.clone(),
                    p.token_url.clone(),
                    &["openid"],
                )?
                .with_allow_signup(Some(Allow::OnEither))
                .with_allow_login(Some(Allow::OnEither)),
            ) as Arc<dyn OAuthProvider>))
        })
    }
}

async fn org_by_slug(store: &MemoryStore, slug: &str) -> Option<AppOrg> {
    store
        .orgs
        .read()
        .await
        .values()
        .find(|o| o.slug == slug)
        .cloned()
}

/// The org-scoped login page: the org's providers from the app's own tables,
/// posting back to this path.
async fn get_org_login(
    State(state): State<AppState>,
    axum::extract::Path(slug): axum::extract::Path<String>,
) -> impl IntoResponse {
    let Some(org) = org_by_slug(&state.store, &slug).await else {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    };

    let buttons: String = state
        .store
        .org_providers
        .read()
        .await
        .iter()
        .filter(|p| p.org_id == org.id)
        .map(|p| {
            format!(
                r#"<form method="post"><input type="hidden" name="provider" value="{}"/><button type="submit">Login with {}</button></form>"#,
                p.name, p.display_name
            )
        })
        .collect();

    Html(format!(
        r#"<h1>Log in to {}</h1>{buttons}<p><a href="/login">Other login options</a></p>"#,
        org.name
    ))
    .into_response()
}

#[derive(authery::reexports::serde::Deserialize)]
#[serde(crate = "authery::reexports::serde")]
struct OrgLoginForm {
    provider: String,
}

/// Start an org SSO login: the slug becomes the flow's context.
async fn post_org_login(
    auth: Authery<MemoryStore>,
    axum::extract::Path(slug): axum::extract::Path<String>,
    axum::Form(form): axum::Form<OrgLoginForm>,
) -> impl IntoResponse {
    match auth
        .oauth_login_init_with_context(slug.clone(), &form.provider, None)
        .await
    {
        Ok((auth, redirect_url)) => (auth, Redirect::to(redirect_url.as_str())).into_response(),
        Err(err) => Redirect::to(&format!(
            "/login/{slug}?error={}",
            urlencoding::encode(&err.to_string())
        ))
        .into_response(),
    }
}

/// An org-gated route: the app checks its own membership table and enforces
/// the org's login-method rules via authery's `LoginMethodRules`.
async fn get_org_protected(
    auth: Authery<MemoryStore>,
    State(state): State<AppState>,
    axum::extract::Path(slug): axum::extract::Path<String>,
) -> impl IntoResponse {
    let Some(org) = org_by_slug(&state.store, &slug).await else {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    };

    let Some(session) = auth.session().await.unwrap() else {
        return Redirect::to(&format!("/login/{slug}")).into_response();
    };

    if !org.login_rules.satisfies(&session.get_method()) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "This organization requires a stronger login method",
        )
            .into_response();
    }

    let member = state
        .store
        .org_members
        .read()
        .await
        .iter()
        .find(|m| m.org_id == org.id && m.user_id == session.get_user_id())
        .cloned();

    match member {
        Some(member) => Html(format!(
            "<h1>Welcome to {}!</h1><p>admin: {}</p>",
            org.name, member.admin
        ))
        .into_response(),
        None => (
            axum::http::StatusCode::FORBIDDEN,
            "Not a member of this organization",
        )
            .into_response(),
    }
}
