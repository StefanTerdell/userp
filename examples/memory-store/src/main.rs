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

use authery::models::org::NewOrgOidcProvider;
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
    )
    .expect("valid auth config")
    .with_https_only(false)
    .with_rate_limiter(FixedWindowRateLimiter::default())
    .with_max_concurrent_sessions(3);

    let auth = auth.with_org_config(OrgConfig {
        create_private_org_on_signup: true,
    });

    let auth_router = auth.router::<MemoryStore, AppState>();

    let store = MemoryStore::default();

    // Demo SaaS setup: an "acme" org with Keycloak as its own SSO provider,
    // reachable at /login/acme. Keycloak realm roles land in the id_token at
    // realm_access.roles, but a top-level claim keeps the demo simple.
    let acme = store
        .org_create("ACME", "acme", None)
        .await
        .expect("create acme org");
    store
        .org_oidc_upsert(
            &acme.get_id(),
            NewOrgOidcProvider {
                name: "keycloak".into(),
                display_name: "ACME SSO (Keycloak)".into(),
                client_id: var("KEYCLOAK_CLIENT_ID")
                    .unwrap_or_else(|_| "authery-example".into()),
                client_secret: var("KEYCLOAK_CLIENT_SECRET")
                    .unwrap_or_else(|_| "authery-secret".into()),
                issuer: var("KEYCLOAK_ISSUER")
                    .unwrap_or_else(|_| "http://localhost:8080/realms/authery".into()),
                auth_url: var("KEYCLOAK_AUTH_URL").unwrap_or_else(|_| {
                    "http://localhost:8080/realms/authery/protocol/openid-connect/auth".into()
                }),
                token_url: var("KEYCLOAK_TOKEN_URL").unwrap_or_else(|_| {
                    "http://localhost:8080/realms/authery/protocol/openid-connect/token".into()
                }),
                scopes: vec!["openid".into()],
                allow_login: true,
                default_roles: vec!["member".into()],
                claim_role_mapping: vec![(
                    "email_verified".into(),
                    "true".into(),
                    "verified".into(),
                )],
                claim_privilege_mapping: Vec::new(),
            },
        )
        .await
        .expect("attach keycloak provider");

    let state = AppState { store, auth };

    let app = Router::new()
        .merge(auth_router)
        .route("/store", get(get_store))
        .route("/", get(get_index))
        .route("/protected", get(get_protected))
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
