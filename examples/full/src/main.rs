//! Every authery feature at once - and proof that app code is store-generic:
//! the same `run` function serves the in-memory store (default) or the
//! Postgres reference store (set DATABASE_URL, e.g. the dev compose one:
//! `postgres://authery:authery@localhost:5432/authery`).
//!
//!     docker compose -f dev/compose.yaml up -d   # Keycloak/Mailhog/Postgres
//!     cargo run -p full

mod ratelimit;
mod templates;

use self::ratelimit::FixedWindowRateLimiter;
use self::templates::{IndexTemplate, ProtectedTemplate};

use askama::Template;
use axum::{
    Router,
    extract::FromRef,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    serve,
};
use dotenv::var;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use authery::prelude::*;
use authery::reexports::url::Url;
use memory_store::MemoryStore;
use postgres_store::PgStore;

/// The app state is generic over the store - handlers and router don't care
/// which one is behind it.
struct AppState<St> {
    store: St,
    auth: AutheryConfig,
}

impl<St: Clone> Clone for AppState<St> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            auth: self.auth.clone(),
        }
    }
}

impl<St: Clone> FromRef<AppState<St>> for AutheryConfig {
    fn from_ref(state: &AppState<St>) -> Self {
        state.auth.clone()
    }
}

// A blanket `impl FromRef<AppState<St>> for St` would be an orphan-rule
// violation, so each store gets a one-liner:
impl FromRef<AppState<MemoryStore>> for MemoryStore {
    fn from_ref(state: &AppState<MemoryStore>) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState<PgStore>> for PgStore {
    fn from_ref(state: &AppState<PgStore>) -> Self {
        state.store.clone()
    }
}

/// Logs texts instead of sending them.
#[derive(Debug, Clone)]
struct DevSmsSender;

impl SmsSender for DevSmsSender {
    fn send<'a>(&'a self, to: &'a str, message: &'a str) -> SmsSendFuture<'a> {
        println!("=== SMS to {to}: {message} ===");
        Box::pin(async { Ok(()) })
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let base_url = Url::parse("http://localhost:3000").unwrap();
    let key = String::from(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );

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

    // The dev Keycloak works without any env config.
    if let Ok(keycloak) = OAuthOidcProvider::new(
        "keycloak",
        "Keycloak (dev)",
        var("KEYCLOAK_CLIENT_ID").unwrap_or_else(|_| "authery-example".into()),
        var("KEYCLOAK_CLIENT_SECRET").unwrap_or_else(|_| "authery-secret".into()),
        var("KEYCLOAK_ISSUER").unwrap_or_else(|_| "http://localhost:8080/realms/authery".into()),
        var("KEYCLOAK_AUTH_URL").unwrap_or_else(|_| {
            "http://localhost:8080/realms/authery/protocol/openid-connect/auth".into()
        }),
        var("KEYCLOAK_TOKEN_URL").unwrap_or_else(|_| {
            "http://localhost:8080/realms/authery/protocol/openid-connect/token".into()
        }),
        &["openid"],
    ) {
        oauth = oauth.with_client(keycloak.with_allow_signup(Some(Allow::OnEither)));
    }

    // A real SMS gateway when its env credentials are present, otherwise
    // codes are just printed to stdout.
    let sms = if let (Ok(sid), Ok(token), Ok(from)) = (
        var("TWILIO_ACCOUNT_SID"),
        var("TWILIO_AUTH_TOKEN"),
        var("TWILIO_FROM"),
    ) {
        println!("sms sender enabled: twilio");
        SmsConfig::new(TwilioSmsSender::new(sid, token, from))
    } else if let (Ok(username), Ok(password), Ok(from)) =
        (var("ELKS_USERNAME"), var("ELKS_PASSWORD"), var("ELKS_FROM"))
    {
        println!("sms sender enabled: 46elks");
        SmsConfig::new(FortySixElksSmsSender::new(username, password, from))
    } else {
        SmsConfig::new(DevSmsSender)
    };

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
        sms,
    )
    .expect("valid auth config")
    .with_https_only(false)
    .with_rate_limiter(FixedWindowRateLimiter::default())
    .with_max_concurrent_sessions(3)
    .with_mfa_policy(MfaPolicy {
        trusted_device_lifetime: Some(authery::reexports::chrono::Duration::days(30)),
        ..Default::default()
    })
    .with_bearer_auth(true)
    .with_bearer_token_prefix("authery_");

    // Same app, either store.
    match var("DATABASE_URL") {
        Ok(url) => {
            println!("store: postgres");
            let store = PgStore::connect(&url).await.expect("database reachable");
            run(store, auth).await;
        }
        Err(_) => {
            println!("store: in-memory");
            run(MemoryStore::default(), auth).await;
        }
    }
}

async fn run<St>(store: St, auth: AutheryConfig)
where
    St: AutheryStore + Clone + Send + Sync + 'static + FromRef<AppState<St>>,
    St::Error: IntoResponse,
    St::User: std::fmt::Debug,
    St::LoginSession: std::fmt::Debug,
{
    let auth_router = auth.router::<St, AppState<St>>();

    let app = Router::new()
        .merge(auth_router)
        .route("/", get(get_index::<St>))
        .route("/protected", get(get_protected::<St>))
        .with_state(AppState { store, auth })
        .layer(TraceLayer::new_for_http());

    println!("Authery example listening at http://localhost:3000 :)");
    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

async fn get_index<St>(auth: Authery<St>) -> impl IntoResponse
where
    St: AutheryStore + Send + Sync,
    St::Error: IntoResponse,
{
    let logged_in = auth.logged_in().await.unwrap();

    Html(IndexTemplate { logged_in }.render().unwrap())
}

async fn get_protected<St>(auth: Authery<St>) -> impl IntoResponse
where
    St: AutheryStore + Send + Sync,
    St::Error: IntoResponse,
    St::User: std::fmt::Debug,
    St::LoginSession: std::fmt::Debug,
{
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
