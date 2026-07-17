//! A complete authery app over Postgres - the reference store implementation.
//!
//! Run the database (and Keycloak + Mailhog for oauth/email flows):
//!
//!     docker compose -f dev/compose.yaml up -d
//!     cargo run
//!
//! The schema in schema.sql is applied automatically at startup.

mod models;
mod store;

use self::store::PgStore;

use axum::{
    Router,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    serve,
};
use axum_macros::FromRef;
use dotenv::var;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use authery::prelude::*;
use authery::reexports::url::Url;

#[derive(Clone, FromRef)]
struct AppState {
    store: PgStore,
    auth: AutheryConfig,
}

/// Logs texts instead of sending them; see the memory-store example for
/// wiring real gateways from env.
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

    let database_url = var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://authery:authery@localhost:5432/authery".into());
    let store = PgStore::connect(&database_url)
        .await
        .expect("database reachable (docker compose -f dev/compose.yaml up -d)");

    // The dev Keycloak works out of the box; add more providers via
    // {NAME}_CLIENT_ID/{NAME}_CLIENT_SECRET like the memory-store example.
    let mut oauth = OAuthConfig::new(base_url.clone());
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
        WebauthnConfig::new(base_url, "Authery postgres example").expect("valid webauthn config"),
        TotpConfig::new("Authery postgres example"),
        SmsConfig::new(DevSmsSender),
    )
    .expect("valid auth config")
    .with_https_only(false);

    let auth_router = auth.router::<PgStore, AppState>();

    let app = Router::new()
        .merge(auth_router)
        .route("/", get(get_index))
        .route("/protected", get(get_protected))
        .with_state(AppState { store, auth })
        .layer(TraceLayer::new_for_http());

    println!("Authery postgres example listening at http://localhost:3000 :)");
    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

async fn get_index(auth: Authery<PgStore>) -> impl IntoResponse {
    let logged_in = auth.logged_in().await.unwrap();

    Html(if logged_in {
        r#"<h1>Welcome!</h1><p><a href="/user">Account</a> · <a href="/protected">Protected</a></p>
           <form action="/logout" method="post"><button type="submit">Log out</button></form>"#
            .to_string()
    } else {
        r#"<h1>Welcome!</h1><p><a href="/login">Log in</a> · <a href="/signup">Sign up</a></p>"#
            .to_string()
    })
}

async fn get_protected(auth: Authery<PgStore>) -> impl IntoResponse {
    let Some((user, session)) = auth.user_session().await.unwrap() else {
        return Redirect::to(&format!(
            "/login?next={}",
            urlencoding::encode("/protected")
        ))
        .into_response();
    };

    Html(format!(
        "<h1>Protected</h1><pre>user: {user:#?}\nsession: {session:#?}</pre>"
    ))
    .into_response()
}
