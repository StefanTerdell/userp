//! Passwordless email auth: magic links + one-time codes, nothing else.
//! Note the config: with only `email`/`otp` enabled, `AutheryConfig::new`
//! wants exactly one method config - the email one.
//!
//!     docker compose -f dev/compose.yaml up -d   # Mailhog on :8025
//!     cargo run -p email-otp

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
use memory_store::MemoryStore;

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
    let key = String::from(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );

    let auth = AutheryConfig::new(
        key,
        Routes::default(),
        EmailConfig::new(
            base_url,
            SmtpSettings {
                server_url: var("SMTP_URL").unwrap_or_else(|_| "smtp://localhost:1025".into()),
                from: var("SMTP_FROM").unwrap_or_else(|_| "auth@example.com".into()),
            },
        ),
    )
    .expect("valid auth config")
    .with_https_only(false);

    let app = Router::new()
        .merge(auth.router::<MemoryStore, AppState>())
        .route("/", get(get_index))
        .route("/protected", get(get_protected))
        .with_state(AppState {
            store: MemoryStore::default(),
            auth,
        })
        .layer(TraceLayer::new_for_http());

    println!("Authery email-otp example listening at http://localhost:3000 :)");
    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

async fn get_index(auth: Authery<MemoryStore>) -> impl IntoResponse {
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

async fn get_protected(auth: Authery<MemoryStore>) -> impl IntoResponse {
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
