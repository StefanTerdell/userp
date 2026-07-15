mod models;
mod store;
mod templates;

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

    let req_var = |name: &'static str| {
        var(name).unwrap_or_else(|_| panic!("Missing required env var: {name}"))
    };

    let base_url = Url::parse("http://localhost:3000").unwrap();

    let key = String::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let auth = AutheryConfig::new(
        key,
        Routes::default(),
        PasswordConfig::new().with_allow_reset(PasswordReset::AnyUserEmail),
        EmailConfig::new(
            base_url.clone(),
            SmtpSettings {
                server_url: req_var("SMTP_URL"),
                username: req_var("SMTP_USERNAME"),
                password: req_var("SMTP_PASSWORD"),
                from: req_var("SMTP_FROM"),
                starttls: true,
            },
        ),
        OAuthConfig::new(base_url)
            .with_client(SpotifyOAuthProvider::new(
                req_var("SPOTIFY_CLIENT_ID"),
                req_var("SPOTIFY_CLIENT_SECRET"),
            ))
            .with_client(GitHubOAuthProvider::new(
                req_var("GITHUB_CLIENT_ID"),
                req_var("GITHUB_CLIENT_SECRET"),
            ))
            .with_client(GitLabOAuthProvider::new(
                req_var("GITLAB_CLIENT_ID"),
                req_var("GITLAB_CLIENT_SECRET"),
            ))
            .with_client(GoogleOAuthProvider::new(
                req_var("GOOGLE_CLIENT_ID"),
                req_var("GOOGLE_CLIENT_SECRET"),
            )),
    )
    .with_https_only(false);

    let auth_router = auth.router::<MemoryStore, AppState>();

    let state = AppState {
        store: MemoryStore::default(),
        auth,
    };

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
